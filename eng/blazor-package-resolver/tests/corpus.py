"""Bounded byte construction only. No imports from a resolver or classification oracle."""
import argparse
import atexit
import hashlib
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
STORE = HERE / "corpus"
ACCEPTED = "9bba9b9c0afff93dd003f6b14d34b82292a2f8a7"


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    """Encode the frozen result writer's JSON shape, without executing any resolver."""
    if isinstance(value, dict):
        return "{" + ",".join(canonical(k) + ":" + canonical(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, str):
        result = '"'
        escapes = {'\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f'}
        for char in value:
            if char in escapes:
                result += escapes[char]
            elif 0x20 <= ord(char) < 0x7f and char not in "\"&'+<>`":
                result += char
            else:
                raw = char.encode("utf-16-be", errors="surrogatepass")
                result += "".join("\\u" + raw[i:i + 2].hex().upper() for i in range(0, len(raw), 2))
        return result + '"'
    return json.dumps(value, separators=(",", ":"), allow_nan=False)


def safe(value):
    return (isinstance(value, str) and len(value) <= 256
            and re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", value)
            and all(part not in (".", "..") for part in value.split("/")))


def load(name):
    path = STORE / name
    check(path.stat().st_size <= 8 * 1024 * 1024, "Recipe document limit")
    return json.loads(path.read_bytes())


def materialize(destination):
    destination = Path(destination).resolve()
    check(not destination.exists(), "Materialization requires a new isolated root")
    lock = load("lock.json")
    check(set(lock) == {"schema", "parent", "files", "seeds", "row_outputs", "recipes_sha256",
                       "expectations_sha256", "bank_sha256"}, "Unknown lock fields")
    check(lock["schema"] == "resolver-corpus/1" and lock["parent"] == ACCEPTED, "Unsupported corpus")
    for name, field in (("recipes.json", "recipes_sha256"), ("expectations.json", "expectations_sha256"),
                        ("chunks.bin", "bank_sha256")):
        check(sha((STORE / name).read_bytes()) == lock[field], "Changed recipe store: " + name)
    recipes = load("recipes.json")
    expectations = load("expectations.json")
    bank = (STORE / "chunks.bin").read_bytes()
    check(len(bank) <= 16 * 1024 * 1024 and len(lock["files"]) <= 2000, "Corpus resource limit")
    seeds = {}
    for name, length, digest in lock["seeds"]:
        check(safe(name), "Unsafe seed")
        data = (STORE / "seeds" / name).read_bytes()
        check(len(data) == length and sha(data) == digest, "Changed seed: " + name)
        seeds[name] = data
    expected_seeds = {name for name, _, _ in lock["seeds"]}
    check({p.relative_to(STORE / "seeds").as_posix() for p in (STORE / "seeds").rglob("*")
           if p.is_file()} == expected_seeds, "Missing/extra seeds")
    actual_recipes = {}
    pins = {name: (length, digest) for name, length, digest in lock["files"]}
    check(len(pins) == len(lock["files"]) and all(
        safe(name) and type(length) is int and 0 <= length <= 8 * 1024 * 1024 and
        isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)
        for name, (length, digest) in pins.items()), "Invalid output pins")
    for source in (recipes, expectations):
        check(set(source) == {"strings", "nodes", "files"}, "Unknown recipe fields")
        strings, nodes = source["strings"], source["nodes"]
        check(len(strings) <= 100000 and len(nodes) <= 100000, "Recipe node limit")
        built = []
        for index, node in enumerate(nodes):
            kind, value = node
            def child(i):
                check(type(i) is int and 0 <= i < index, "Forward/cyclic JSON recipe")
                return built[i]
            if kind == "s":
                check(type(value) is int and 0 <= value < len(strings), "Invalid string reference")
                result = strings[value]
            elif kind == "o":
                check(len({key for key, _ in value}) == len(value), "Duplicate recipe key")
                result = {strings[key]: child(item) for key, item in value}
            elif kind == "a":
                result = [child(item) for item in value]
            elif kind == "v":
                check(value is None or type(value) in (bool, int), "Unsupported JSON scalar")
                result = value
            else:
                raise ValueError("Unsupported JSON recipe")
            built.append(result)
        for name, recipe in source["files"].items():
            check(safe(name) and name not in actual_recipes, "Duplicate/unsafe output")
            check(name in pins, "Extra output")
            kind, value = recipe
            if kind in ("j", "u"):
                check(type(value) is int and 0 <= value < len(built), "Invalid JSON root")
                chunks, total = [], 1
                for part in json.JSONEncoder(indent=2, ensure_ascii=kind == "j").iterencode(built[value]):
                    raw = part.encode()
                    total += len(raw)
                    check(total <= pins[name][0], "Rendered JSON resource limit")
                    chunks.append(raw)
                data = b"".join(chunks) + b"\n"
            elif kind == "b":
                chunks, total = [], 0
                for offset, length in value:
                    check(type(offset) is int and type(length) is int and
                          0 <= offset <= len(bank) and 0 < length <= len(bank) - offset,
                          "Invalid raw byte slice")
                    total += length
                    check(total <= pins[name][0], "Raw composition resource limit")
                    chunks.append(bank[offset:offset + length])
                data = b"".join(chunks)
            elif kind == "r":
                check(value in seeds, "Unknown raw seed")
                data = seeds[value]
            else:
                raise ValueError("Unsupported output recipe")
            actual_recipes[name] = data
    check(len(pins) == len(lock["files"]) and set(pins) == set(actual_recipes), "Missing/extra outputs")
    check(sum(len(data) for data in actual_recipes.values()) <= 64 * 1024 * 1024, "Total byte limit")
    for name, data in actual_recipes.items():
        length, digest = pins[name]
        check(len(data) == length and sha(data) == digest, "Output mismatch: " + name)
    for name, digest in lock["row_outputs"].items():
        suite = json.loads(actual_recipes[name])
        output = {"schema_version": 1, "cases": [
            {"case_id": item["case_id"], "result": item["expected"]} for item in suite["cases"]]}
        check(sha((canonical(output) + "\n").encode()) == digest,
              "Canonical row output changed: " + name)
    destination.mkdir(parents=True)
    try:
        for name, data in actual_recipes.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        check({p.relative_to(destination).as_posix() for p in destination.rglob("*")
               if p.is_file()} == set(pins), "Materialized output set differs")
    except BaseException:
        shutil.rmtree(destination)
        raise
    return lock


def temporary():
    parent = Path(tempfile.mkdtemp(prefix="resolver-corpus-"))
    atexit.register(shutil.rmtree, parent)
    directory = parent / "fixtures"
    materialize(directory)
    return parent, directory


def oracle(name):
    parent, fixtures = temporary()
    for path in (HERE / "oracles").glob("*.py"):
        shutil.copyfile(path, parent / path.name)
    sys.path.insert(0, str(parent))
    if name == "pi01_expectations.py":
        print("PI-01: historical correlated conformance checker; independent claim is limited "
              "to locked bytes and construction facts, not semantic/cryptographic validation.")
    sys.argv[0] = str(parent / name)
    runpy.run_path(str(parent / name), run_name="__main__")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("materialize")
    create.add_argument("--output", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--parent", action="store_true")
    replay = sub.add_parser("replay")
    replay.add_argument("row", choices=["foundation", *["lp%02d" % i for i in range(1, 11)], "pi01"])
    args = parser.parse_args()
    if args.command == "materialize":
        materialize(args.output)
        return
    parent, fixtures = temporary()
    if args.command == "verify":
        lock = load("lock.json")
        if args.parent:
            for name, length, digest in lock["files"]:
                old = subprocess.check_output(["git", "show", ACCEPTED +
                                               ":eng/blazor-package-resolver/tests/fixtures/" + name])
                check(old == (fixtures / name).read_bytes(), "Accepted parent mismatch: " + name)
        print("Corpus verified:", len(lock["files"]), "exact paths;",
              sum(pin[1] for pin in lock["files"]), "bytes; locked canonical outputs unchanged.")
    else:
        manifest = fixtures / ("cases.json" if args.row == "foundation" else args.row + "/cases.json")
        subprocess.run(["dotnet", "run", "--no-restore", "--project",
                        str(HERE.parent / "BlazorPackageResolver.csproj"), "--",
                        "replay", str(manifest)], check=True)


if __name__ == "__main__":
    main()
