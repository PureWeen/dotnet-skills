"""One-shot reviewed byte-representation compiler; never classifies a package."""
import json
from pathlib import Path
import shutil

from corpus import ACCEPTED, HERE, STORE, check, sha, materialize, canonical


class Table:
    def __init__(self):
        self.strings, self.nodes, self.files = [], [], {}
        self.string_ids, self.node_ids = {}, {}

    def string(self, value):
        if value not in self.string_ids:
            self.string_ids[value] = len(self.strings)
            self.strings.append(value)
        return self.string_ids[value]

    def node(self, value):
        if isinstance(value, dict):
            node = ["o", [[self.string(k), self.node(v)] for k, v in value.items()]]
        elif isinstance(value, list):
            node = ["a", [self.node(v) for v in value]]
        elif isinstance(value, str):
            node = ["s", self.string(value)]
        else:
            node = ["v", value]
        key = json.dumps(node, separators=(",", ":"), ensure_ascii=True)
        if key not in self.node_ids:
            self.node_ids[key] = len(self.nodes)
            self.nodes.append(node)
        return self.node_ids[key]

    def document(self):
        return {"strings": self.strings, "nodes": self.nodes, "files": self.files}


def main():
    original = HERE / "fixtures"
    check(original.is_dir() and not STORE.exists(), "Compiler requires untouched accepted corpus")
    STORE.mkdir()
    seeds = STORE / "seeds"
    seeds.mkdir()
    tables = [Table(), Table()]
    pins, seed_pins, outputs = [], [], {}
    bank, chunks = bytearray(), {}
    seed_hashes = {}
    for path in sorted(p for p in original.rglob("*") if p.is_file()):
        name, data = path.relative_to(original).as_posix(), path.read_bytes()
        pins.append([name, len(data), sha(data)])
        expected = path.name in ("cases.json", "acceptance.json", "rejected-inputs.json",
                                 "branch-cases.json", "branch-rejected-inputs.json")
        table = tables[int(expected)]
        genuine = ("/templates/" in name or "/template/" in name or path.suffix == ".md" or
                   path.name in ("spdx-licenses-3.27.0.json", "lp01-policy-1.0.0.json",
                                 "mit-full.txt", "bsd-full.txt"))
        if genuine:
            digest = sha(data)
            if digest not in seed_hashes:
                seed_name = name.replace("/", "__")
                (seeds / seed_name).write_bytes(data)
                seed_pins.append([seed_name, len(data), digest])
                seed_hashes[digest] = seed_name
            table.files[name] = ["r", seed_hashes[digest]]
            continue
        document = None
        try:
            parsed = json.loads(data)
            for ascii_only in (True, False):
                if (json.dumps(parsed, indent=2, ensure_ascii=ascii_only) + "\n").encode() == data:
                    document = parsed
                    table.files[name] = ["j" if ascii_only else "u", table.node(parsed)]
                    break
        except (ValueError, UnicodeDecodeError):
            pass
        if document is None:
            parts = []
            start, rolling = 0, 0
            for index, byte in enumerate(data):
                rolling = ((rolling << 1) + byte + 1) & 0xffff
                if index + 1 - start >= 64 and (rolling & 127 == 0 or index + 1 - start >= 1024):
                    raw = data[start:index + 1]
                    if raw not in chunks:
                        chunks[raw] = len(bank)
                        bank.extend(raw)
                    parts.append([chunks[raw], len(raw)])
                    start, rolling = index + 1, 0
            if start < len(data):
                raw = data[start:]
                if raw not in chunks:
                    chunks[raw] = len(bank)
                    bank.extend(raw)
                parts.append([chunks[raw], len(raw)])
            table.files[name] = ["b", parts]
        if path.name == "cases.json":
            suite = json.loads(data)
            output = {"schema_version": 1, "cases": [
                {"case_id": item["case_id"], "result": item["expected"]} for item in suite["cases"]]}
            outputs[name] = sha((canonical(output) + "\n").encode())
    def write(name, value):
        raw = (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
        (STORE / name).write_bytes(raw)
        return sha(raw)
    recipe_sha = write("recipes.json", tables[0].document())
    expectation_sha = write("expectations.json", tables[1].document())
    (STORE / "chunks.bin").write_bytes(bank)
    write("lock.json", {"schema": "resolver-corpus/1", "parent": ACCEPTED, "files": pins,
                       "seeds": seed_pins, "row_outputs": outputs, "recipes_sha256": recipe_sha,
                       "expectations_sha256": expectation_sha, "bank_sha256": sha(bank)})
    test = STORE.parent / ".corpus-equivalence"
    materialize(test)
    try:
        for name, length, digest in pins:
            check((test / name).read_bytes() == (original / name).read_bytes(), "Pre-removal byte mismatch")
        print("Pre-removal proof:", len(pins), "paths,", sum(p[1] for p in pins), "bytes identical.")
    finally:
        shutil.rmtree(test)
    print("Compact store:", sum(p.stat().st_size for p in STORE.rglob("*") if p.is_file()), "bytes")


if __name__ == "__main__":
    main()
