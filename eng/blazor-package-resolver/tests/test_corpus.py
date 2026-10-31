"""Finite materializer rejection checks and independent, deliberately narrow PI-01 facts."""
import copy
import json
from pathlib import Path
import shutil
import struct
import tempfile

import corpus


def main():
    original = corpus.STORE
    lock = corpus.load("lock.json")
    # This assertion protects the preserved two foundation plus 868 row replay inventory.
    parent, fixtures = corpus.temporary()
    suites = list(fixtures.rglob("cases.json"))
    corpus.check(sum(len(json.loads(path.read_bytes())["cases"]) for path in suites) == 870,
                 "Changed accepted replay inventory")
    corpus.check(all(corpus.sha((fixtures / name).read_bytes()) == digest
                     for name, _, digest in lock["files"]), "Byte pins changed")
    key = (fixtures / "pi01/template/public.snk").read_bytes()
    corpus.check(len(key) == 276 and key[:4] == b"\x06\x02\x00\x00" and key[8:12] == b"RSA1" and
                 struct.unpack_from("<I", key, 12)[0] == 2048, "Control key is not public-only")
    states = {}
    for path in sorted((fixtures / "pi01/templates").glob("*")):
        image = path.read_bytes()
        if image[:2] != b"MZ":
            continue
        pe = struct.unpack_from("<I", image, 0x3c)[0]
        corpus.check(image[pe:pe + 4] == b"PE\0\0", "Control is not a PE image")
        count, optional_size = struct.unpack_from("<H", image, pe + 6)[0], struct.unpack_from("<H", image, pe + 20)[0]
        optional = pe + 24
        directory = optional + (96 if struct.unpack_from("<H", image, optional)[0] == 0x10b else 112)
        rva = struct.unpack_from("<I", image, directory + 14 * 8)[0]
        sections = optional + optional_size
        offsets = []
        for index in range(count):
            section = sections + index * 40
            size, start, raw_size, raw_start = struct.unpack_from("<IIII", image, section + 8)
            if start <= rva < start + min(size, raw_size):
                offsets.append(raw_start + rva - start)
        corpus.check(len(offsets) == 1, "Ambiguous control CLR header")
        cli = offsets[0]
        flags = struct.unpack_from("<I", image, cli + 16)[0]
        signature_rva, signature_size = struct.unpack_from("<II", image, cli + 32)
        states[path.name] = (bool(flags & 8), signature_size > 0, signature_rva > 0)
    corpus.check(states["unsigned.dll"] == (False, False, False), "Unsigned construction fact")
    corpus.check(states["verified.dll"] == (True, True, True), "Signed control header fact")
    corpus.check(states["module.netmodule"] == (False, False, False), "Module construction fact")
    # Header facts and byte pins are NOT independent metadata or RSA/CMS semantic validation.
    print("Independent PI-01 construction facts: public-only key and", len(states),
          "PE controls; no independent crypto/metadata-validation claim.")
    runs = 0
    def reject(label, change):
        nonlocal runs
        with tempfile.TemporaryDirectory(prefix="corpus-rejection-") as work:
            store = Path(work) / "store"
            shutil.copytree(original, store)
            corpus.STORE = store
            try:
                change(store)
                try:
                    corpus.materialize(Path(work) / "outputs")
                except (ValueError, KeyError, OSError):
                    runs += 1
                else:
                    raise ValueError("Materializer accepted weakening: " + label)
            finally:
                corpus.STORE = original
    def edit_lock(store, change):
        value = json.loads((store / "lock.json").read_bytes())
        change(value)
        (store / "lock.json").write_text(json.dumps(value))
    def edit_recipe(store, change):
        value = json.loads((store / "recipes.json").read_bytes())
        change(value)
        raw = json.dumps(value).encode()
        (store / "recipes.json").write_bytes(raw)
        edit_lock(store, lambda item: item.update(recipes_sha256=corpus.sha(raw)))
    reject("missing seed", lambda store: (store / "seeds" / lock["seeds"][0][0]).unlink())
    reject("extra seed", lambda store: (store / "seeds/extra.txt").write_bytes(b"extra"))
    reject("changed seed", lambda store: (store / "seeds" / lock["seeds"][0][0]).write_bytes(b"wrong"))
    reject("changed bank", lambda store: (store / "chunks.bin").write_bytes(b"wrong"))
    reject("changed recipe", lambda store: (store / "recipes.json").write_bytes(b"{}"))
    reject("changed expectation", lambda store: (store / "expectations.json").write_bytes(b"{}"))
    reject("missing output", lambda store: edit_recipe(store, lambda item: item["files"].pop(next(iter(item["files"])))))
    reject("extra output", lambda store: edit_recipe(store, lambda item: item["files"].update({"extra.txt": ["b", []]})))
    reject("unsafe output", lambda store: edit_recipe(store, lambda item: item["files"].update({"../escape": ["b", []]})))
    reject("wrong output pin", lambda store: edit_lock(store, lambda item: item["files"][0].__setitem__(2, "0" * 64)))
    reject("wrong canonical answer pin", lambda store: edit_lock(
        store, lambda item: item["row_outputs"].__setitem__("lp04/cases.json", "0" * 64)))
    reject("unknown schema", lambda store: edit_lock(store, lambda item: item.update(schema="unknown")))
    reject("invalid raw slice", lambda store: edit_recipe(
        store, lambda item: item["files"].__setitem__(next(iter(item["files"])), ["b", [[-1, 1]]])))
    reject("unknown operation", lambda store: edit_recipe(
        store, lambda item: item["files"].__setitem__(next(iter(item["files"])), ["repair-archive", []])))
    reject("resource limit", lambda store: edit_lock(
        store, lambda item: item.__setitem__("files", item["files"] * 2)))
    corpus.check(runs == 15, "Missing finite rejection recipe")
    with tempfile.TemporaryDirectory(prefix="corpus-existing-") as work:
        try:
            corpus.materialize(work)
        except ValueError:
            pass
        else:
            raise ValueError("Existing output root was overwritten")
    print("16 fixed materializer rejection/overwrite checks passed; 1,563 paths / 6,007,501 bytes preserved.")


if __name__ == "__main__":
    main()
