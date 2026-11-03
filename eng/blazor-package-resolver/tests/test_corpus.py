"""Finite materializer rejection checks and independent, deliberately narrow PI-01 facts."""
import copy
import json
from pathlib import Path
import shutil
import struct
import subprocess
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
    current = json.loads((fixtures / "lp01/cases.json").read_bytes())
    historical = copy.deepcopy(current)
    for case in historical["cases"]:
        case["expected"]["resolver_version"] = "1.0.0"
        if case["expected"]["branch_id"] == "approved-non-copyleft":
            case["expected"].update(corpus.LP01_APPROVED_BEFORE)
    def encoded(value):
        return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()
    before = encoded(historical)
    corpus.check_parent_file("lp01/cases.json", before, encoded(current))
    approved = next(i for i, case in enumerate(current["cases"])
                    if case["expected"]["branch_id"] == "approved-non-copyleft")
    other = next(i for i, case in enumerate(current["cases"])
                 if case["expected"]["branch_id"] == "file-declared")
    rejected_changes = (
        ("other result", lambda suite: suite["cases"][other]["expected"].update(finding="unreviewed")),
        ("other branch", lambda suite: suite["cases"][other]["expected"].update(branch_id="approved-non-copyleft")),
        ("input bytes", lambda suite: suite["cases"][approved]["inputs"][0].update(sha256="0" * 64)),
        ("approved evidence", lambda suite: suite["cases"][approved]["expected"].update(evidence_references=[])),
        ("approved finding", lambda suite: suite["cases"][approved]["expected"].update(finding="unreviewed")),
    )
    for label, change in rejected_changes:
        changed = copy.deepcopy(current)
        change(changed)
        try:
            corpus.check_parent_file("lp01/cases.json", before, encoded(changed))
        except ValueError:
            pass
        else:
            raise ValueError("Parent preservation accepted " + label)
    for name in ("lp02/cases.json", "lp01/README.md", "lp01/packages/mit.nupkg"):
        try:
            corpus.check_parent_file(name, b"historical", b"unreviewed")
        except ValueError:
            pass
        else:
            raise ValueError("Parent preservation accepted unreviewed bytes: " + name)
    print("Named LP-01 parent allowance accepted; eight unreviewed result/input/contract changes rejected.")
    name = "lp04/cases.json"
    before_lp04 = corpus.historical_parent_bytes(fixtures, name)
    current_lp04 = json.loads((fixtures / name).read_bytes())
    corpus.check_parent_file(name, before_lp04, encoded(current_lp04))
    for label, change in (
        ("input pin", lambda suite: suite["cases"][1]["inputs"][0].update(sha256="0" * 64)),
        ("rationale", lambda suite: suite["cases"][0].update(rationale="unreviewed")),
        ("branch", lambda suite: suite["cases"][0]["expected"].update(branch_id="origin-review-missing")),
        ("version", lambda suite: suite["cases"][0]["expected"].update(resolver_version="1.0.0")),
        ("result", lambda suite: suite["cases"][0]["expected"].update(missing_fact="unreviewed")),
        ("inventory", lambda suite: suite["cases"][0]["expected"].update(bundled_web_assets={})),
        ("case identity", lambda suite: suite["cases"][0].update(case_id="unreviewed")),
        ("extra case", lambda suite: suite["cases"].append(copy.deepcopy(suite["cases"][0]))),
    ):
        changed = copy.deepcopy(current_lp04)
        change(changed)
        try:
            corpus.check_parent_file(name, before_lp04, encoded(changed))
        except ValueError:
            pass
        else:
            raise ValueError("LP-04 D-lite parent preservation accepted " + label)
    for row in [f"lp{i:02}" for i in range(1, 11) if i != 4] + ["pi01"]:
        name = row + "/cases.json"
        before_row = corpus.historical_parent_bytes(fixtures, name)
        changed = json.loads((fixtures / name).read_bytes())
        changed["cases"][0]["expected"]["missing_fact"] = "Unapproved cross-row change"
        try:
            corpus.check_parent_file(name, before_row, encoded(changed))
        except ValueError:
            pass
        else:
            raise ValueError("D-lite migration admitted a change to another row: " + row)
    print("Named LP-04 D-lite result allowance accepted; eight mutations and all ten cross-row edits rejected.")
    current_lp02 = json.loads((fixtures / "lp02/cases.json").read_bytes())
    historical_lp02 = copy.deepcopy(current_lp02)
    old_missing = "Selected project and implementation files do not establish the bounded library-source mapping."
    for case in historical_lp02["cases"]:
        result = case["expected"]
        result["resolver_version"] = "1.0.0"
        if case["case_id"] in ("lp02-wrong-project-identity", "lp02-missing-implementation"):
            result.update(branch_id="source-relevance-unestablished", decision="escalated",
                          applicability="unknown", finding=None, missing_fact=old_missing,
                          required_input="exact-package-and-anonymous-source-capture", next_category="source-acquisition")
            case["rationale"] = case["rationale"].replace(
                "must yield public-source-observed.", "must yield source-relevance-unestablished.")
        elif result["branch_id"] == "public-source-observed":
            result["finding"] = result["finding"].replace(
                "and the retained nonempty archive matches the declared repository/revision root. ",
                "and retained files support a bounded mapping to the package's library source. ").replace(
                "The package declaration supplies that association; source relevance is not independently established. ", "")
        elif result["branch_id"] == "source-relevance-unestablished":
            result["missing_fact"] = old_missing
    before_lp02 = encoded(historical_lp02)
    corpus.check_parent_file("lp02/cases.json", before_lp02, encoded(current_lp02))
    for label, change in (
        ("input binding", lambda suite: suite["cases"][15]["inputs"][0].update(sha256="0" * 64)),
        ("wrong branch", lambda suite: suite["cases"][0]["expected"].update(branch_id="public-source-observed")),
        ("wrong version", lambda suite: suite["cases"][0]["expected"].update(resolver_version="1.0.0")),
        ("invented finding", lambda suite: suite["cases"][15]["expected"].update(finding="unreviewed")),
        ("evidence reference", lambda suite: suite["cases"][15]["expected"].update(evidence_references=[])),
        ("extra case", lambda suite: suite["cases"].append(copy.deepcopy(suite["cases"][0]))),
    ):
        changed = copy.deepcopy(current_lp02)
        change(changed)
        try:
            corpus.check_parent_file("lp02/cases.json", before_lp02, encoded(changed))
        except ValueError:
            pass
        else:
            raise ValueError("LP-02 parent preservation accepted " + label)
    print("Named LP-02 public-availability allowance accepted; six unrelated changes rejected.")
    for name in corpus.LP03_LEGACY_PINS:
        before_lp03 = corpus.historical_parent_bytes(fixtures, name)
        current_lp03 = json.loads((fixtures / name).read_bytes())
        corpus.check_parent_file(name, before_lp03, encoded(current_lp03))
        for label, change in (
            ("input pin", lambda suite: suite["cases"][0]["inputs"][0].update(sha256="0" * 64)),
            ("rationale", lambda suite: suite["cases"][0].update(rationale="unreviewed")),
            ("evidence reference", lambda suite: suite["cases"][0]["expected"].update(evidence_references=[])),
            ("branch", lambda suite: suite["cases"][0]["expected"].update(branch_id="dependencies-policy-satisfied")),
            ("version", lambda suite: suite["cases"][0]["expected"].update(resolver_version="1.0.0")),
            ("result text", lambda suite: suite["cases"][0]["expected"].update(missing_fact="unreviewed")),
            ("case identity", lambda suite: suite["cases"][0].update(case_id="unreviewed")),
            ("extra case", lambda suite: suite["cases"].append(copy.deepcopy(suite["cases"][0]))),
        ):
            changed = copy.deepcopy(current_lp03)
            change(changed)
            try:
                corpus.check_parent_file(name, before_lp03, encoded(changed))
            except ValueError:
                pass
            else:
                raise ValueError("LP-03 parent preservation accepted " + label)
    print("Named lp03-sbom-declarations-1.1.0 allowance accepted; 16 unrelated changes rejected; all legacy inputs unchanged.")
    for row in ("lp01", "lp03", "pi01"):
        for filename in ("cases.json", "acceptance.json"):
            name = row + "/" + filename
            historical_bytes = corpus.historical_parent_bytes(fixtures, name)
            current_namespace = json.loads((fixtures / name).read_bytes())
            corpus.check_parent_file(name, historical_bytes, encoded(current_namespace))
            for label, change in (
                ("version rollback", lambda suite: suite["cases"][0]["expected"].update(resolver_version="1.0.0")),
                ("branch", lambda suite: suite["cases"][0]["expected"].update(branch_id="unreviewed")),
                ("input pin", lambda suite: suite["cases"][-1]["inputs"][0].update(sha256="0" * 64)),
                ("rationale", lambda suite: suite["cases"][0].update(rationale="unreviewed")),
                ("finding", lambda suite: suite["cases"][0]["expected"].update(finding="unreviewed")),
                ("extra case", lambda suite: suite["cases"].append(copy.deepcopy(suite["cases"][0]))),
            ):
                changed = copy.deepcopy(current_namespace)
                change(changed)
                try:
                    corpus.check_parent_file(name, historical_bytes, encoded(changed))
                except ValueError:
                    pass
                else:
                    raise ValueError("Nuspec namespace parent allowance accepted " + row + ": " + label)
    before_foundation = corpus.historical_parent_bytes(fixtures, "cases.json")
    current_foundation = (fixtures / "cases.json").read_bytes()
    corpus.check_parent_file("cases.json", before_foundation, current_foundation)
    corpus.check(set(corpus._parent_patches()["pins"]) == {name for name, _, _ in lock["files"]},
                 "Historical parent pin set differs from locked corpus")
    for name, _, _ in lock["files"]:
        current_bytes = (fixtures / name).read_bytes()
        corpus.check_parent_file(name, corpus.historical_parent_bytes(fixtures, name, allow_git=True), current_bytes)
        corpus.check_parent_file(name, corpus.historical_parent_bytes(fixtures, name, allow_git=False), current_bytes)
    unpatched = fixtures / "lp05/cases.json"
    saved_unpatched = unpatched.read_bytes()
    try:
        unpatched.write_bytes(saved_unpatched + b" ")
        try:
            corpus.historical_parent_bytes(fixtures, "lp05/cases.json", allow_git=False)
        except ValueError:
            pass
        else:
            raise ValueError("Unpatched parent pin failed to reject drifted file without git")
    finally:
        unpatched.write_bytes(saved_unpatched)
    for changed in (
        current_foundation.replace(b'"1.1.0"', b'"1.2.0"', 1),
        current_foundation.replace(b'"missing-policy"', b'"unreviewed"', 1),
        current_foundation.replace(b'"c51ea103', b'"051ea103', 1),
        current_foundation.replace(b'"synthetic-package"', b'"unreviewed"', 1),
    ):
        try:
            corpus.check_parent_file("cases.json", before_foundation, changed)
        except ValueError:
            pass
        else:
            raise ValueError("Foundation namespace allowance accepted unrelated changes")
    print("Named nuspec-namespaces version-only allowances accepted; 40 unrelated changes rejected.")
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
    corpus.check(runs == 12, "Missing finite rejection recipe")
    with tempfile.TemporaryDirectory(prefix="corpus-existing-") as work:
        try:
            corpus.materialize(work)
        except ValueError:
            pass
        else:
            raise ValueError("Existing output root was overwritten")
    print("13 fixed materializer rejection/overwrite checks passed;",
          len(lock["files"]), "paths /", sum(pin[1] for pin in lock["files"]), "locked bytes.")


if __name__ == "__main__":
    main()
