"""Independent D-lite construction facts; no production imports or execution."""
import hashlib
import io
import json
from pathlib import Path
import zipfile

CONTRACT = (
    "Package-byte classification under bundled-web-assets/1, not a legal determination. "
    "Only the assessed nupkg is inspected; no origin, SBOM, applicability or notice conclusion is inferred. "
    "Other representations were not assessed. Legacy notice-coverage-v1 deciding packets are retired.")
EMPTY = "No JS/CSS assets detected in the supported package layouts; other representations were not assessed."
FIXED = {
    "missing-package": ("The exact root package is missing.", "package", "package-acquisition"),
    "input-invalid": ("The package is unsafe, malformed, incomplete or outside the bounded supported profile.",
                      "safe-bounded-package", "evidence-repair"),
    "legacy-protocol": ("A retired notice-coverage-v1 role or packet was supplied; it cannot decide LP-04.",
                        "package-only-request", "evidence-repair"),
}
SUFFIXES = (".js", ".mjs", ".cjs", ".css", ".map")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inventory(files, unsupported=()):
    assets = [{"path": path, "length": len(data), "sha256": digest(data)}
              for path, data in sorted(files, key=lambda item: item[0].encode("utf-16-be"))]
    canonical = "bundled-web-assets/1\n" + "".join(
        f"{asset['path']}\t{asset['length']}\t{asset['sha256']}\n" for asset in assets)
    return {"profile": "bundled-web-assets/1", "assets": assets,
            "unsupported_candidates": sorted(unsupported, key=lambda path: path.encode("utf-16-be")),
            "inventory_sha256": digest(canonical.encode())}


def result(branch, pins, surface=None):
    if branch in FIXED:
        missing, required, next_category = FIXED[branch]
    else:
        assets = surface["assets"]
        counts = ", ".join(f"{suffix}={sum(asset['path'].lower().endswith(suffix) for asset in assets)}"
                           for suffix in SUFFIXES)
        summary = (f"bundled-web-assets/1: {len(assets)} assets ({counts}), "
                   f"{sum(asset['length'] for asset in assets)} bytes; inventory SHA-256 {surface['inventory_sha256']}.")
        if branch == "no-supported-layout-assets":
            missing = EMPTY + " Scanned suffixes: .js, .mjs, .cjs, .css, .map. " + summary
            required = "evidence-of-applicability-or-other-representations"
        elif branch == "surface-unsupported":
            missing = (summary + f" {len(surface['unsupported_candidates'])} unsupported candidates are retained in "
                       "bundled_web_assets.unsupported_candidates; their origin and notice obligations are unknown.")
            required = "supported-surface-or-separate-assessment"
        elif branch == "origin-review-missing":
            missing = summary + " Origin and notice obligations are unknown; no origin, SBOM, applicability or notice conclusion is inferred."
            required = "asset-origin-and-notice-obligations"
        else:
            raise ValueError("Unknown independent D-lite branch")
        next_category = "notice-investigation"
    value = dict(row_id="LP-04", resolver_id="lp04-notice-coverage", resolver_version="2.0.0",
                 branch_id=branch, decision="escalated", applicability="unknown", inputs=pins,
                 evidence_references=[], evidence_contract=CONTRACT, finding=None,
                 missing_fact=missing, required_input=required, next_category=next_category)
    if surface is not None:
        value["bundled_web_assets"] = surface
    return value


def legacy_delta(suite):
    """Named case construction, not inferred from old/production deciding results."""
    for case in suite["cases"]:
        case_id = case["case_id"]
        if case_id == "lp04-missing-package":
            branch = "missing-package"
        elif case_id in ("lp04-duplicate-package-path", "lp04-alias-package-path"):
            branch = "input-invalid"
        else:
            branch = "legacy-protocol"
        if case["row_id"] != "LP-04" or case["expected"]["resolver_version"] != "1.0.0":
            raise ValueError("Unexpected historical LP-04 case identity")
        case["expected"] = result(branch, case["inputs"])


def mapping_results():
    return ([result(branch, []) for branch in FIXED] +
            [result("no-supported-layout-assets", [], inventory([])),
             result("origin-review-missing", [], inventory([("wwwroot/x.js", b"x")])),
             result("surface-unsupported", [], inventory([], ["tools/x.js"]))])


def main():
    root = Path(__file__).parent / "fixtures" / "lp04"
    suite = json.loads((root / "cases.json").read_bytes())
    counts = {}
    for case in suite["cases"]:
        pins = case["inputs"]
        package = next((pin for pin in pins if pin["role"] == "package"), None)
        if package is None:
            branch = "missing-package"
        else:
            raw = (root / package["path"]).read_bytes()
            if digest(raw) != package["sha256"]:
                raise ValueError("Changed independent fixture package")
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                names = archive.namelist()
                if archive.testzip() is not None:
                    raise ValueError("Unexpected corrupt fixture construction")
                branch = "input-invalid" if len(set(name.casefold() for name in names)) != len(names) else "legacy-protocol"
            if not any(pin["role"] != "package" for pin in pins):
                raise ValueError("Historical synthetic fixture is not a legacy-role refusal witness")
        if case["expected"] != result(branch, pins):
            raise ValueError("Independent D-lite fixture mismatch: " + case["case_id"])
        counts[branch] = counts.get(branch, 0) + 1
    if counts != {"missing-package": 1, "legacy-protocol": 40, "input-invalid": 2}:
        raise ValueError("Historical construction inventory changed")
    sample = inventory([("wwwroot/b.js", b""), ("wwwroot/a.css", b"x")])
    if sample != inventory([("wwwroot/a.css", b"x"), ("wwwroot/b.js", b"")]):
        raise ValueError("Independent inventory is not deterministic")
    print("LP-04 D-lite: 43 independent legacy/safety expectations; six N-only branch specifications; "
          "canonical inventory order checked. Historical v1 oracle and optional acceptance are retired.")


if __name__ == "__main__":
    main()
