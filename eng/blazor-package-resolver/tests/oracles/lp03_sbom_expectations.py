"""Independent B-prime specifications and byte construction; never invokes production."""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile
import xml.etree.ElementTree as ET

NPM_TRUST = "npm archive hashes bind caller-designated bytes and do not authenticate publisher archives."
CONTRACT = (
    "The caller designates the bound raw SBOM as the authoritative release-wide inventory; "
    "structural checks do not independently establish completeness or publication. "
    "Each included dependency is classified from its exact checked nupkg or npm tarball declaration "
    "using LP-01 policy 1.0.0 and SPDX 3.27.0. No ordinary grant, reviewer or owner approval "
    "is required. No legal sufficiency, notice compliance or build correspondence is established. " + NPM_TRUST)
LEGACY = "The supplied LP-03 assessment uses legacy schema 1; re-admit a schema-2 release-wide SBOM packet."
FIXED = {
    "missing-package": ("The exact root package is missing.", "package", "package-acquisition"),
    "scope-missing": ("The exact root and release-wide SBOM assessment binding is missing.", "assessment", "assessment-scope"),
    "input-invalid": (LEGACY, "supported-release-sbom-packet", "evidence-repair"),
    "policy-unavailable": ("The pinned policy and SPDX catalog are missing or inconsistent.", "pinned-policy-and-corpus", "policy-acquisition"),
    "binding-conflict": ("Exact root, SBOM, designation or dependency bindings disagree.", "consistent-checked-bindings", "evidence-repair"),
    "evidence-missing": ("The retained raw release SBOM is missing.", "release-sbom", "dependency-acquisition"),
    "closure-unresolved": ("Release inventory structure or caller designation is unsupported or incomplete.", "authoritative-release-inventory", "dependency-acquisition"),
    "dependency-bytes-missing": ("An exact inventoried dependency archive is unavailable.", "exact-dependency-bytes", "dependency-acquisition"),
    "license-evidence-unresolved": ("An exact-package license declaration is missing, ambiguous or unsupported.", "exact-dependency-license-declaration", "license-investigation"),
}
BRANCHES = (*FIXED, "incompatible-dependency-license", "dependencies-policy-satisfied")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def result(branch, pins, detail=None):
    positive = branch == "dependencies-policy-satisfied"
    negative = branch == "incompatible-dependency-license"
    missing, required, next_category = FIXED.get(branch, (None, None, None))
    finding = None
    if positive:
        finding = ("Under the caller's exact-root/raw-SBOM authoritative release-wide designation, all admitted dependency declarations satisfy the pinned OSI-approved non-copyleft policy. " +
                   detail + " Structural admission does not independently prove completeness or publication.")
    elif negative:
        finding = "An exact dependency in the caller-designated release inventory declares an incompatible copyleft or non-OSI license under the pinned policy: " + detail
    elif detail is not None:
        missing = detail
    if finding is not None:
        finding += " " + NPM_TRUST
    if missing is not None:
        missing += " " + NPM_TRUST
    return dict(row_id="LP-03", resolver_id="lp03-dependency-licenses", resolver_version="1.4.0",
                branch_id=branch, decision="deterministic" if positive or negative else "escalated",
                applicability="applicable" if positive or negative else "unknown", inputs=pins,
                evidence_references=[f"input:{p['role']}:{p['sha256']}" for p in pins],
                evidence_contract=CONTRACT, finding=finding, missing_fact=missing,
                required_input=required, next_category=next_category)


def legacy_result(old):
    branch = old["branch_id"] if old["branch_id"] in ("missing-package", "scope-missing") else "input-invalid"
    return result(branch, old["inputs"])


def mapping_results():
    return [result(branch, [], "synthetic mapping witness") for branch in BRANCHES]


def package(package_id, version="1.0.0", expression="MIT", dependencies="", license_xml=None):
    license_xml = (f'<license type="expression">{expression}</license>' if expression is not None else "") if license_xml is None else license_xml
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_STORED) as archive:
        entry = zipfile.ZipInfo("Package.nuspec", (2020, 1, 1, 0, 0, 0))
        archive.writestr(entry, f"<package><metadata><id>{package_id}</id><version>{version}</version>{license_xml}{dependencies}</metadata></package>")
    return memory.getvalue()


def sbom(dependencies=("example.dependency",)):
    def component(name, spdx, version="1.0.0", product=False):
        return dict(name=name, SPDXID=spdx, downloadLocation="NOASSERTION", filesAnalyzed=False,
                    licenseConcluded="NOASSERTION", licenseDeclared="NOASSERTION", copyrightText="NOASSERTION",
                    versionInfo=("v" if product else "") + version,
                    externalRefs=[dict(referenceCategory="PACKAGE-MANAGER", referenceType="purl",
                                       referenceLocator=(f"pkg:swid/Example/github.com/{name}@v{version}?tag_id=11111111-1111-1111-1111-111111111111" if product else f"pkg:nuget/{name}@{version}"))],
                    supplier="NOASSERTION")
    packages = [component("example.controls", "SPDXRef-Product", product=True),
                component("example.controls", "SPDXRef-Root")]
    packages += [component(name, f"SPDXRef-Dependency-{i}") for i, name in enumerate(dependencies)]
    return dict(externalDocumentRefs=[], spdxVersion="SPDX-2.2", dataLicense="CC0-1.0",
                SPDXID="SPDXRef-DOCUMENT", name="example.controls v1.0.0", documentNamespace="https://example.test/release/1.0.0",
                creationInfo=dict(created="2026-01-01T00:00:00Z", creators=["Tool: synthetic"]),
                documentDescribes=["SPDXRef-Product"], packages=packages, files=[],
                relationships=[dict(relationshipType="DESCRIBES", spdxElementId="SPDXRef-DOCUMENT", relatedSpdxElement="SPDXRef-Product")] +
                [dict(relationshipType="DEPENDS_ON", spdxElementId="SPDXRef-Product", relatedSpdxElement=p["SPDXID"]) for p in packages[1:]])


def scope(root, raw, designation=True):
    identity = dict(id="example.controls", version="1.0.0", sha256=digest(root))
    return dict(schema_version=2, root=identity, inventory_scope="release-wide", sbom_sha256=digest(raw),
                designation=dict(basis="caller-authoritative-release-inventory/1", scope="release-wide",
                                 root=identity.copy(), sbom_sha256=digest(raw)) if designation else None)


def specimens(policy, catalog):
    """Expected branches/details are normative constants, not computed by a classifier."""
    root = package("example.controls")
    base = {"package": root, "policy": policy, "corpus": catalog,
            "dependency-000": package("example.dependency")}
    cases = []
    def add(name, branch, detail=None, document=None, mutate=None, root_bytes=None, dependency=None):
        packet = base.copy()
        if root_bytes is not None:
            packet["package"] = root_bytes
        if dependency is not None:
            packet["dependency-000"] = dependency
        raw = encoded(document if document is not None else sbom())
        packet["sbom"] = raw
        packet["assessment"] = encoded(scope(packet["package"], raw))
        if mutate:
            mutate(packet)
        cases.append((name, packet, branch, detail))
    success = "1 exact dependency declarations pass; the caller's bound designation supplies authoritative release-wide scope."
    add("all-mit-no-grants-no-reviews", "dependencies-policy-satisfied", success)
    for file_name, extra in (
        ("./example.controls.1.0.0.nupkg",
         " Published file checksum differs from assessed root bytes: ./example.controls.1.0.0.nupkg; published " +
         "0" * 64 + "; assessed " + digest(root) + ". PI-10 is separately assessed."),
        ("./unrelated.css", "")):
        d = sbom()
        d["files"] = [dict(fileName=file_name, SPDXID="SPDXRef-File", checksums=[
            dict(algorithm="SHA256", checksumValue="0" * 64)], licenseConcluded="NOASSERTION",
            licenseInfoInFiles=["NOASSERTION"], copyrightText="NOASSERTION")]
        add("root-checksum-diagnostic" if extra else "unrelated-file-not-root-comparison",
            "dependencies-policy-satisfied", success + extra, document=d)
    for label, expression in (("allowed-or", "MIT OR Apache-2.0"), ("allowed-and", "MIT AND Apache-2.0")):
        add(label, "dependencies-policy-satisfied", success, dependency=package("example.dependency", expression=expression))
    for label, expression in (("copyleft", "GPL-3.0-only"), ("weak-copyleft", "LGPL-2.1-only"), ("non-osi", "BUSL-1.1")):
        add(label, "incompatible-dependency-license", "example.dependency/1.0.0", dependency=package("example.dependency", expression=expression))
    for label, expression, state in (
        ("noassertion", "NOASSERTION", "unknown-license"), ("missing-license", None, "missing-license"),
        ("custom", "LicenseRef-owner-grant", "custom-license"), ("mixed", "MIT OR GPL-3.0-only", "mixed-alternatives"),
        ("with", "MIT WITH LLVM-exception", "exception-unreviewed"), ("deprecated", "BSD-2-Clause-FreeBSD", "deprecated-license"),
        ("unclassified", "EUPL-1.2", "unclassified-osi")):
        add(label, "license-evidence-unresolved", f"Unsupported or ambiguous exact-package declarations: example.dependency/1.0.0 ({state})",
            dependency=package("example.dependency", expression=expression))
    for label, xml in (("file-only", '<license type="file">LICENSE.txt</license>'),
                       ("licenseUrl-only", "<licenseUrl>https://example.test/MIT</licenseUrl>")):
        state = "file-unverified" if label == "file-only" else "missing-license"
        add(label, "license-evidence-unresolved", f"Unsupported or ambiguous exact-package declarations: example.dependency/1.0.0 ({state})",
            dependency=package("example.dependency", license_xml=xml))
    add("expression-plus-licenseUrl", "dependencies-policy-satisfied", success,
        dependency=package("example.dependency", license_xml='<license type="expression">MIT</license><licenseUrl>https://example.test/gpl</licenseUrl>'))
    add("version-mismatch", "binding-conflict", "SBOM member and exact nupkg identity/version disagree: example.dependency/1.0.0",
        dependency=package("example.dependency", "2.0.0"))
    add("missing-nupkg", "dependency-bytes-missing", "Missing exact SBOM dependency bytes: example.dependency/1.0.0",
        mutate=lambda p: p.pop("dependency-000"))
    add("missing-package", "missing-package", mutate=lambda p: p.pop("package"))
    add("missing-assessment", "scope-missing", mutate=lambda p: p.pop("assessment"))
    add("missing-sbom", "evidence-missing", mutate=lambda p: p.pop("sbom"))
    add("missing-policy", "policy-unavailable", mutate=lambda p: p.pop("policy"))
    def change_scope(packet, edit):
        value = json.loads(packet["assessment"]); edit(value); packet["assessment"] = encoded(value)
    for label, edit, detail in (
        ("no-designation", lambda s: s.update(designation=None), "Caller authoritative release-wide inventory designation is missing."),
        ("sample-designation", lambda s: s["designation"].update(scope="sample"), "The designation is unknown, sampled, partial or not release-wide."),
        ("unknown-designation", lambda s: s["designation"].update(basis="unknown"), "The designation is unknown, sampled, partial or not release-wide.")):
        add(label, "closure-unresolved", detail, mutate=lambda p, edit=edit: change_scope(p, edit))
    add("wrong-designation-binding", "binding-conflict", "Caller designation does not bind this exact root and raw SBOM.",
        mutate=lambda p: change_scope(p, lambda s: s["designation"].update(sbom_sha256="0" * 64)))
    add("wrong-root-binding", "binding-conflict", "Assessment root does not match exact package bytes.",
        mutate=lambda p: change_scope(p, lambda s: s["root"].update(version="2.0.0")))
    add("extra-nupkg", "binding-conflict", "Extra dependency role is not an admitted SBOM member.",
        mutate=lambda p: p.update({"dependency-001": package("extra")}))
    add("legacy-scope", "input-invalid", LEGACY, mutate=lambda p: change_scope(p, lambda s: s.update(schema_version=1)))
    d = sbom(); d["spdxVersion"] = "SPDX-2.3"
    add("unsupported-format", "closure-unresolved", "Only the retained SPDX-2.2 JSON profile is supported.", document=d)
    d = sbom(); d["packages"].append(copy.deepcopy(d["packages"][-1]))
    add("duplicate-id", "closure-unresolved", "Duplicate SPDX package ID.", document=d)
    d = sbom(); extra = copy.deepcopy(d["packages"][-1]); extra["SPDXID"] += "-extra"; d["packages"].append(extra)
    add("duplicate-component", "closure-unresolved", "Duplicate canonical component: nuget:example.dependency/1.0.0", document=d)
    d = sbom(); d["relationships"][-1]["relatedSpdxElement"] = "DocumentRef-external:node"
    add("dangling-edge", "closure-unresolved", "Unsupported or unresolved dependency relationship.", document=d)
    d = sbom(); d["relationships"].pop()
    add("orphan-node", "closure-unresolved", "Orphan or incomplete package inventory.", document=d)
    d = sbom(); d["externalDocumentRefs"] = [{"externalDocumentId": "external"}]
    add("external-ref", "closure-unresolved", "Unsupported array or inventory cap.", document=d)
    add("oversized-sbom", "input-invalid", "JSON byte limit/BOM.", mutate=lambda p: (
        p.update(sbom=b" " * (1024 * 1024 + 1)), change_scope(p, lambda s: s.update(sbom_sha256=digest(p["sbom"])))))
    add("empty-inventory", "dependencies-policy-satisfied",
        "0 exact dependency declarations pass; the caller's bound designation supplies authoritative release-wide scope.",
        document=sbom(()), mutate=lambda p: p.pop("dependency-000"))
    malformed = ('<dependencies><group targetFramework="net8.0"><dependency id="example.dependency" version="1.0.0"/></group>'
                 '<group targetFramework="net9.0"><dependency version="1.0.0"/></group></dependencies>')
    add("malformed-later-root-group-nonempty", "closure-unresolved", "Malformed or ambiguous root dependency identity.",
        root_bytes=package("example.controls", dependencies=malformed))
    add("known-direct-omitted", "closure-unresolved", "Known root direct dependency omitted or no inventoried version satisfies its NuGet range: absent",
        root_bytes=package("example.controls", dependencies='<dependencies><dependency id="absent"/></dependencies>'))
    add("duplicate-root-dependency", "closure-unresolved", "Malformed or ambiguous root dependency identity.",
        root_bytes=package("example.controls", dependencies='<dependencies><dependency id="example.dependency"/><dependency id="example.dependency"/></dependencies>'))
    two = sbom(("example.dependency", "z.dependency"))
    add("missing-precedes-gap", "dependency-bytes-missing", "Missing exact SBOM dependency bytes: z.dependency/1.0.0",
        document=two, dependency=package("example.dependency", expression="GPL-3.0-only"))
    add("unresolved-precedes-gap", "license-evidence-unresolved",
        "Unsupported or ambiguous exact-package declarations: z.dependency/1.0.0 (unknown-license)",
        document=two, dependency=package("example.dependency", expression="GPL-3.0-only"),
        mutate=lambda p: p.update({"dependency-001": package("z.dependency", expression="NOASSERTION")}))
    add("present-conflict-precedes-missing", "binding-conflict",
        "SBOM member and exact nupkg identity/version disagree: z.dependency/1.0.0", document=two,
        mutate=lambda p: (p.pop("dependency-000"), p.update({"dependency-001": package("z.dependency", "2.0.0")})))
    add("malformed-empty-root-group", "closure-unresolved", "Malformed or ambiguous root dependency identity.",
        document=sbom(()), mutate=lambda p: p.pop("dependency-000"),
        root_bytes=package("example.controls", dependencies='<dependencies><group targetFramework="net8.0"><dependency version="1.0.0"/></group></dependencies>'))
    return cases


def materialize(destination, policy, catalog):
    destination.mkdir()
    cases = []
    for name, packet, branch, detail in specimens(policy, catalog):
        folder = destination / name
        folder.mkdir()
        pins = []
        for role, data in sorted(packet.items()):
            path = folder / (role + ".bin")
            path.write_bytes(data)
            pins.append(dict(role=role, path=name + "/" + path.name, sha256=digest(data)))
        cases.append(dict(case_id=name, row_id="LP-03", inputs=pins, expected=result(branch, pins, detail),
                          rationale="Independent current-profile specification: " + name,
                          evidence_pointers=[f"input:{p['role']}:{p['sha256']}" for p in pins]))
    (destination / "cases.json").write_bytes(encoded(dict(schema_version=1, cases=cases)))


def reference(packet, policy, licenses):
    """Independent scoped admission witness. Full hostile-byte admission is tested natively."""
    if "package" not in packet: return "missing-package"
    if "assessment" not in packet: return "scope-missing"
    assessment = json.loads(packet["assessment"])
    if assessment["schema_version"] != 2: return "input-invalid"
    if "policy" not in packet or "corpus" not in packet: return "policy-unavailable"
    if "sbom" not in packet: return "evidence-missing"
    if len(packet["sbom"]) > 1024 * 1024: return "input-invalid"
    with zipfile.ZipFile(io.BytesIO(packet["package"])) as archive:
        metadata = ET.fromstring(archive.read("Package.nuspec")).find("metadata")
    if assessment["root"]["version"] != metadata.findtext("version"): return "binding-conflict"
    document = json.loads(packet["sbom"])
    if document["spdxVersion"] != "SPDX-2.2": return "closure-unresolved"
    ids, keys = set(), set()
    for component in document["packages"]:
        identity = component["SPDXID"]
        if identity in ids: return "closure-unresolved"
        ids.add(identity)
        if identity != "SPDXRef-Product":
            key = component["name"].lower() + "/" + component["versionInfo"]
            if key in keys: return "closure-unresolved"
            keys.add(key)
    if document["externalDocumentRefs"]: return "closure-unresolved"
    edges = [r for r in document["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
    if any(r["spdxElementId"] not in ids or r["relatedSpdxElement"] not in ids for r in edges): return "closure-unresolved"
    reached = {"SPDXRef-Product"}
    for _ in ids:
        reached.update(r["relatedSpdxElement"] for r in edges if r["spdxElementId"] in reached)
    if reached != ids: return "closure-unresolved"
    for dep in metadata.findall(".//dependency"):
        identity = dep.get("id", "").lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", identity): return "closure-unresolved"
        if not any(k.startswith(identity + "/") for k in keys): return "closure-unresolved"
    for group in metadata.findall("dependencies") + metadata.findall("dependencies/group"):
        declared = [d.get("id", "").lower() for d in group.findall("dependency")]
        if len(set(declared)) != len(declared): return "closure-unresolved"
    designation = assessment["designation"]
    if not designation or designation["basis"] != "caller-authoritative-release-inventory/1" or designation["scope"] != "release-wide":
        return "closure-unresolved"
    if designation["sbom_sha256"] != digest(packet["sbom"]): return "binding-conflict"
    keys.remove("example.controls/1.0.0")
    missing, unresolved, incompatible = False, False, False
    from lp01_expectations import classify_package
    for index, key in enumerate(sorted(keys)):
        content = packet.get(f"dependency-{index:03}")
        if content is None:
            missing = True; continue
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            meta = ET.fromstring(archive.read("Package.nuspec")).find("metadata")
        if meta.findtext("id").lower() + "/" + meta.findtext("version") != key: return "binding-conflict"
        branch, _, _ = classify_package(content, policy, licenses)
        if branch in ("copyleft", "weak-copyleft", "non-osi"): incompatible = True
        elif branch != "approved-non-copyleft": unresolved = True
    if any(role.startswith("dependency-") and int(role[11:]) >= len(keys) for role in packet): return "binding-conflict"
    return ("dependency-bytes-missing" if missing else "license-evidence-unresolved" if unresolved else
            "incompatible-dependency-license" if incompatible else "dependencies-policy-satisfied")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--materialize", type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    # Materialized oracle copies have fixtures beside them; repository invocation uses shipping assets.
    assets = here / "fixtures/lp01/policy"
    if assets.exists():
        policy_bytes = (assets / "lp01-policy-1.0.0.json").read_bytes()
        catalog_bytes = (assets / "spdx-licenses-3.27.0.json").read_bytes()
    else:
        data = here.parents[3] / "plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/scripts/eleven-row-data"
        policy_bytes, catalog_bytes = (data / "policy.json").read_bytes(), (data / "corpus.json").read_bytes()
    if args.materialize:
        materialize(args.materialize, policy_bytes, catalog_bytes)
        return
    policy = json.loads(policy_bytes)
    licenses = {x["licenseId"]: x for x in json.loads(catalog_bytes)["licenses"]}
    checked = 0
    for name, packet, expected, _ in specimens(policy_bytes, catalog_bytes):
        actual = reference(packet, policy, licenses)
        if actual != expected:
            raise ValueError(f"{name}: independent oracle {actual}, normative {expected}")
        checked += 1
    print(f"LP-03 B-prime: {checked} independently specified current-profile cases; no production/network execution.")


if __name__ == "__main__":
    main()
