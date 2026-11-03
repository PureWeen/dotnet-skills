"""Installed-plugin smoke checks. No model calls, network or assessed-code execution."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import zipfile
from unittest import mock
from argparse import Namespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def lp03_installed_checks(plugin, work):
    """Run the installed helper, replacing only build launchers with the prebuilt trusted DLL."""
    from oracles.lp03_sbom_expectations import sbom, package, encoded
    script = plugin / "skills/blazor-package-readiness-resolver/scripts/autofill-eleven.py"
    loaded = runpy.run_path(str(script), run_name="lp03_installed_test")
    tool = loaded["run_command"].__globals__
    resolver = REPO / "eng/blazor-package-resolver/bin/Debug/net10.0/BlazorPackageResolver.dll"
    if not resolver.is_file():
        raise ValueError("Build the trusted resolver with --no-restore before --lp03.")
    original_tools, original_collector = tool["Tools"], tool["Collector"]
    calls = []
    selected_bytes = package("example.dependency")

    def transport(url, destination, maximum, seconds):
        expected = tool["NUGET_FEEDS"][feed] + "/example.dependency/1.0.0/example.dependency.1.0.0.nupkg"
        if url != expected or maximum != tool["PACKAGE_LIMIT"] or not 0 < seconds <= 60:
            raise ValueError("A non-inventory/minimum/feed-fallback request escaped exact acquisition.")
        calls.append(url)
        destination.write_bytes(selected_bytes)
        return {"result": "succeeded", "detail_code": "http-200", "http_status": 200,
                "http_requests": [{"host": "api.nuget.org" if feed == "nuget.org" else "pkgs.dev.azure.com",
                                   "attempted_at_utc": "2026-10-30T12:00:00Z", "http_status": 200}]}

    class PrebuiltTools(original_tools):
        def command(self, args, output=None):
            if len(args) > 2 and args[0] == sys.executable and str(self.resolver) in args:
                idx = args.index(str(self.resolver))
                args = ["dotnet", str(resolver), *args[idx + 1:]]
            return super().command(args, output)

    class MockCollector(original_collector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs, transport=transport)

    for label, status, expression, online, designated, supplied, feed in (
        ("offline-exact-plus-extra", "verified", "MIT", False, True, True, "nuget.org"),
        ("mocked-exact-only", "verified", "MIT", True, True, False, "nuget.org"),
        ("offline-missing", "not tested", "MIT", False, True, False, "nuget.org"),
        ("no-designation", "not tested", "MIT", False, False, True, "nuget.org"),
        ("mocked-copyleft", "gap", "GPL-3.0-only", True, True, False, "nuget.org"),
        ("mocked-noassertion", "not tested", "NOASSERTION", True, True, False, "nuget.org"),
        ("mocked-file-only", "not tested", "FILE", True, True, False, "nuget.org"),
        ("explicit-mirror-no-hidden-fallback", "verified", "MIT", True, True, False, "dotnet-public"),
    ):
        calls.clear()
        selected_bytes = (package("example.dependency", license_xml='<license type="file">LICENSE.txt</license>')
                          if expression == "FILE" else package("example.dependency", expression=expression))
        root = work / label
        root.mkdir()
        nupkg = root / "sample.nupkg"
        # A minimum declaration is not used to select the SBOM member's exact version.
        nupkg.write_bytes(package("example.controls", dependencies='<dependencies><dependency id="example.dependency" version="0.5.0"/></dependencies>'))
        document = root / "release.spdx.json"
        document.write_bytes(encoded(sbom()))
        dependencies = []
        if supplied:
            for name, content in (("dependency.nupkg", selected_bytes), ("extra.nupkg", package("extra"))):
                path = root / name
                path.write_bytes(content)
                dependencies.append(str(path))
        args = Namespace(nupkg=str(nupkg), source_availability="closed-source",
                         dependency=dependencies, dependency_directory=None, source_archive=None,
                         allow_network=online, nuget_feed=feed, release_sbom=str(document) if designated else None,
                         row_packets=None)
        with mock.patch.dict(tool, Tools=PrebuiltTools, Collector=MockCollector):
            receipt = tool["run_command"](args, root)
            assessment = json.loads(Path(receipt["assessment"]).read_bytes())
            states = {row["id"]: row for row in assessment["rows"]}
            lp03 = states["LP-03"]
            if (lp03["status"] != status or lp03["owner_action"] is not None or
                    any(states[row]["status"] is not None for row in ("PI-06", "PI-07", "PI-10"))):
                raise ValueError(label + ": incorrect row projection/scope.")
            if status == "verified" and ("caller" not in lp03["observation"].lower() or "publication" not in lp03["observation"]):
                raise ValueError("Positive omitted caller-designation trust boundary.")
            if "npm archive hashes bind caller-designated bytes and do not authenticate publisher archives." not in lp03["observation"]:
                raise ValueError("Rendered verified/gap/not-tested finding omitted npm authenticity qualification.")
            state = tool["load"](receipt["state"])
            paths = {key: root / relative for key, relative in state["paths"].items()}
            acquisition = tool["load"](paths["acquisition"])
            request = tool["load"](paths["resolve_request"])
            lp03_request = next(case for case in request["cases"] if case["row_id"] == "LP-03")
            if any(p["role"] == "source-observation" for case in request["cases"] for p in case["inputs"]):
                raise ValueError("A local import invented anonymous source capture.")
            if designated:
                sbom_attempt = next(a for a in acquisition["attempts"] if a["subject"] == "documentation")
                if sbom_attempt["method"] != "local-file" or sbom_attempt["request_sent"]:
                    raise ValueError("SBOM import fabricated transport provenance.")
            expected_calls = 1 if online and designated and not supplied else 0
            if len(calls) != expected_calls:
                raise ValueError(label + ": unexpected transport count.")
            if feed == "dotnet-public" and any("api.nuget.org" in url for url in calls):
                raise ValueError("Explicit mirror acquisition silently fell back to nuget.org.")
            if label == "offline-exact-plus-extra":
                if len([p for p in lp03_request["inputs"] if p["role"].startswith("dependency-")]) != 1:
                    raise ValueError("Extra supplied archive leaked into authoritative inventory.")
                check = Namespace(command="check", state=receipt["state"], assessment=receipt["assessment"])
                tool["continue_command"](check, root)
                legacy = dict(state)
                legacy["producer"] = "eleven-row-handoff/1.3.0"
                old = root / "legacy-state.json"
                old.write_bytes(encoded(legacy))
                try:
                    tool["open_state"](root, old)
                except ValueError:
                    pass
                else:
                    raise ValueError("Older handoff state was accepted.")
                raw = next(p for p in lp03_request["inputs"] if p["role"] == "sbom")
                retained = paths["resolve_request"].parent / raw["path"]
                retained.write_bytes(retained.read_bytes() + b" ")
                try:
                    tool["open_state"](root, Path(receipt["state"]))
                except ValueError:
                    pass
                else:
                    raise ValueError("Changed raw SBOM was accepted by saved state.")
            print(f"Installed LP-03 {label}: {status}; {len(calls)} mocked requests; real native resolver; PI rows untouched.")


def run(command, cwd, env=None, code=0):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=240, check=False)
    if result.returncode != code:
        raise ValueError(f"Unexpected exit {result.returncode} for {command[0:2]}:\n" +
                         result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace"))
    return result.stdout


def lp04_installed_checks(plugin, work):
    from oracles.lp04_dlite_expectations import inventory, result
    helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
    loaded = runpy.run_path(str(plugin / "skills/blazor-package-readiness-resolver/scripts/autofill-eleven.py"),
                            run_name="lp04_installed_test")
    cases, expected = [], {}
    fixtures = (
        ("empty", [], [], "no-supported-layout-assets", False),
        ("assets", [("staticwebassets/a.js", b"x"), ("contentFiles/any/net8.0/wwwroot/a.css", b"y"),
                    ("WWWROOT/a.JS.MAP", b"{}"), ("wwwroot/lib/empty.min.cjs", b"")],
         [], "origin-review-missing", False),
        ("outside", [], ["tools/x.js"], "surface-unsupported", False),
        ("compressed", [], ["staticwebassets/x.css.br"], "surface-unsupported", False),
        ("legacy", [], [], "legacy-protocol", True),
    )
    for label, files, unsupported, branch, legacy in fixtures:
        path = work / (label + ".nupkg")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("Sample.nuspec", "<package><metadata><id>Sample</id><version>1.0.0</version></metadata></package>")
            for name, raw in files:
                archive.writestr(name, raw)
            for name in unsupported:
                archive.writestr(name, b"x")
        pins = [{"role": "package", "path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]
        if legacy:
            packet = work / "v1.json"
            packet.write_bytes(b'{"protocol":"notice-coverage-v1"}')
            pins.append({"role": "notice-coverage", "path": packet.name,
                         "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()})
        cases.append({"case_id": label, "row_id": "LP-04", "inputs": pins})
        expected[label] = result(branch, pins, None if legacy else inventory(files, unsupported))
    request = work / "lp04-request.json"
    request.write_text(json.dumps({"schema_version": 1, "cases": cases}), encoding="utf-8")
    output = json.loads(run([sys.executable, "-I", str(helper), "resolve", str(request)], work))
    for case in output["cases"]:
        actual = case["result"]
        loaded["checked_result"](actual, expected[case["case_id"]]["inputs"])
        if actual != expected.pop(case["case_id"]):
            raise ValueError("Installed LP-04 output differs from independent byte-construction facts.")
    if expected:
        raise ValueError("Installed LP-04 omitted a case.")
    print("Installed LP-04: five complete independent expectations passed, including full inventory, "
          "empty not-tested wording, unsupported roots/compressed variants and v1 refusal; no network/models.")


def inspection_checks(helper, assessment):
    def archive(entries):
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_STORED) as zipped:
            for name, data in entries.items():
                zipped.writestr(name, data)
        return memory.getvalue()

    with zipfile.ZipFile(assessment / "sample.nupkg") as package:
        target = package.read("build/assessment.targets")
    prefix = "controls-1234567890123456789012345678901234567890/"
    source = archive({
        prefix + "build/assessment.targets": target,
        prefix + "assets/Check Box.svg": b"<svg/>",
        prefix + "src/Library.csproj": (
            b'<Project Sdk="Microsoft.NET.Sdk.Razor"><PropertyGroup>'
            b'<PackageId>Example.Controls</PackageId></PropertyGroup></Project>'),
        prefix + "Directory.Build.props": b"<Project/>",
        prefix + "NOTICE.txt": b"Retained source notice, not an obligation review.",
    })
    dependency = archive({
        "Dependency.nuspec": (
            b"<package><metadata><id>Example.Dependency</id><version>1.0.0</version>"
            b'<license type="expression">MIT</license></metadata></package>'),
        "LICENSE.txt": b"Named retained text; no whole-version applicability review.",
    })
    (assessment / "source.zip").write_bytes(source)
    (assessment / "dependency.nupkg").write_bytes(dependency)
    pins = [{"role": role, "path": name,
             "sha256": hashlib.sha256((assessment / name).read_bytes()).hexdigest()}
            for role, name in (("package", "sample.nupkg"),
                               ("source-archive", "source.zip"),
                               ("dependency-000", "dependency.nupkg"))]
    request = {"schema_version": 1, "inputs": pins}
    path = assessment / "inspection-request.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    output = run([sys.executable, str(helper), "inspect", str(path)], assessment)
    (assessment / "observations.json").write_bytes(output)
    facts = json.loads(output)
    project = facts["source"]["projects"][0]
    if (facts["inputs"] != pins or facts["producer"] != "package-evidence-observations/1.1.0" or
            project["sdk_declaration"] != "Microsoft.NET.Sdk.Razor" or
            len(project["ancestor_build_files"]) != 1 or
            facts["exact_source_matches"][0]["package_entry"] != "build/assessment.targets" or
            facts["supplied_dependencies"][0]["license_declarations"] != [{"type": "expression", "value": "MIT"}] or
            facts["supplied_dependencies"][0]["license_or_notice_candidates"][0]["utf8_text"] !=
            "Named retained text; no whole-version applicability review." or
            len(facts["source"]["license_or_notice_candidates"]) != 1 or
            "assembly_candidates" not in facts or
            "decision" in facts or "status" in facts or facts["diagnostics"]):
        raise ValueError("Installed inspector lost broader facts or invented an assessment result.")
    request["inputs"][0]["sha256"] = "0" * 64
    (assessment / "inspection-changed.json").write_text(json.dumps(request), encoding="utf-8")
    run([sys.executable, str(helper), "inspect", "inspection-changed.json"], assessment, code=2)
    return output


def lp02_public_capture_checks(plugin, work, root):
    script = plugin / "skills/blazor-package-readiness-resolver/scripts/autofill-eleven.py"
    helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
    tool = runpy.run_path(str(script), run_name="autofill_shipping_test")
    capture = root / "public-capture"
    capture.mkdir()
    package = capture / "package.nupkg"
    shutil.copyfile(root / "sample.nupkg", package)
    source = (root / "source.zip").read_bytes()
    metadata = tool["package_metadata"](package.read_bytes())
    calls = []

    def transport(url, destination, maximum, seconds):
        if url != tool["source_url"](metadata):
            raise ValueError("Unexpected transport request in mocked public-source integration.")
        calls.append(url)
        destination.write_bytes(source)
        return {"result": "succeeded", "detail_code": "http-200", "http_status": 200,
                "http_requests": [{"host": "codeload.github.com", "attempted_at_utc": "2026-10-30T12:00:00Z",
                                   "http_status": 200}]}

    collector = tool["Collector"](root, capture, 64, True, transport)
    collector.collect(package, metadata, None, [])
    _, request = tool["requests"](root, capture, package, metadata, collector, None)
    lp02 = next(case for case in request["cases"] if case["row_id"] == "LP-02")
    request_path = capture / "lp02-request.json"
    request_path.write_text(json.dumps({"schema_version": 1, "cases": [lp02]}), encoding="utf-8")
    result = json.loads(run([sys.executable, "-I", str(helper), "resolve", str(request_path)], work))["cases"][0]["result"]
    tool["checked_result"](result, lp02["inputs"])
    if (len(calls) != 1 or result["resolver_version"] != "1.2.0" or
            result["branch_id"] != "public-source-observed" or
            "source relevance is not independently established" not in result["finding"] or
            "binaries were built from that revision" not in result["finding"]):
        raise ValueError("Mocked single-fetch capture must reach the qualified LP-02 availability finding.")
    (capture / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Installed LP-02: one mocked anonymous download -> pinned observation -> real resolver qualified positive; "
          "Razor, inherited build files and interior filename spaces are not false blockers.")


def forged_provenance_shortcut_checks(plugin, work, root, receipt):
    """B5: caller-authored native-result-shaped JSON cannot bypass provenance admission."""
    tool = runpy.run_path(str(plugin / "skills/blazor-package-readiness-resolver/scripts/autofill-eleven.py"),
                          run_name="forged_provenance_test")
    state = json.loads(Path(receipt["state"]).read_bytes())
    paths = {key: root / relative for key, relative in state["paths"].items()}
    results = json.loads(paths["results"].read_bytes())
    request = json.loads(paths["resolve_request"].read_bytes())
    result = next(case["result"] for case in results["cases"] if case["result"]["row_id"] == "LP-04")
    pins = [result["inputs"][0]] + [
        {"role": role, "path": "unregistered-" + role + ".bin", "sha256": "a" * 64}
        for role in ("release-package", "provenance-bundle", "provenance-attestation", "source-archive")]
    fake_sha = hashlib.sha256(b"x").hexdigest()
    inventory_sha = hashlib.sha256(("bundled-web-assets/1\nwwwroot/fake.js\t1\t" + fake_sha + "\n").encode()).hexdigest()
    result.update(branch_id="provenance-notices-verified", decision="deterministic", applicability="applicable",
                  inputs=pins, evidence_references=[f"input:{p['role']}:{p['sha256']}" for p in pins],
                  finding="Claimed complete notice coverage from caller-authored result JSON.",
                  missing_fact=None, required_input=None, next_category=None,
                  bundled_web_assets={"profile": "bundled-web-assets/1", "assets": [
                      {"path": "wwwroot/fake.js", "length": 1, "sha256": fake_sha}],
                      "unsupported_candidates": [], "inventory_sha256": inventory_sha})
    next(case for case in request["cases"] if case["row_id"] == "LP-04")["inputs"] = pins
    forged_dir = work / "forged-capture"
    shutil.copytree(paths["resolve_request"].parent, forged_dir)
    forged_results, forged_request = root / "forged-results.json", forged_dir / "resolve-request.json"
    forged_results.write_text(json.dumps(results), encoding="utf-8")
    forged_request.write_text(json.dumps(request), encoding="utf-8")
    scratch = work / "forged-handoff"
    scratch.mkdir()
    tools = tool["Tools"](root, scratch)
    outputs = dict(paths, results=forged_results, resolve_request=forged_request)
    try:
        tool["bind"](tools, root, scratch, paths["package"], outputs)
    except ValueError as error:
        if "Missing path:" not in str(error) and "Checked input missing or changed before handoff" not in str(error):
            raise ValueError(f"Unexpected forged unregistered pin error: {error}") from error
    else:
        raise ValueError("Forged unregistered provenance pins were accepted by bind.")
    # Now also materialize the four forged pins on disk with matching SHA-256 and verify HMAC rejection.
    att_bytes = b'{"payload":"e30=","hmac_sha256":"' + (b"0" * 64) + b'"}'
    att_sha = hashlib.sha256(att_bytes).hexdigest()
    dummy_bytes = b"dummy"
    dummy_sha = hashlib.sha256(dummy_bytes).hexdigest()
    materialized_pins = [result["inputs"][0]]
    for role in ("release-package", "provenance-bundle", "provenance-attestation", "source-archive"):
        name = "unregistered-" + role + ".bin"
        content, digest = (att_bytes, att_sha) if role == "provenance-attestation" else (dummy_bytes, dummy_sha)
        (forged_dir / name).write_bytes(content)
        materialized_pins.append({"role": role, "path": name, "sha256": digest})
    result.update(inputs=materialized_pins,
                  evidence_references=[f"input:{p['role']}:{p['sha256']}" for p in materialized_pins])
    next(case for case in request["cases"] if case["row_id"] == "LP-04")["inputs"] = materialized_pins
    forged_results.write_text(json.dumps(results), encoding="utf-8")
    forged_request.write_text(json.dumps(request), encoding="utf-8")
    try:
        tool["bind"](tools, root, scratch, paths["package"], outputs)
    except ValueError as error:
        if "Unauthenticated provenance attestation" not in str(error):
            raise ValueError(f"Unexpected forged HMAC error: {error}") from error
    else:
        raise ValueError("Forged unauthenticated provenance attestation was accepted by bind.")
    print("B5 handoff: caller-authored result with unregistered or unauthenticated provenance pins rejected.")


def autofill_checks(plugin, work, setup):
    root = work / "autofill-assessment"
    root.mkdir()
    shutil.copyfile(setup, root / "setup.py")
    run([sys.executable, "setup.py"], root)
    skill = plugin / "skills/blazor-package-readiness-resolver"
    script = skill / "scripts/autofill-eleven.py"
    helper = skill / "scripts/run-resolver.py"
    inspection_checks(helper, root)
    env = os.environ.copy()
    env.update(DOTNET_GENERATE_ASPNET_CERTIFICATE="false", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
    packets = {"schema_version": 1, "cases": [{"case_id": "supplied-lp05", "row_id": "LP-05", "inputs": [
        {"role": "package", "path": "sample.nupkg", "sha256": hashlib.sha256((root / "sample.nupkg").read_bytes()).hexdigest()}
    ]}]}
    (root / "row-packets.json").write_text(json.dumps(packets), encoding="utf-8")
    invocation = [sys.executable, "-I", str(script)]
    output = run([*invocation, "run", "--root", str(root), "--nupkg", str(root / "sample.nupkg"),
                  "--source-availability", "unresolved", "--offline", "--nuget-feed", "dotnet-public",
                  "--source-archive", str(root / "source.zip"), "--dependency", str(root / "dependency.nupkg"),
                  "--row-packets", str(root / "row-packets.json")], work, env)
    receipt = json.loads(output)
    assessment = json.loads(Path(receipt["assessment"]).read_bytes())
    states = {row["id"]: row for row in assessment["rows"]}
    assigned = ["LP-%02d" % number for number in range(1, 11)] + ["PI-01"]
    lp01 = states["LP-01"]
    if (lp01["status"] != "verified" or lp01["owner_action"] is not None or
            lp01["assessment_follow_up"] is not None or
            "LP-01 [approved-non-copyleft]" not in lp01["observation"] or
            "Declarations and named files do not establish owner authority" in lp01["observation"]):
        raise ValueError("An approved LP-01 package declaration must be verified without owner follow-up.")
    if (len(states) != 60 or len(assessment.get("selected_ids", [])) != 60 or
            any(states[row]["status"] is None for row in assigned) or
            any(row["status"] is not None for key, row in states.items() if key not in assigned) or
            assessment["completion_state"] != "incomplete" or
            "Microsoft.NET.Sdk.Razor" not in states["LP-02"]["observation"] or
            "MIT" not in states["LP-03"]["observation"] or
            states["LP-04"]["status"] != "not tested" or
            "No JS/CSS assets detected in the supported package layouts; other representations were not assessed."
                not in states["LP-04"]["observation"] or
            not states["LP-04"]["assessment_follow_up"] or
            "inspected signing fields" not in states["PI-01"]["observation"] or
            "build/assessment.targets" not in states["LP-10"]["observation"]):
        raise ValueError("Eleven-row autofill lost supported breadth or assigned outside its scope.")
    if states["LP-02"]["status"] != "not tested" or "LP-02 [observation-missing]" not in states["LP-02"]["observation"]:
        raise ValueError("A local source import must not invent anonymous public retrieval.")
    check = [*invocation, "check", "--root", str(root), "--state", receipt["state"]]
    run([*check, "--assessment", receipt["assessment"]], work, env)
    continued = json.loads(json.dumps(assessment))
    pi02 = next(row for row in continued["rows"] if row["id"] == "PI-02")
    pi02.update(status="not tested", observation="The package-signature check was not performed.",
                assessment_follow_up="Inspect the exact package signature.")
    (root / "continued-canonical.json").write_text(json.dumps(continued), encoding="utf-8")
    run([*check, "--assessment", str(root / "continued-canonical.json")], work, env)
    state = json.loads(Path(receipt["state"]).read_bytes())
    paths = {key: root / relative for key, relative in state["paths"].items()}
    forged_provenance_shortcut_checks(plugin, work, root, receipt)
    if json.loads(paths["acquisition"].read_bytes())["nuget_feed"] != "dotnet-public":
        raise ValueError("The installed handoff lost the explicit Azure feed selection.")
    resolve = json.loads(paths["resolve_request"].read_bytes())
    supplied_case = next(case for case in resolve["cases"] if case["row_id"] == "LP-05")
    if supplied_case["inputs"][0]["path"] != "packet-lp-05-000.bin":
        raise ValueError("The installed handoff did not use the explicitly supplied checked row packet.")
    mutated = json.loads(json.dumps(assessment))
    next(row for row in mutated["rows"] if row["id"] == "LP-01")["observation"] = "Invented model replacement."
    (root / "mutated-assessment.json").write_text(json.dumps(mutated), encoding="utf-8")
    run([*check, "--assessment", str(root / "mutated-assessment.json")], work, env, code=2)
    stale = json.loads(json.dumps(assessment))
    stale["identity"]["nupkg_sha256"] = "0" * 64
    (root / "stale-identity.json").write_text(json.dumps(stale), encoding="utf-8")
    run([*check, "--assessment", str(root / "stale-identity.json")], work, env, code=2)
    premature = json.loads(json.dumps(assessment))
    premature["completion_state"] = "complete"
    (root / "premature-complete.json").write_text(json.dumps(premature), encoding="utf-8")
    run([*check, "--assessment", str(root / "premature-complete.json")], work, env, code=2)
    bad_producer = json.loads(json.dumps(assessment))
    bad_producer["producer"] = "forged-producer/1.0.0"
    (root / "bad-producer.json").write_text(json.dumps(bad_producer), encoding="utf-8")
    run([*check, "--assessment", str(root / "bad-producer.json")], work, env, code=2)
    bool_schema = json.loads(json.dumps(assessment))
    bool_schema["schema_version"] = True
    (root / "bool-schema.json").write_text(json.dumps(bool_schema), encoding="utf-8")
    run([*check, "--assessment", str(root / "bool-schema.json")], work, env, code=2)
    float_schema = json.loads(json.dumps(assessment))
    float_schema["schema_version"] = 1.0
    (root / "float-schema.json").write_text(json.dumps(float_schema), encoding="utf-8")
    run([*check, "--assessment", str(root / "float-schema.json")], work, env, code=2)
    extra_key = json.loads(json.dumps(assessment))
    extra_key["unexpected"] = True
    (root / "extra-key.json").write_text(json.dumps(extra_key), encoding="utf-8")
    run([*check, "--assessment", str(root / "extra-key.json")], work, env, code=2)
    run([*invocation, "run", "--root", str(root), "--nupkg", str(root / "sample.nupkg"),
         "--source-availability", "closed-source", "--source-archive", str(root / "source.zip"),
         "--offline"], work, env, code=2)
    lp02_public_capture_checks(plugin, work, root)
    lone = work / "autofill-single/skills/blazor-package-readiness-resolver"
    shutil.copytree(skill, lone, ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
    (lone / "scripts/run-resolver.py").unlink()
    run([sys.executable, "-I", str(lone / "scripts/autofill-eleven.py"), "run", "--root", str(root),
         "--nupkg", str(root / "sample.nupkg"), "--allow-network"], work, env, code=2)
    print("Installed eleven-row autofill: offline producer chain, eleven assigned/49 untouched, partial breadth, "
          "unchanged-row check, stale identity and model overwrite rejection, closed-source boundary check, "
          "and missing-launcher no-acquisition failure passed.")


def certificate_launcher_checks(plugin, work):
    shim_dir = work / "dotnet shim"
    shim_dir.mkdir()
    bash_shim = shim_dir / "dotnet"
    bash_shim.write_text(
        '#!/usr/bin/env bash\n'
        'if [[ ! -e shim-record ]]; then\n'
        '  printf "args=%s\\ncert=%s\\nskip=%s\\nhome=%s\\n" "$*" '
        '"${DOTNET_GENERATE_ASPNET_CERTIFICATE-<unset>}" '
        '"${DOTNET_SKIP_FIRST_TIME_EXPERIENCE-<unset>}" '
        '"${DOTNET_CLI_HOME-<unset>}" > shim-record\n'
        'fi\n'
        'cat shim-record\n'
        'exit 47\n', encoding="utf-8", newline="\n")
    if os.name != "nt":
        bash_shim.chmod(0o755)
    cmd_shim = shim_dir / "dotnet.cmd"
    cmd_shim.write_text(
        '@echo off\r\n'
        'if not exist shim-record (\r\n'
        '  > shim-record echo args=%*\r\n'
        '  >> shim-record echo cert=%DOTNET_GENERATE_ASPNET_CERTIFICATE%\r\n'
        '  >> shim-record echo skip=%DOTNET_SKIP_FIRST_TIME_EXPERIENCE%\r\n'
        '  >> shim-record echo home=%DOTNET_CLI_HOME%\r\n'
        ')\r\n'
        'type shim-record\r\n'
        'exit /b 47\r\n', encoding="utf-8", newline="")

    clean_env = os.environ.copy()
    for key in ("DOTNET_GENERATE_ASPNET_CERTIFICATE", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE",
                "DOTNET_CLI_HOME", "READINESS_TEMP"):
        clean_env.pop(key, None)

    resolver_probe = work / "cert-shim-resolver"
    resolver_probe.mkdir()
    resolver_env = clean_env.copy()
    resolver_env["PATH"] = str(shim_dir) + os.pathsep + resolver_env["PATH"]
    for key in ("TMPDIR", "TEMP", "TMP"):
        resolver_env[key] = str(work)
    resolution = run([sys.executable, "-c", "import shutil; print(shutil.which('dotnet'))"],
                     resolver_probe, resolver_env).decode().strip()
    expected_shim = cmd_shim if os.name == "nt" else bash_shim
    if not resolution or not Path(resolution).is_file() or not os.path.samefile(resolution, expected_shim):
        raise ValueError(f"Resolver resolved dotnet to {resolution!r}, not {expected_shim}.")
    helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
    result = subprocess.run([sys.executable, str(helper), "coverage"], cwd=resolver_probe,
                            env=resolver_env, capture_output=True, timeout=30, check=False)
    if result.returncode != 3 or b"args=--list-sdks" not in result.stderr:
        raise ValueError(f"Resolver did not reach the intercepted SDK enumeration: "
                         f"exit={result.returncode}, stderr={result.stderr!r}")
    values = dict(line.split("=", 1) for line in result.stderr.decode(errors="replace").splitlines()
                  if line.startswith(("args=", "cert=", "skip=", "home=")))
    home = Path(values.get("home", ""))
    if (values.get("args") != "--list-sdks" or values.get("cert") != "false" or
            values.get("skip") != "1" or home.name != "home" or
            not home.parent.name.startswith("blazor-resolver-") or
            home.parent.parent != work):
        raise ValueError(f"Resolver first dotnet call lacked isolated launcher-owned settings: {values}")
    real_probe = work / "cert-real-resolver"
    real_probe.mkdir()
    real_result = subprocess.run([sys.executable, str(helper), "coverage"], cwd=real_probe,
                                 env=clean_env, capture_output=True, timeout=240, check=False)
    if real_result.returncode != 0:
        raise ValueError(f"Resolver real first coverage failed: exit={real_result.returncode}, "
                         f"stderr={real_result.stderr.decode(errors='replace')}")
    output = (real_result.stdout + real_result.stderr).decode(errors="replace")
    if re.search(r"ASP\.NET Core HTTPS development certificate|dotnet dev-certs https --trust|"
                 r"development certificate.{0,60}(?:install|trust)", output, re.IGNORECASE):
        raise ValueError(f"Resolver first coverage emitted a development-certificate banner: {output}")
    print("Resolver launcher: first intercepted dotnet --list-sdks received launcher-owned "
          "certificate/first-time settings and isolated CLI home; real first coverage emitted "
          "no development-certificate installation/trust banner.")


def sdk_checks(helper, work):
    pin_sdk = runpy.run_path(str(helper))["pin_sdk"]
    scratch = work / "sdk-selection"
    scratch.mkdir()
    inventory = ("11.0.100-preview.3 [installed sdk]\n10.0.99 [installed sdk]\n"
                 "10.0.403 [installed sdk]\n10.0.404-preview.1 [installed sdk]\n")
    response = subprocess.CompletedProcess([], 0, inventory.encode())
    with mock.patch("subprocess.run", return_value=response):
        if not pin_sdk("dotnet", scratch, os.environ.copy()):
            raise ValueError("Installed stable net10 SDK was not admitted.")
    expected = {"sdk": {"version": "10.0.403", "rollForward": "disable", "allowPrerelease": False}}
    if json.loads((scratch / "global.json").read_bytes()) != expected:
        raise ValueError("The exact newest stable net10 SDK was not pinned.")
    (scratch / "global.json").unlink()
    for code, output in ((0, b"11.0.100-preview.3 [installed sdk]\n"),
                         (0, b"10.0.403-preview.1 [installed sdk]\n"), (1, b"sdk query failed")):
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], code, output)), \
                mock.patch("sys.stderr"):
            if pin_sdk("dotnet", scratch, os.environ.copy()) or (scratch / "global.json").exists():
                raise ValueError("Unavailable SDK selection did not fail closed.")
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        raise ValueError("SDK selection check requires installed dotnet.")
    before = run([dotnet, "--version"], work)
    if not pin_sdk(dotnet, scratch, os.environ.copy()):
        raise ValueError("No stable .NET 10 SDK is installed for offline shipping checks.")
    selected = run([dotnet, "--version"], scratch).decode().strip()
    if selected != json.loads((scratch / "global.json").read_bytes())["sdk"]["version"]:
        raise ValueError("Dotnet did not select the pinned SDK.")
    if before != run([dotnet, "--version"], work):
        raise ValueError("Tool SDK selection changed the caller's active SDK.")
    print("Offline SDK selection: exact newest stable net10 pin, three fail-closed controls, "
          "real SDK selection and unchanged caller SDK passed.")


def isolated_checks(plugin, work, setup):
    # Match ordinary skill-only staging, including a parent literally named "skills".
    resolver = work / "resolver-single/.agents/skills/blazor-package-readiness-resolver"
    shutil.copytree(plugin / "skills/blazor-package-readiness-resolver", resolver,
                    ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
    if (resolver.parents[1] / "plugin.json").exists():
        raise ValueError("Single-skill test accidentally staged a full plugin.")
    assessment = work / "single-assessment"
    assessment.mkdir()
    shutil.copyfile(setup, assessment / "setup.py")
    run([sys.executable, "setup.py"], assessment)
    result = run([sys.executable, str(resolver / "scripts/run-resolver.py"), "package", "sample.nupkg"], assessment)
    (assessment / "result.json").write_bytes(result)
    run([sys.executable, "setup.py", "result.json", "all"], assessment)
    autofill_script = resolver / "scripts/autofill-eleven.py"
    receipt = json.loads(run([sys.executable, "-I", str(autofill_script), "run",
                              "--root", str(assessment), "--nupkg", str(assessment / "sample.nupkg"),
                              "--offline"], work))
    run([sys.executable, "-I", str(autofill_script), "check",
         "--root", str(assessment), "--state", receipt["state"], "--assessment", receipt["assessment"]], work)
    data = resolver / "scripts/resolver/data"
    for name in ("rubric.json", "requirement-basis.json"):
        path = data / name
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n")
            run([sys.executable, str(resolver / "scripts/run-resolver.py"), "coverage"], assessment, code=2)
            run([sys.executable, "-I", str(autofill_script), "check",
                 "--root", str(assessment), "--state", receipt["state"],
                 "--assessment", receipt["assessment"]], work, code=2)
        finally:
            path.write_bytes(original)
    print("Single-skill staging: standalone resolver package dispatch, standalone eleven-row autofill "
          "run/check, and two normative catalog drift rejections passed without plugin.json.")


def main():
    if sys.argv[1:] not in ([], ["--isolated"], ["--launcher"], ["--cert"], ["--autofill"], ["--lp03"], ["--lp04"]):
        raise ValueError("Supported options: --isolated, --launcher, --cert, --autofill, --lp03, --lp04")
    with tempfile.TemporaryDirectory(prefix="resolver-installed-") as work:
        work = Path(work)
        plugin = work / "plugin"
        shutil.copytree(REPO / "plugins/dotnet-blazor", plugin,
                        ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
        if sys.argv[1:] == ["--lp03"]:
            lp03_installed_checks(plugin, work)
            return
        if sys.argv[1:] == ["--lp04"]:
            lp04_installed_checks(plugin, work)
            return
        if sys.argv[1:] == ["--cert"]:
            certificate_launcher_checks(plugin, work)
            return
        helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
        sdk_checks(helper, work)
        assessment = work / "assessment"
        assessment.mkdir()
        setup = REPO / "tests/dotnet-blazor/blazor-package-readiness-resolver/fixtures/setup.py"
        if sys.argv[1:] == ["--autofill"]:
            autofill_checks(plugin, work, setup)
            return
        if sys.argv[1:] == ["--isolated"]:
            isolated_checks(plugin, work, setup)
            return
        shutil.copyfile(setup, assessment / "setup.py")
        run([sys.executable, "setup.py"], assessment)
        (assessment / "global.json").write_text('{"sdk":{"version":"0.0.0"}}')
        before = {p.relative_to(plugin): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in plugin.rglob("*") if p.is_file()}
        invocation = [sys.executable, str(helper)]
        coverage = run([*invocation, "coverage"], assessment)
        if hashlib.sha256(coverage).hexdigest() != "0adb96315f7c2d513eff0d3d10640704a2aceeeb10eefee568406a0cd91e100b":
            raise ValueError("Installed coverage changed.")
        if sys.argv[1:] == ["--launcher"]:
            print("Exact installed coverage invocation passed with hostile caller global.json, "
                  "fresh isolated packages, empty feeds and no assessed-code execution.")
            return
        result = run([*invocation, "package", "sample.nupkg"], assessment)
        (assessment / "result.json").write_bytes(result)
        run([sys.executable, "setup.py", "result.json", "all"], assessment)
        gold = json.loads(result)
        def reject(change):
            value = json.loads(json.dumps(gold))
            change(value)
            (assessment / "mutated.json").write_text(json.dumps(value))
            run([sys.executable, "setup.py", "mutated.json", "all"], assessment, code=1)
        reject(lambda value: value["cases"].pop())
        reject(lambda value: value["cases"][0]["result"].pop("missing_fact"))
        reject(lambda value: value["cases"][0]["result"]["inputs"][0].update(sha256="0" * 64))
        reject(lambda value: value["cases"][3]["result"].update(branch_id="notice-coverage-satisfied"))
        reject(lambda value: value["cases"][0]["result"].update(decision="verified"))
        reject(lambda value: value["cases"].append(value["cases"][0]))
        result = run([*invocation, "resolve", "request.json"], assessment)
        (assessment / "result.json").write_bytes(result)
        run([sys.executable, "setup.py", "result.json"], assessment)
        run([*invocation, "resolve", "changed.json"], assessment, code=2)
        run([*invocation, "resolve", "malformed.json"], assessment, code=2)
        run([*invocation, "acquire-lp02", "sample.nupkg"], assessment, code=2)
        inspection_checks(helper, assessment)
        certificate_launcher_checks(plugin, work)
        isolated_checks(plugin, work, setup)
        autofill_checks(plugin, work, setup)
        after = {p.relative_to(plugin): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in plugin.rglob("*") if p.is_file()}
        if before != after:
            raise ValueError("Installed plugin was modified by a launcher.")
        print("Installed offline launcher: coverage, package, checked request, two strict failures, "
              "acquisition rejection, hostile cwd isolation, six grader mutations and read-only plugin passed.")


if __name__ == "__main__":
    main()
