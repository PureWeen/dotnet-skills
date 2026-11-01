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
    """Run the installed helper, replacing only build launchers with prebuilt trusted DLLs."""
    from oracles.lp03_sbom_expectations import sbom, package, encoded
    script = plugin / "skills/blazor-component-readiness/scripts/autofill-eleven.py"
    loaded = runpy.run_path(str(script), run_name="lp03_installed_test")
    tool = loaded["run_command"].__globals__
    resolver = REPO / "eng/blazor-package-resolver/bin/Debug/net10.0/BlazorPackageResolver.dll"
    validator = REPO / "plugins/dotnet-blazor/skills/blazor-component-readiness/scripts/validator/bin/Debug/net11.0/BlazorComponentReadiness.Validator.dll"
    if not resolver.is_file() or not validator.is_file():
        raise ValueError("Build the trusted resolver and validator with --no-restore before --lp03.")
    original_tools, original_collector = tool["Tools"], tool["Collector"]
    calls = []
    selected_bytes = package("example.dependency")

    def transport(url, destination, maximum, seconds):
        expected = "https://api.nuget.org/v3-flatcontainer/example.dependency/1.0.0/example.dependency.1.0.0.nupkg"
        if url != expected or maximum != tool["PACKAGE_LIMIT"] or not 0 < seconds <= 60:
            raise ValueError("A non-inventory/minimum/mirror request escaped exact acquisition.")
        calls.append(url)
        destination.write_bytes(selected_bytes)
        return {"result": "succeeded", "detail_code": "http-200", "http_status": 200,
                "http_requests": [{"host": "api.nuget.org", "attempted_at_utc": "2026-10-30T12:00:00Z", "http_status": 200}]}

    class PrebuiltTools(original_tools):
        def command(self, args, output=None):
            if len(args) > 2 and args[0] == sys.executable and str(self.resolver) in args:
                args = ["dotnet", str(resolver), *args[-2:]]
            elif any(str(a).endswith(("run-validator.ps1", "run-validator.sh")) for a in args):
                destination = self.work / "validator-build/bin/Release/net11.0"
                destination.mkdir(parents=True)
                for path in validator.parent.iterdir():
                    if path.is_file():
                        shutil.copyfile(path, destination / path.name)
                args = ["dotnet", str(destination / validator.name), "help"]
            return super().command(args, output)

    class MockCollector(original_collector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs, transport=transport)

    env = os.environ.copy()
    env["READINESS_SKILL_ROOT"] = str(plugin / "skills/blazor-component-readiness")
    def v(*args):
        return run(["dotnet", str(validator), *map(str, args)], work, env)

    for label, status, expression, online, designated, supplied, feed in (
        ("offline-exact-plus-extra", "verified", "MIT", False, True, True, "nuget.org"),
        ("mocked-exact-only", "verified", "MIT", True, True, False, "nuget.org"),
        ("offline-missing", "not tested", "MIT", False, True, False, "nuget.org"),
        ("no-designation", "not tested", "MIT", False, False, True, "nuget.org"),
        ("mocked-copyleft", "gap", "GPL-3.0-only", True, True, False, "nuget.org"),
        ("mocked-noassertion", "not tested", "NOASSERTION", True, True, False, "nuget.org"),
        ("mocked-file-only", "not tested", "FILE", True, True, False, "nuget.org"),
        ("explicit-mirror-no-hidden-fallback", "not tested", "MIT", True, True, False, "dotnet-public"),
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
        candidates0, candidates = root / "candidates0.json", root / "candidates.json"
        draft, confirmed = root / "input.draft.json", root / "input.confirmed.json"
        v("inputs", "candidates", "init", "--acquisition", "published", "--package-locator", "sample.nupkg",
          "--package-method", "local-file", "--source-availability", "closed-source", "--output", candidates0)
        v("inputs", "candidates", "add-retrieval", "--input", candidates0, "--subject", "package",
          "--locator", "sample.nupkg", "--method", "local-file", "--result", "succeeded", "--output", candidates)
        v("inputs", "discover", "--root", root, "--nupkg", nupkg, "--candidates", candidates, "--output", draft)
        v("inputs", "confirm", "--root", root, "--draft", draft, "--output", confirmed)
        dependencies = []
        if supplied:
            for name, content in (("dependency.nupkg", selected_bytes), ("extra.nupkg", package("extra"))):
                path = root / name
                path.write_bytes(content)
                dependencies.append(str(path))
        args = Namespace(confirmed=str(confirmed), candidates=str(candidates), nupkg=str(nupkg),
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
            expected_calls = 1 if online and designated and feed == "nuget.org" and not supplied else 0
            if len(calls) != expected_calls:
                raise ValueError(label + ": unexpected transport count.")
            if label == "offline-exact-plus-extra":
                if len([p for p in lp03_request["inputs"] if p["role"].startswith("dependency-")]) != 1:
                    raise ValueError("Extra supplied archive leaked into authoritative inventory.")
                check = Namespace(command="check", confirmed=receipt["manifest"], state=receipt["state"],
                                  assessment=receipt["assessment"])
                tool["continue_command"](check, root)
                rebound = tool["continue_command"](Namespace(command="rebind", confirmed=receipt["manifest"],
                    state=receipt["state"], unrelated_evidence=[]), root)
                if tool["load"](rebound["state"])["captured_at"] != state["captured_at"]:
                    raise ValueError("Rebind fabricated a capture timestamp.")
                check.state, check.assessment = rebound["state"], rebound["assessment"]
                tool["continue_command"](check, root)
                legacy = dict(state)
                legacy["producer"] = "eleven-row-handoff/1.2.0"
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
            print(f"Installed LP-03 {label}: {status}; {len(calls)} mocked requests; real native/validator; PI rows untouched.")


def run(command, cwd, env=None, code=0):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=240, check=False)
    if result.returncode != code:
        raise ValueError(f"Unexpected exit {result.returncode} for {command[0:2]}:\n" +
                         result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace"))
    return result.stdout


def report_command(consumer):
    shell = shutil.which("pwsh") if os.name == "nt" else shutil.which("bash")
    if shell is None:
        raise ValueError("No supported shell for the report validator.")
    launcher = consumer / "scripts/validator" / ("run-validator.ps1" if os.name == "nt" else "run-validator.sh")
    return ([shell, "-NoProfile", "-File", str(launcher)] if os.name == "nt"
            else [shell, str(launcher)])


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
    if (facts["inputs"] != pins or facts["producer"] != "package-evidence-observations/1.0.0" or
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
    script = plugin / "skills/blazor-component-readiness/scripts/autofill-eleven.py"
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
    if (len(calls) != 1 or result["resolver_version"] != "1.1.0" or
            result["branch_id"] != "public-source-observed" or
            "source relevance is not independently established" not in result["finding"] or
            "binaries were built from that revision" not in result["finding"]):
        raise ValueError("Mocked single-fetch capture must reach the qualified LP-02 availability finding.")
    (capture / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Installed LP-02: one mocked anonymous download -> pinned observation -> real resolver qualified positive; "
          "Razor, inherited build files and interior filename spaces are not false blockers.")


def autofill_checks(plugin, work, setup):
    root = work / "autofill-assessment"
    root.mkdir()
    shutil.copyfile(setup, root / "setup.py")
    run([sys.executable, "setup.py"], root)
    consumer = plugin / "skills/blazor-component-readiness"
    script = consumer / "scripts/autofill-eleven.py"
    helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
    inspection_checks(helper, root)
    command = report_command(consumer)
    env = os.environ.copy()
    env.update(READINESS_TEMP=str(work / "autofill-bootstrap"),
               DOTNET_GENERATE_ASPNET_CERTIFICATE="false", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
    run([*command, "inputs", "candidates", "init", "--acquisition", "published",
         "--package-locator", "sample.nupkg", "--package-method", "local-file",
         "--source-availability", "unresolved", "--output", str(root / "candidates0.json")], work, env)
    run([*command, "inputs", "candidates", "add-retrieval", "--input", str(root / "candidates0.json"),
         "--subject", "package", "--locator", "sample.nupkg", "--method", "local-file",
         "--result", "succeeded", "--output", str(root / "candidates.json")], work, env)
    run([*command, "inputs", "discover", "--root", str(root), "--nupkg", str(root / "sample.nupkg"),
         "--candidates", str(root / "candidates.json"), "--output", str(root / "input.draft.json")], work, env)
    run([*command, "inputs", "confirm", "--root", str(root), "--draft", str(root / "input.draft.json"),
         "--output", str(root / "input.confirmed.json")], work, env)
    packets = {"schema_version": 1, "cases": [{"case_id": "supplied-lp05", "row_id": "LP-05", "inputs": [
        {"role": "package", "path": "sample.nupkg", "sha256": hashlib.sha256((root / "sample.nupkg").read_bytes()).hexdigest()}
    ]}]}
    (root / "row-packets.json").write_text(json.dumps(packets), encoding="utf-8")
    invocation = [sys.executable, "-I", str(script)]
    output = run([*invocation, "run", "--root", str(root), "--nupkg", str(root / "sample.nupkg"),
                  "--candidates", str(root / "candidates.json"), "--confirmed", str(root / "input.confirmed.json"),
                  "--offline", "--nuget-feed", "dotnet-public", "--source-archive", str(root / "source.zip"),
                  "--dependency", str(root / "dependency.nupkg"), "--row-packets", str(root / "row-packets.json")], work, env)
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
    if (len(states) != 60 or any(states[row]["status"] is None for row in assigned) or
            any(row["status"] is not None for key, row in states.items() if key not in assigned) or
            assessment["completion_state"] != "incomplete" or
            "Microsoft.NET.Sdk.Razor" not in states["LP-02"]["observation"] or
            "MIT" not in states["LP-03"]["observation"] or
            "1 files across 1 of 1 supplied dependency versions" not in states["LP-04"]["observation"] or
            "1 source files" not in states["LP-04"]["observation"] or
            "inspected signing fields" not in states["PI-01"]["observation"] or
            "build/assessment.targets" not in states["LP-10"]["observation"]):
        raise ValueError("Eleven-row autofill lost supported breadth or assigned outside its scope.")
    if states["LP-02"]["status"] != "not tested" or "LP-02 [observation-missing]" not in states["LP-02"]["observation"]:
        raise ValueError("A local source import must not invent anonymous public retrieval.")
    check = [*invocation, "check", "--root", str(root), "--confirmed", receipt["manifest"], "--state", receipt["state"]]
    run([*check, "--assessment", receipt["assessment"]], work, env)
    remaining = {"schema_version": 1, "rows": [{
        "id": "PI-02", "status": "not tested", "observation": "The package-signature check was not performed.",
        "evidence_ids": [], "owner_action": None, "assessment_follow_up": "Inspect the exact package signature.",
        "not_applicable_rationale": None
    }], "findings": [], "summary_groups": [], "completion_state": "incomplete"}
    (root / "remaining-decisions.json").write_text(json.dumps(remaining))
    run([*command, "assessment", "apply-decisions", "--assessment", receipt["assessment"],
         "--decisions", str(root / "remaining-decisions.json"), "--output", str(root / "continued-draft.json")], work, env)
    run([*command, "assessment", "canonicalize", "--assessment", str(root / "continued-draft.json"),
         "--output", str(root / "continued-canonical.json")], work, env)
    run([*check, "--assessment", str(root / "continued-canonical.json")], work, env)
    state = json.loads(Path(receipt["state"]).read_bytes())
    paths = {key: root / relative for key, relative in state["paths"].items()}
    if json.loads(paths["acquisition"].read_bytes())["nuget_feed"] != "dotnet-public":
        raise ValueError("The installed handoff lost the explicit Azure feed selection.")
    resolve = json.loads(paths["resolve_request"].read_bytes())
    supplied_case = next(case for case in resolve["cases"] if case["row_id"] == "LP-05")
    if supplied_case["inputs"][0]["path"] != "packet-lp-05-000.bin":
        raise ValueError("The installed handoff did not use the explicitly supplied checked row packet.")
    run([*command, "evidence", "ledger-build", "--kind", "repository", "--subject", str(paths["identity"]),
         "--draft", str(paths["evidence_draft"]), "--nupkg", str(root / "sample.nupkg"),
         "--output", str(root / "rebuilt-same-subject-ledger.json")], work, env)
    if json.loads((root / "rebuilt-same-subject-ledger.json").read_bytes()) != json.loads(paths["ledger"].read_bytes()):
        raise ValueError("Rebuilding unchanged records under the same subject changed the ledger.")
    mutated = json.loads(json.dumps(assessment))
    next(row for row in mutated["rows"] if row["id"] == "LP-01")["observation"] = "Invented model replacement."
    (root / "mutated-assessment.json").write_text(json.dumps(mutated))
    run([*check, "--assessment", str(root / "mutated-assessment.json")], work, env, code=2)
    (root / "unrelated.json").write_text('{"other_rows":"additional retained evidence"}\n')
    run([*command, "inputs", "candidates", "add-evidence", "--input", receipt["candidates"],
         "--path", "unrelated.json", "--kind", "document", "--output", str(root / "next-candidates.json")], work, env)
    run([*command, "inputs", "discover", "--root", str(root), "--nupkg", str(root / "sample.nupkg"),
         "--candidates", str(root / "next-candidates.json"), "--output", str(root / "next.draft.json")], work, env)
    run([*command, "inputs", "confirm", "--root", str(root), "--draft", str(root / "next.draft.json"),
         "--output", str(root / "next.confirmed.json")], work, env)
    rebound = json.loads(run([*invocation, "rebind", "--root", str(root), "--confirmed", str(root / "next.confirmed.json"),
                             "--state", receipt["state"], "--unrelated-evidence", "unrelated.json"], work, env))
    newer = json.loads(Path(rebound["assessment"]).read_bytes())
    next_states = {row["id"]: row for row in newer["rows"]}
    if any(states[row]["evidence_ids"] == next_states[row]["evidence_ids"] for row in assigned):
        raise ValueError("Rebind retained stale subject-bound evidence IDs.")
    if any(states[row]["observation"] != next_states[row]["observation"] for row in assigned):
        raise ValueError("Rebind changed the unchanged eleven-row facts.")
    if json.loads(Path(receipt["state"]).read_bytes())["captured_at"] != json.loads(Path(rebound["state"]).read_bytes())["captured_at"]:
        raise ValueError("Rebind invented new capture metadata.")
    run([*invocation, "check", "--root", str(root), "--confirmed", str(root / "next.confirmed.json"),
         "--state", rebound["state"], "--assessment", rebound["assessment"]], work, env)
    run([*check, "--assessment", rebound["assessment"]], work, env, code=2)
    lp02_public_capture_checks(plugin, work, root)
    lone = work / "autofill-single/blazor-component-readiness"
    shutil.copytree(consumer, lone, ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
    run([sys.executable, "-I", str(lone / "scripts/autofill-eleven.py"), "run", "--root", str(root),
         "--nupkg", str(root / "sample.nupkg"), "--candidates", receipt["candidates"],
         "--confirmed", receipt["manifest"], "--allow-network"], work, env, code=2)
    print("Installed eleven-row autofill: offline producer chain, eleven assigned/49 untouched, partial breadth, "
          "unchanged-row check, changed-manifest rebind with new IDs/preserved capture time, stale identity and "
          "model overwrite rejection, and single-skill no-acquisition failure passed.")


def certificate_launcher_checks(plugin, work):
    consumer = plugin / "skills/blazor-component-readiness"
    bash = shutil.which("bash")
    pwsh = shutil.which("pwsh")
    if not bash or (os.name == "nt" and not pwsh):
        raise ValueError("Bash (and PowerShell on Windows) are required for launcher checks.")
    launchers = [("bash", bash, consumer / "scripts/validator/run-validator.sh")]
    if pwsh:
        launchers.append(("pwsh", pwsh, consumer / "scripts/validator/run-validator.ps1"))

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
    for name, shell, launcher in launchers:
        probe = work / ("cert-shim-" + name)
        probe.mkdir()
        build = work / ("cert-build-" + name)
        env = clean_env.copy()
        env["PATH"] = str(shim_dir) + os.pathsep + env["PATH"]
        env["READINESS_TEMP"] = str(build)

        if name == "bash":
            resolution = run([shell, "-c", "command -v dotnet"], probe, env).decode().strip()
            if os.name == "nt":
                resolution = run([shell, "-c", 'cygpath -w -- "$(command -v dotnet)"'],
                                 probe, env).decode().strip()
            expected_shim = bash_shim
            command = [shell, str(launcher), "help"]
        else:
            resolution = run([shell, "-NoProfile", "-Command", "(Get-Command dotnet).Source"],
                             probe, env).decode().strip()
            expected_shim = cmd_shim if os.name == "nt" else bash_shim
            command = [shell, "-NoProfile", "-File", str(launcher), "help"]
        if not resolution or not Path(resolution).is_file() or not os.path.samefile(resolution, expected_shim):
            raise ValueError(f"{name} resolved dotnet to {resolution!r}, not {expected_shim}.")
        if build.exists():
            raise ValueError(f"{name} launcher build directory was not fresh.")
        result = subprocess.run(command, cwd=probe, env=env, capture_output=True,
                                timeout=30, check=False)
        record = probe / "shim-record"
        if result.returncode != 3 or not record.is_file():
            raise ValueError(f"{name} did not reach the intercepted SDK check: "
                             f"exit={result.returncode}, stderr={result.stderr!r}")
        values = dict(line.split("=", 1) for line in record.read_text(encoding="utf-8").splitlines())
        if values.get("args") != "--version" or values.get("cert") != "false" or values.get("skip") != "1":
            raise ValueError(f"{name} first dotnet call lacked launcher-owned bootstrap settings: {values}")
        home = values.get("home", "")
        if name == "bash" and os.name == "nt":
            home = run([shell, "-c", 'cygpath -w -- "$1"', "_", home],
                       probe, env).decode().strip()
        if not home or not Path(home).is_dir() or Path(home).resolve().parent != build.resolve():
            raise ValueError(f"{name} did not create an isolated launcher-owned CLI home: {home!r}")

        cleanup_probe = work / ("cert-cleanup-" + name)
        cleanup_probe.mkdir()
        cleanup_env = env.copy()
        cleanup_env.pop("READINESS_TEMP")
        for key in ("TMPDIR", "TEMP", "TMP"):
            cleanup_env[key] = str(work)
        result = subprocess.run(command, cwd=cleanup_probe, env=cleanup_env, capture_output=True,
                                timeout=30, check=False)
        cleanup_record = cleanup_probe / "shim-record"
        if result.returncode != 3 or not cleanup_record.is_file():
            raise ValueError(f"{name} did not reach the intercepted SDK failure in cleanup mode: "
                             f"exit={result.returncode}, stderr={result.stderr!r}")
        cleanup_values = dict(line.split("=", 1) for line in
                              cleanup_record.read_text(encoding="utf-8").splitlines())
        cleanup_home = cleanup_values.get("home", "")
        if name == "bash" and os.name == "nt":
            cleanup_home = run([shell, "-c", 'cygpath -w -- "$1"', "_", cleanup_home],
                               cleanup_probe, cleanup_env).decode().strip()
        cleanup_path = Path(cleanup_home)
        if (cleanup_values.get("args") != "--version" or
                not cleanup_home or
                not cleanup_path.parent.name.startswith("blazor-readiness-validator-") or
                cleanup_path.parent.parent.resolve() != work.resolve() or
                cleanup_path.exists() or cleanup_path.parent.exists()):
            raise ValueError(f"{name} did not clean up its isolated CLI home on SDK failure: "
                             f"{cleanup_values}")

        real_env = clean_env.copy()
        real_build = work / ("cert-real-build-" + name)
        real_env["READINESS_TEMP"] = str(real_build)
        if real_build.exists():
            raise ValueError(f"{name} real validator CLI home was not fresh.")
        result = subprocess.run(command, cwd=probe, env=real_env, capture_output=True,
                                timeout=240, check=False)
        if result.returncode != 0:
            raise ValueError(f"{name} real first validator help failed: "
                             f"exit={result.returncode}, stderr={result.stderr.decode(errors='replace')}")
        if not (real_build / "cli-home").is_dir():
            raise ValueError(f"{name} real first validator help did not create its isolated CLI home.")
        output = (result.stdout + result.stderr).decode(errors="replace")
        if re.search(r"ASP\.NET Core HTTPS development certificate|dotnet dev-certs https --trust|"
                     r"development certificate.{0,60}(?:install|trust)", output, re.IGNORECASE):
            raise ValueError(f"{name} first validator help emitted a development-certificate banner: {output}")

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
    print("Bash and available PowerShell launchers: first intercepted dotnet --version received "
          "launcher-owned certificate/first-time settings and isolated CLI home; SDK failure "
          "cleaned up automatic scratch; real first "
          "validator help emitted no development-certificate installation/trust banner. "
          "Resolver first --list-sdks received the same isolated settings.")


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


def worker_command(plugin, work):
    consumer = plugin / "skills/blazor-component-readiness"
    bash = (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/bin/bash.exe"
            if os.name == "nt" else shutil.which("bash"))
    if not bash or not Path(bash).is_file():
        raise ValueError("Bash is required to check the documented POSIX worker handoff.")
    unit = work / "worker unit"
    staged = unit / "plugin"
    target = staged / "skills/blazor-component-readiness"
    (target / "scripts").mkdir(parents=True)
    shutil.copyfile(plugin / "plugin.json", staged / "plugin.json")
    shutil.copyfile(consumer / "SKILL.md", target / "SKILL.md")
    helper = target / "scripts/prepare-worker-launch.sh"
    shutil.copy2(consumer / "scripts/prepare-worker-launch.sh", helper)
    if os.name != "nt" and not os.access(helper, os.X_OK):
        raise ValueError("The POSIX worker helper must be executable in the checkout.")
    (unit / "worker-prompt-base.txt").write_text("Inspect local evidence without runtime execution.\n")
    document = (consumer / "references/worker-execution.md").read_text()
    start = document.index('bash "$PLUGIN/skills/blazor-component-readiness/scripts/prepare-worker-launch.sh"')
    end = document.index('\n. "$CONTRACT"', start) + len('\n. "$CONTRACT"')
    script = work / "documented-worker-command.sh"
    script.write_text(
        'set -euo pipefail\nUNIT="$PWD/worker unit"\nPLUGIN="$UNIT/plugin/../plugin"\n'
        'CONTRACT="$UNIT/launch.env"\n' + document[start:end] +
        '\nEXPECTED_PLUGIN="$(cd -- "$PLUGIN" && pwd -P)"\n'
        '[[ "$PLUGIN_ROOT" = "$EXPECTED_PLUGIN" && "$CLI_PLUGIN_DIR" = "$EXPECTED_PLUGIN" ]]\n'
        '[[ -f "$WORKER_PROMPT_FILE" ]]\n'
        'grep -Fq "Explicit trusted plugin root: $EXPECTED_PLUGIN" "$WORKER_PROMPT_FILE"\n',
        newline="\n")
    run([str(bash), script.name], work)


def isolated_checks(plugin, work, setup):
    consumer = plugin / "skills/blazor-component-readiness"
    data = plugin / "skills/blazor-package-readiness-resolver/scripts/resolver/data"
    for name in ("rubric.json", "requirement-basis.json"):
        if (consumer / "references" / name).read_bytes() != (data / name).read_bytes():
            raise ValueError("Generated normative assets differ from their canonical sources.")
    if (consumer / "plugin-manifest.json").read_bytes() != (plugin / "plugin.json").read_bytes():
        raise ValueError("Generated plugin snapshot differs from its authority.")
    # Match ordinary skill-only staging, including a parent literally named "skills".
    staged = work / "single/.agents/skills/blazor-component-readiness"
    shutil.copytree(consumer, staged, ignore=shutil.ignore_patterns("bin", "obj"))
    if (staged.parent / "blazor-package-readiness-resolver").exists() or (staged.parents[1] / "plugin.json").exists():
        raise ValueError("Single-skill test accidentally staged a full plugin.")
    assessment = work / "single-assessment"
    assessment.mkdir()
    shutil.copyfile(setup, assessment / "setup.py")
    grader = REPO / "tests/dotnet-blazor/blazor-component-readiness/fixtures/check_report.py"
    shutil.copyfile(grader, assessment / "check_report.py")
    run([sys.executable, "setup.py"], assessment)
    command = report_command(staged)
    env = os.environ.copy()
    env["READINESS_TEMP"] = str(work / "single-build")
    run([*command, "inputs", "candidates", "init", "--acquisition", "published",
         "--package-locator", "sample.nupkg", "--package-method", "local-file",
         "--source-availability", "unresolved", "--output", str(assessment / "candidates0.json")], work, env)
    run([*command, "inputs", "candidates", "add-component", "--input", str(assessment / "candidates0.json"),
         "--id", "date-field", "--name", "DateField", "--mode", "interactive-server",
         "--lifecycle-applicability", "not-applicable", "--lifecycle-rationale",
         "This test control has no dynamic children.", "--output", str(assessment / "candidates1.json")], work, env)
    run([*command, "inputs", "candidates", "add-retrieval", "--input", str(assessment / "candidates1.json"),
         "--subject", "package", "--locator", "sample.nupkg", "--method", "local-file",
         "--result", "succeeded", "--output", str(assessment / "candidates2.json")], work, env)
    run([*command, "inputs", "discover", "--root", str(assessment), "--nupkg", str(assessment / "sample.nupkg"),
         "--candidates", str(assessment / "candidates2.json"), "--output",
         str(assessment / "discovered.json")], work, env)
    run([*command, "inputs", "confirm", "--root", str(assessment), "--draft",
         str(assessment / "discovered.json"), "--output", str(assessment / "confirmed.json")], work, env)
    def initialize(kind, output):
        return [*command, "assessment", "init", "--kind", kind, "--root", str(assessment),
                "--input", str(assessment / "confirmed.json"), "--output", str(assessment / output),
                *(["--component", "date-field"] if kind == "component" else [])]
    for kind in ("component", "package"):
        run(initialize(kind, kind + ".json"), work, env)
        run([sys.executable, "check_report.py", kind + ".json", kind], assessment)
    package = json.loads((assessment / "package.json").read_bytes())
    decisions = {
        "schema_version": 1,
        "rows": [
            {
                "id": row["id"],
                "status": "not tested",
                "observation": ("Static-only installed-plugin decision payload proves file-driven "
                                "draft authoring without embedding assessment prose in a shell command. " * 3).strip(),
                "evidence_ids": [],
                "owner_action": None,
                "assessment_follow_up": "Supply requirement-specific evidence before completion.",
                "not_applicable_rationale": None,
            }
            for row in package["rows"]
        ],
        "findings": [],
        "summary_groups": [],
        "completion_state": "incomplete",
    }
    decisions_path = assessment / "package.decisions.json"
    decisions_path.write_text(json.dumps(decisions), encoding="utf-8")
    if decisions_path.stat().st_size <= 32767:
        raise ValueError("Decision-file regression payload must exceed the Windows command-line limit.")
    run([*command, "assessment", "apply-decisions", "--assessment", str(assessment / "package.json"),
         "--decisions", str(decisions_path), "--output", str(assessment / "package.draft.json")], work, env)
    package_draft = json.loads((assessment / "package.draft.json").read_bytes())
    if len(package_draft["rows"]) != 60 or any(row["status"] != "not tested" for row in package_draft["rows"]):
        raise ValueError("File-driven assessment decisions did not update all package rows.")
    duplicate = json.loads(json.dumps(decisions))
    duplicate["rows"].append(duplicate["rows"][0])
    (assessment / "duplicate.decisions.json").write_text(json.dumps(duplicate), encoding="utf-8")
    run([*command, "assessment", "apply-decisions", "--assessment", str(assessment / "package.json"),
         "--decisions", str(assessment / "duplicate.decisions.json"),
         "--output", str(assessment / "duplicate.draft.json")], work, env, code=1)
    unknown = json.loads(json.dumps(decisions))
    unknown["rows"][0]["id"] = "UNKNOWN-ROW"
    (assessment / "unknown.decisions.json").write_text(json.dumps(unknown), encoding="utf-8")
    run([*command, "assessment", "apply-decisions", "--assessment", str(assessment / "package.json"),
         "--decisions", str(assessment / "unknown.decisions.json"),
         "--output", str(assessment / "unknown.draft.json")], work, env, code=1)
    gold = json.loads((assessment / "component.json").read_bytes())
    def reject(change):
        value = json.loads(json.dumps(gold))
        change(value)
        (assessment / "mutated.json").write_text(json.dumps(value))
        run([sys.executable, "check_report.py", "mutated.json", "component"], assessment, code=1)
    reject(lambda value: value["selected_ids"].pop())
    reject(lambda value: value.update(completion_state="complete"))
    reject(lambda value: value["identity"]["input_manifest_sha256"].update(value="0" * 64))
    reject(lambda value: value["rows"][0].update(status="verified"))
    for name in ("rubric.json", "requirement-basis.json"):
        path = staged / "references" / name
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n")
            run(initialize("package", "drift-" + name), work, env, code=1)
            if (assessment / ("drift-" + name)).exists():
                raise ValueError("Normative drift produced an assessment.")
        finally:
            path.write_bytes(original)
    snapshot = consumer / "plugin-manifest.json"
    original = snapshot.read_bytes()
    try:
        snapshot.write_bytes(original + b"\n")
        run([*report_command(consumer), "help"], work, env, code=1)
    finally:
        snapshot.write_bytes(original)
    resolver = work / "resolver-single/skills/blazor-package-readiness-resolver"
    shutil.copytree(plugin / "skills/blazor-package-readiness-resolver", resolver,
                    ignore=shutil.ignore_patterns("bin", "obj"))
    result = run([sys.executable, str(resolver / "scripts/run-resolver.py"), "package", "sample.nupkg"], assessment)
    (assessment / "result.json").write_bytes(result)
    run([sys.executable, "setup.py", "result.json", "all"], assessment)
    worker_command(plugin, work)
    print("Single-skill staging: component 52/package 60 rows, file-driven >32K decision application "
          "with duplicate/unknown rejection, four outcome-grader mutations, "
          "two normative drift rejections, installed manifest drift rejection, standalone resolver "
          "and exact documented Bash handoff passed; no worker was launched.")


def main():
    if sys.argv[1:] not in ([], ["--isolated"], ["--launcher"], ["--cert"], ["--autofill"], ["--lp03"]):
        raise ValueError("Supported options: --isolated, --launcher, --cert, --autofill, --lp03")
    with tempfile.TemporaryDirectory(prefix="resolver-installed-") as work:
        work = Path(work)
        plugin = work / "plugin"
        shutil.copytree(REPO / "plugins/dotnet-blazor", plugin,
                        ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
        if sys.argv[1:] == ["--lp03"]:
            lp03_installed_checks(plugin, work)
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
        if hashlib.sha256(coverage).hexdigest() != "17c4b777bc53892a8c2fa35cb962053bc9b8fa84687658c87fb927e005dddf12":
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
        consumer = plugin / "skills/blazor-component-readiness"
        # Build/launch only the trusted report validator; assessed build targets remain inert.
        command = report_command(consumer)
        certificate_launcher_checks(plugin, work)
        env = os.environ.copy()
        env["READINESS_TEMP"] = str(work / "report-build")
        # The report validator intentionally requires the caller's active .NET 11 SDK.
        run([*command, "help"], work, env)
        reader = consumer / "scripts/source-reader/BlazorComponentReadiness.SourceReader.csproj"
        run(["dotnet", "build", str(reader), "--artifacts-path", str(work / "reader-build"),
             "--configfile", str(consumer / "scripts/validator/restore-offline.config"),
             "--nologo", "--verbosity", "quiet", "-p:NuGetAudit=false"], work, env)
        run(["dotnet", str(work / "reader-build/bin/BlazorComponentReadiness.SourceReader/debug/"
                          "BlazorComponentReadiness.SourceReader.dll"), "--help"], work, env)
        run([*command, "inputs", "candidates", "init", "--acquisition", "published",
             "--package-locator", "sample.nupkg", "--package-method", "local-file",
             "--source-availability", "unresolved", "--output", str(assessment / "candidates0.json")], work, env)
        run([*command, "inputs", "candidates", "add-evidence", "--input", str(assessment / "candidates0.json"),
             "--path", "result.json", "--kind", "document", "--output",
             str(assessment / "candidates1.json")], work, env)
        run([*command, "inputs", "candidates", "add-evidence", "--input", str(assessment / "candidates1.json"),
             "--path", "observations.json", "--kind", "document", "--output",
             str(assessment / "candidates1-observations.json")], work, env)
        run([*command, "inputs", "candidates", "add-retrieval", "--input", str(assessment / "candidates1-observations.json"),
             "--subject", "package", "--locator", "sample.nupkg", "--method", "local-file",
             "--result", "succeeded", "--output", str(assessment / "candidates2.json")], work, env)
        run([*command, "inputs", "discover", "--root", str(assessment), "--nupkg",
             str(assessment / "sample.nupkg"), "--candidates", str(assessment / "candidates2.json"),
             "--output", str(assessment / "discovered.json")], work, env)
        run([*command, "inputs", "confirm", "--root", str(assessment), "--draft",
             str(assessment / "discovered.json"), "--output", str(assessment / "confirmed.json")], work, env)
        if "observations.json" not in json.dumps(json.loads((assessment / "confirmed.json").read_bytes())["evidence_inputs"]):
            raise ValueError("Confirmed report input omitted the broader checked evidence observations.")
        run([*command, "assessment", "init", "--kind", "package", "--root", str(assessment), "--input",
             str(assessment / "confirmed.json"), "--output", str(assessment / "assessment.json")], work, env)
        run([*command, "assessment", "export-identity", "--assessment", str(assessment / "assessment.json"),
             "--output", str(assessment / "identity.json")], work, env)
        claim = ("Retained byte inspection found build/assessment.targets matching a source entry, "
                 "a Razor project with an ancestor Directory.Build.props, and a supplied dependency "
                 "declaring MIT. This does not establish ownership, complete dependency closure, "
                 "notice coverage or compiled build correspondence.")
        run([*command, "evidence", "draft-add", "--output", str(assessment / "evidence-draft.json"),
             "--claim", claim, "--scope", "repository-wide", "--kind", "reviewer-generated-analysis",
             "--root", str(assessment), "--manifest", str(assessment / "confirmed.json"),
             "--evidence-input", "observations.json", "--method", "package-evidence-observations/1.0.0",
             "--captured-at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")], work, env)
        run([*command, "evidence", "ledger-build", "--kind", "repository", "--subject",
             str(assessment / "identity.json"), "--draft", str(assessment / "evidence-draft.json"),
             "--nupkg", str(assessment / "sample.nupkg"), "--output",
             str(assessment / "repository-ledger.json")], work, env)
        run([*command, "evidence", "ledger-validate", "--ledger",
             str(assessment / "repository-ledger.json")], work, env)
        records = json.loads((assessment / "repository-ledger.json").read_bytes())["records"]
        if len(records) != 1 or records[0]["claim"] != claim:
            raise ValueError("Typed ledger did not preserve the checked observation and its limits.")
        selected_id = records[0]["stable_id"]
        run([*command, "evidence", "bundle", "--assessment", str(assessment / "identity.json"),
             "--source-ledger", str(assessment / "repository-ledger.json"), "--ids", selected_id,
             "--root", str(assessment), "--manifest", str(assessment / "confirmed.json"),
             "--output", str(assessment / "evidence.json")], work, env)
        decisions = {"schema_version": 1, "rows": [{
            "id": "LP-10", "status": "not tested", "observation": claim, "evidence_ids": [selected_id],
            "owner_action": None, "not_applicable_rationale": None,
            "assessment_follow_up": "Obtain scoped ownership and build correspondence evidence before deciding LP-10."
        }], "findings": [], "summary_groups": [], "completion_state": "incomplete"}
        (assessment / "inspection-decisions.json").write_text(json.dumps(decisions), encoding="utf-8")
        run([*command, "assessment", "apply-decisions", "--assessment", str(assessment / "assessment.json"),
             "--decisions", str(assessment / "inspection-decisions.json"),
             "--output", str(assessment / "inspection-draft.json")], work, env)
        run([*command, "assessment", "canonicalize", "--assessment", str(assessment / "inspection-draft.json"),
             "--output", str(assessment / "inspection-canonical.json")], work, env)
        draft = json.loads((assessment / "inspection-canonical.json").read_bytes())
        row = next(row for row in draft["rows"] if row["id"] == "LP-10")
        if (row["observation"] != claim or row["evidence_ids"] != [selected_id] or
                row["status"] != "not tested" or draft["completion_state"] != "incomplete"):
            raise ValueError("Canonical draft lost partial evidence or promoted an unresolved row.")
        isolated_checks(plugin, work, setup)
        autofill_checks(plugin, work, setup)
        after = {p.relative_to(plugin): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in plugin.rglob("*") if p.is_file()}
        if before != after:
            raise ValueError("Installed plugin was modified by a launcher.")
        print("Installed offline launcher: coverage, package, checked request, two strict failures, "
              "acquisition rejection, hostile cwd isolation, six grader mutations and read-only plugin passed.")
        print("Full-report handoff: retained JSON registered/discovered/confirmed; canonical shared "
              "rubric admitted, trusted static source reader built, and separate 60-row package "
              "draft initialized, not claimed complete.")
        print("Broader checked inspection: Razor/inherited metadata, exact source match and supplied "
              "dependency/license declaration preserved through confirmed inputs, a validated typed "
              "ledger, an input-bound bundle and an unresolved canonical LP-10 draft observation; "
              "changed input rejected, no row/approval/completeness claims manufactured.")


if __name__ == "__main__":
    main()
