"""Installed-plugin smoke checks. No model calls, network or assessed-code execution."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


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
    if sys.argv[1:] not in ([], ["--isolated"], ["--launcher"]):
        raise ValueError("Supported options: --isolated, --launcher")
    with tempfile.TemporaryDirectory(prefix="resolver-installed-") as work:
        work = Path(work)
        plugin = work / "plugin"
        shutil.copytree(REPO / "plugins/dotnet-blazor", plugin,
                        ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
        helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
        sdk_checks(helper, work)
        assessment = work / "assessment"
        assessment.mkdir()
        setup = REPO / "tests/dotnet-blazor/blazor-package-readiness-resolver/fixtures/setup.py"
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
        if hashlib.sha256(coverage).hexdigest() != "0f3e74952684b87eee5aa2cc29d27d05ba2472d32ec449344f5a9cd8a6efb763":
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
        consumer = plugin / "skills/blazor-component-readiness"
        # Build/launch only the trusted report validator; assessed build targets remain inert.
        command = report_command(consumer)
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
        run([*command, "inputs", "candidates", "add-retrieval", "--input", str(assessment / "candidates1.json"),
             "--subject", "package", "--locator", "sample.nupkg", "--method", "local-file",
             "--result", "succeeded", "--output", str(assessment / "candidates2.json")], work, env)
        run([*command, "inputs", "discover", "--root", str(assessment), "--nupkg",
             str(assessment / "sample.nupkg"), "--candidates", str(assessment / "candidates2.json"),
             "--output", str(assessment / "discovered.json")], work, env)
        run([*command, "inputs", "confirm", "--root", str(assessment), "--draft",
             str(assessment / "discovered.json"), "--output", str(assessment / "confirmed.json")], work, env)
        run([*command, "assessment", "init", "--kind", "package", "--root", str(assessment), "--input",
             str(assessment / "confirmed.json"), "--output", str(assessment / "assessment.json")], work, env)
        isolated_checks(plugin, work, setup)
        after = {p.relative_to(plugin): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in plugin.rglob("*") if p.is_file()}
        if before != after:
            raise ValueError("Installed plugin was modified by a launcher.")
        print("Installed offline launcher: coverage, package, checked request, two strict failures, "
              "acquisition rejection, hostile cwd isolation, six grader mutations and read-only plugin passed.")
        print("Full-report handoff: retained JSON registered/discovered/confirmed; canonical shared "
              "rubric admitted, trusted static source reader built, and separate 60-row package "
              "draft initialized, not claimed complete.")


if __name__ == "__main__":
    main()
