"""Installed-plugin smoke checks. No model calls, network or assessed-code execution."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

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
        'set -euo pipefail\nUNIT="$PWD/worker unit"\nPLUGIN="$UNIT/plugin"\n'
        'CONTRACT="$UNIT/launch.env"\n' + document[start:end] +
        '\n[[ "$PLUGIN_ROOT" = "$PLUGIN" && "$CLI_PLUGIN_DIR" = "$PLUGIN" ]]\n'
        '[[ -f "$WORKER_PROMPT_FILE" ]]\n'
        'grep -Fq "Explicit trusted plugin root: $PLUGIN" "$WORKER_PROMPT_FILE"\n',
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
    print("Single-skill staging: component 52/package 60 rows, four outcome-grader mutations, "
          "two normative drift rejections, installed manifest drift rejection, standalone resolver "
          "and exact documented Bash handoff passed; no worker was launched.")


def main():
    if sys.argv[1:] not in ([], ["--isolated"]):
        raise ValueError("Supported option: --isolated")
    with tempfile.TemporaryDirectory(prefix="resolver-installed-") as work:
        work = Path(work)
        plugin = work / "plugin"
        shutil.copytree(REPO / "plugins/dotnet-blazor", plugin,
                        ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
        helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
        assessment = work / "assessment"
        assessment.mkdir()
        setup = REPO / "tests/dotnet-blazor/blazor-package-readiness-resolver/fixtures/setup.py"
        if sys.argv[1:]:
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
