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


def main():
    with tempfile.TemporaryDirectory(prefix="resolver-installed-") as work:
        work = Path(work)
        plugin = work / "plugin"
        shutil.copytree(REPO / "plugins/dotnet-blazor", plugin,
                        ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
        helper = plugin / "skills/blazor-package-readiness-resolver/scripts/run-resolver.py"
        assessment = work / "assessment"
        assessment.mkdir()
        setup = REPO / "tests/dotnet-blazor/blazor-package-readiness-resolver/fixtures/setup.py"
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
        shell = shutil.which("pwsh") if os.name == "nt" else shutil.which("bash")
        if shell is None:
            raise ValueError("No supported shell for the report validator.")
        launcher = consumer / "scripts/validator" / ("run-validator.ps1" if os.name == "nt" else "run-validator.sh")
        command = ([shell, "-NoProfile", "-File", str(launcher)] if os.name == "nt"
                   else [shell, str(launcher)])
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
