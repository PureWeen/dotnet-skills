#!/usr/bin/env python3
"""Build only the trusted bundled resolver, without feeds; never build assessed inputs."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def pin_sdk(dotnet, scratch, env):
    result = subprocess.run([dotnet, "--list-sdks"], cwd=scratch, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=30, check=False)
    if result.returncode:
        sys.stderr.buffer.write(result.stdout)
        print("Resolver environment failure: could not enumerate installed .NET SDKs.",
              file=sys.stderr)
        return False
    versions = []
    for line in result.stdout.decode("utf-8").splitlines():
        match = re.fullmatch(r"(10\.0\.(\d+)) \[.+\]", line.strip())
        if match:
            versions.append((int(match[2]), match[1]))
    if not versions:
        print("Resolver environment failure: an installed stable .NET 10 SDK is required; "
              "no SDK or packs were downloaded.", file=sys.stderr)
        return False
    # Newer SDKs can request older net10 packs absent from their side-by-side installation.
    (scratch / "global.json").write_text(json.dumps({
        "sdk": {"version": max(versions)[1], "rollForward": "disable", "allowPrerelease": False}
    }) + "\n", encoding="utf-8")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("coverage", "package", "resolve", "replay"))
    parser.add_argument("input", nargs="?")
    args = parser.parse_args()
    if (args.command == "coverage") != (args.input is None):
        parser.error("coverage takes no input; all other commands require one input path")
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        print("Resolver environment failure: an installed .NET 10 SDK and packs are required.",
              file=sys.stderr)
        return 3
    runtime = Path(__file__).resolve().parent / "resolver"
    project = runtime / "BlazorPackageResolver.csproj"
    # Remove assessment-directory/global.json and ancestor build customization from tool selection.
    with tempfile.TemporaryDirectory(prefix="blazor-resolver-") as scratch:
        scratch = Path(scratch)
        env = os.environ.copy()
        env.update(DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
                   DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE="true",
                   DOTNET_GENERATE_ASPNET_CERTIFICATE="false",
                   DOTNET_CLI_HOME=str(scratch / "home"), DOTNET_EnableDiagnostics="0",
                   MSBuildEnableWorkloadResolver="false")
        # SDK bootstrap hooks are code, not assessment data.
        for key in list(env):
            if (key.upper().startswith(("MSBUILD", "NUGET_", "DOTNET_MSBUILD_", "RESTORE",
                                        "CUSTOMBEFORE", "CUSTOMAFTER")) or
                key.upper() in ("DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS",
                                "DOTNET_SHARED_STORE", "DOTNET_HOST_PATH", "DOTNET_ROOT")):
                env.pop(key)
        env["MSBuildEnableWorkloadResolver"] = "false"
        env["NUGET_PACKAGES"] = str(scratch / "packages")
        if not pin_sdk(dotnet, scratch, env):
            return 3
        properties = ["-p:ImportDirectoryBuildProps=false", "-p:ImportDirectoryBuildTargets=false",
                      "-p:ImportDirectoryPackagesProps=false", "-p:EnableResolverTestHooks=false",
                      "-p:DefineConstants=TRACE", "-noAutoResponse",
                      "-p:NuGetAudit=false", "-p:RestoreIgnoreFailedSources=false",
                      "-p:RestoreSources=", "-p:RestoreAdditionalProjectSources=",
                      "-p:RestoreFallbackFolders=", "-p:UseAppHost=false",
                      "-p:CustomBeforeMicrosoftCommonProps=", "-p:CustomAfterMicrosoftCommonProps=",
                      "-p:CustomBeforeMicrosoftCommonTargets=", "-p:CustomAfterMicrosoftCommonTargets=",
                      "-p:BaseIntermediateOutputPath=" + str(scratch / "obj") + os.sep,
                      "-p:OutputPath=" + str(scratch / "bin") + os.sep]
        commands = [
            [dotnet, "restore", str(project), "--configfile", str(runtime / "restore-offline.config"),
             "--verbosity", "quiet", *properties],
            [dotnet, "build", str(project), "--no-restore", "--configuration", "Release",
             "--nologo", "--verbosity", "quiet", *properties],
        ]
        for command in commands:
            result = subprocess.run(command, cwd=scratch, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=180, check=False)
            if result.returncode:
                sys.stderr.buffer.write(result.stdout)
                print("Resolver environment/build failure; no assessment result was produced.",
                      file=sys.stderr)
                return 3
        command = [dotnet, str(scratch / "bin" / "BlazorPackageResolver.dll"), args.command]
        if args.input is not None:
            command.append(str(Path(args.input).resolve()))
        return subprocess.run(command, cwd=scratch, env=env, timeout=180, check=False).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.TimeoutExpired) as error:
        print("Resolver environment failure: " + str(error), file=sys.stderr)
        sys.exit(3)
