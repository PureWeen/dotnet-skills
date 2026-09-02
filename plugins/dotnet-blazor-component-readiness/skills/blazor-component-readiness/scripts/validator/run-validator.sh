#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
plugin_root="$(cd -- "$script_dir/../../../.." && pwd -P)"
project="$script_dir/BlazorComponentReadiness.Validator.csproj"
restore_config="$script_dir/restore-offline.config"

sdk_version="$(dotnet --version 2>/dev/null || true)"
if [[ ! "$sdk_version" =~ ^11\. ]]; then
  printf 'error: the readiness validator requires the repository-selected .NET 11 SDK; active SDK is %s\n' \
    "${sdk_version:-unavailable}" >&2
  printf 'Select an installed .NET 11 SDK before running this launcher.\n' >&2
  exit 3
fi

cleanup=false
if [[ -n "${READINESS_TEMP:-}" ]]; then
  readiness_parent="$(dirname -- "$READINESS_TEMP")"
  if [[ ! -d "$readiness_parent" ]]; then
    printf 'error: the parent of READINESS_TEMP must already exist: %s\n' \
      "$readiness_parent" >&2
    exit 3
  fi

  readiness_temp="$(cd -- "$readiness_parent" && pwd -P)/$(basename -- "$READINESS_TEMP")"
else
  temp_parent="${TMPDIR:-${TEMP:-${TMP:-}}}"
  if [[ -z "$temp_parent" ]]; then
    printf 'error: no temporary directory is configured; set READINESS_TEMP.\n' >&2
    exit 3
  fi

  readiness_temp="$temp_parent/blazor-readiness-validator-$$-$RANDOM"
  (umask 077 && mkdir -- "$readiness_temp")
  cleanup=true
fi

case "$readiness_temp/" in
  "$plugin_root/"*)
    printf 'error: READINESS_TEMP must be outside the plugin tree.\n' >&2
    exit 3
    ;;
esac

mkdir -p -- "$readiness_temp"
readiness_temp="$(cd -- "$readiness_temp" && pwd -P)"
case "$readiness_temp/" in
  "$plugin_root/"*)
    printf 'error: READINESS_TEMP resolves inside the plugin tree.\n' >&2
    exit 3
    ;;
esac

mkdir -p -- "$readiness_temp/packages" "$readiness_temp/bin" "$readiness_temp/obj"
for artifact_directory in packages bin obj; do
  if [[ -L "$readiness_temp/$artifact_directory" ]]; then
    printf 'error: external artifact directories cannot be symbolic links: %s\n' \
      "$readiness_temp/$artifact_directory" >&2
    exit 3
  fi
done

if [[ "$cleanup" == true ]]; then
  trap 'rm -rf -- "$readiness_temp"' EXIT
fi

common=(
  -noAutoResponse
  -property:Configuration=Release
  -property:ImportDirectoryBuildProps=false
  -property:ImportDirectoryBuildTargets=false
  -property:ImportDirectoryPackagesProps=false
  "-property:RestoreConfigFile=$restore_config"
  "-property:RestorePackagesPath=$readiness_temp/packages"
  -property:NuGetAudit=false
  "-property:BaseOutputPath=$readiness_temp/bin/"
  "-property:BaseIntermediateOutputPath=$readiness_temp/obj/"
)

dotnet msbuild "$project" -target:Restore "${common[@]}"
dotnet msbuild "$project" '-target:VerifyNoPackageReferences;Build' "${common[@]}"

validator="$readiness_temp/bin/Release/net11.0/BlazorComponentReadiness.Validator.dll"
if [[ ! -f "$validator" || -L "$validator" ]]; then
  printf 'error: the expected external validator DLL was not produced: %s\n' "$validator" >&2
  exit 3
fi

dotnet "$validator" "$@"
