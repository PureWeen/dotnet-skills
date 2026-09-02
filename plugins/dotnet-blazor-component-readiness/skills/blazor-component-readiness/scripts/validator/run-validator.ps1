[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ValidatorArguments
)

$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
$pluginRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '../../../..')).ProviderPath
$project = Join-Path $scriptDir 'BlazorComponentReadiness.Validator.csproj'
$restoreConfig = Join-Path $scriptDir 'restore-offline.config'

$sdkVersion = (& dotnet --version 2>$null)
if ($LASTEXITCODE -ne 0 -or $sdkVersion -notmatch '^11\.') {
    $active = if ([string]::IsNullOrWhiteSpace($sdkVersion)) { 'unavailable' } else { $sdkVersion }
    [Console]::Error.WriteLine(
        "error: the readiness validator requires the repository-selected .NET 11 SDK; active SDK is $active")
    [Console]::Error.WriteLine('Select an installed .NET 11 SDK before running this launcher.')
    exit 3
}

$cleanup = $false
if ([string]::IsNullOrWhiteSpace($env:READINESS_TEMP)) {
    $tempParent = [IO.Path]::GetTempPath()
    if ([string]::IsNullOrWhiteSpace($tempParent)) {
        [Console]::Error.WriteLine(
            'error: no temporary directory is configured; set READINESS_TEMP.')
        exit 3
    }

    $readinessTemp = Join-Path $tempParent (
        'blazor-readiness-validator-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($readinessTemp) | Out-Null
    $cleanup = $true
}
else {
    $readinessTemp = [IO.Path]::GetFullPath($env:READINESS_TEMP)
}

$comparison = if ($IsWindows) {
    [StringComparison]::OrdinalIgnoreCase
}
else {
    [StringComparison]::Ordinal
}
$pluginPrefix = $pluginRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (($readinessTemp + [IO.Path]::DirectorySeparatorChar).StartsWith(
        $pluginPrefix,
        $comparison)) {
    [Console]::Error.WriteLine('error: READINESS_TEMP must be outside the plugin tree.')
    exit 3
}

[IO.Directory]::CreateDirectory($readinessTemp) | Out-Null
$readinessTemp = (Resolve-Path -LiteralPath $readinessTemp).ProviderPath
if (($readinessTemp + [IO.Path]::DirectorySeparatorChar).StartsWith(
        $pluginPrefix,
        $comparison)) {
    [Console]::Error.WriteLine('error: READINESS_TEMP resolves inside the plugin tree.')
    exit 3
}

[IO.Directory]::CreateDirectory((Join-Path $readinessTemp 'packages')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $readinessTemp 'bin')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $readinessTemp 'obj')) | Out-Null
foreach ($artifactDirectory in @('packages', 'bin', 'obj')) {
    $artifactPath = Join-Path $readinessTemp $artifactDirectory
    if (([IO.File]::GetAttributes($artifactPath) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        [Console]::Error.WriteLine(
            "error: external artifact directories cannot be symbolic links: $artifactPath")
        exit 3
    }
}

try {
    $common = @(
        '-noAutoResponse'
        '-property:Configuration=Release'
        '-property:ImportDirectoryBuildProps=false'
        '-property:ImportDirectoryBuildTargets=false'
        '-property:ImportDirectoryPackagesProps=false'
        "-property:RestoreConfigFile=$restoreConfig"
        "-property:RestorePackagesPath=$(Join-Path $readinessTemp 'packages')"
        '-property:NuGetAudit=false'
        "-property:BaseOutputPath=$(Join-Path $readinessTemp 'bin')$([IO.Path]::DirectorySeparatorChar)"
        "-property:BaseIntermediateOutputPath=$(Join-Path $readinessTemp 'obj')$([IO.Path]::DirectorySeparatorChar)"
    )

    & dotnet msbuild $project -target:Restore @common
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    & dotnet msbuild $project '-target:VerifyNoPackageReferences;Build' @common
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $validator = Join-Path $readinessTemp (
        'bin/Release/net11.0/BlazorComponentReadiness.Validator.dll')
    if (-not [IO.File]::Exists($validator) -or
        ([IO.File]::GetAttributes($validator) -band [IO.FileAttributes]::ReparsePoint)) {
        [Console]::Error.WriteLine(
            "error: the expected external validator DLL was not produced: $validator")
        exit 3
    }

    & dotnet $validator @ValidatorArguments
    exit $LASTEXITCODE
}
finally {
    if ($cleanup -and [IO.Directory]::Exists($readinessTemp)) {
        [IO.Directory]::Delete($readinessTemp, $true)
    }
}
