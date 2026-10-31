#!/usr/bin/env pwsh
#requires -Version 7
[CmdletBinding()]
param(
    [switch] $KeepTestRepositories
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourceScript = Join-Path $PSScriptRoot 'Sync-PluginVersions.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) "skills-version-tests-$([guid]::NewGuid().ToString('N'))"
$script:assertions = 0

function Invoke-Git {
    param(
        [string] $Repository,
        [Parameter(ValueFromRemainingArguments)]
        [string[]] $Arguments
    )
    $output = git -C $Repository @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed in '$Repository'."
    }
    return $output
}

function Assert-Equal {
    param($Expected, $Actual, [string] $Message)
    $script:assertions++
    if ($Expected -ne $Actual) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

function Set-JsonVersion {
    param([string] $Path, [string] $Version)
    $text = [IO.File]::ReadAllText($Path)
    $updated = [regex]::Replace($text, '("version"\s*:\s*")[^"]+(")', "`${1}$Version`${2}", 1)
    [IO.File]::WriteAllText($Path, $updated)
}

function New-TestRepository {
    param([string] $Name, [switch] $LegacyHistory)
    $repo = Join-Path $testRoot $Name
    [void](New-Item -ItemType Directory -Path (Join-Path $repo 'eng/version') -Force)
    [void](New-Item -ItemType Directory -Path (Join-Path $repo 'plugins/sample/.codex-plugin') -Force)
    [void](New-Item -ItemType Directory -Path (Join-Path $repo 'plugins/sample/.claude-plugin') -Force)
    [void](New-Item -ItemType Directory -Path (Join-Path $repo 'plugins/sample/skills/example') -Force)
    $testScript = Join-Path $repo 'eng/version/Sync-PluginVersions.ps1'
    Copy-Item -LiteralPath $sourceScript -Destination $testScript
    if ($LegacyHistory) {
        $text = [IO.File]::ReadAllText($testScript)
        [IO.File]::WriteAllText($testScript, $text.Replace('release-checkpoint-validation-v1', 'legacy-checkpoint-versioning'))
    }

    @'
{
  "$schema": "https://raw.githubusercontent.com/dotnet/Nerdbank.GitVersioning/main/src/NerdBank.GitVersioning/version.schema.json",
  "version": "0.1",
  "pathFilters": [
    ".",
    ":!plugin.json",
    ":!.codex-plugin/plugin.json",
    ":!.claude-plugin/plugin.json",
    ":!version.json"
  ]
}
'@ | Set-Content -LiteralPath (Join-Path $repo 'plugins/sample/version.json')

    @'
{
  "name": "sample",
  "version": "0.1.4",
  "description": "Test plugin.",
  "skills": ["./skills/"]
}
'@ | Set-Content -LiteralPath (Join-Path $repo 'plugins/sample/plugin.json')
    Copy-Item -LiteralPath (Join-Path $repo 'plugins/sample/plugin.json') `
        -Destination (Join-Path $repo 'plugins/sample/.codex-plugin/plugin.json')
    Copy-Item -LiteralPath (Join-Path $repo 'plugins/sample/plugin.json') `
        -Destination (Join-Path $repo 'plugins/sample/.claude-plugin/plugin.json')
    'initial content' | Set-Content -LiteralPath (Join-Path $repo 'plugins/sample/skills/example/SKILL.md')

    [void](Invoke-Git $repo init -b main)
    [void](Invoke-Git $repo config user.name 'Version Test')
    [void](Invoke-Git $repo config user.email 'version-test@example.com')
    [void](Invoke-Git $repo add .)
    [void](Invoke-Git $repo commit -m 'Initial release checkpoint')
    if ($LegacyHistory) {
        Copy-Item -LiteralPath $sourceScript -Destination $testScript -Force
    }
    return $repo
}

function Add-PluginContent {
    param([string] $Repository, [string] $RelativePath, [string] $Content, [string] $Message)
    $path = Join-Path $Repository "plugins/sample/$RelativePath"
    [void](New-Item -ItemType Directory -Path (Split-Path $path -Parent) -Force)
    $Content | Set-Content -LiteralPath $path
    [void](Invoke-Git $Repository add "plugins/sample/$RelativePath")
    [void](Invoke-Git $Repository commit -m $Message)
}

function Set-ManifestVersions {
    param([string] $Repository, [string] $Version)
    Set-JsonVersion -Path (Join-Path $Repository 'plugins/sample/plugin.json') -Version $Version
    Set-JsonVersion -Path (Join-Path $Repository 'plugins/sample/.codex-plugin/plugin.json') -Version $Version
    Set-JsonVersion -Path (Join-Path $Repository 'plugins/sample/.claude-plugin/plugin.json') -Version $Version
}

function Commit-ManifestVersions {
    param([string] $Repository, [string] $Version)
    Set-ManifestVersions -Repository $Repository -Version $Version
    [void](Invoke-Git $Repository add plugins/sample/plugin.json plugins/sample/.codex-plugin/plugin.json plugins/sample/.claude-plugin/plugin.json)
    [void](Invoke-Git $Repository commit -m "Stamp sample $Version")
}

function Invoke-Sync {
    param(
        [string] $Repository,
        [string] $BaseCommit,
        [string] $HeadCommit,
        [switch] $PredictMerge,
        [switch] $Write
    )
    $parameters = @{ OnlyChanged = $true }
    if ($BaseCommit) { $parameters.BaseCommit = $BaseCommit }
    if ($HeadCommit) { $parameters.HeadCommit = $HeadCommit }
    if ($PredictMerge) { $parameters.PredictMerge = $true }
    if ($Write) { $parameters.Write = $true }

    Push-Location $Repository
    try {
        $json = & (Join-Path $Repository 'eng/version/Sync-PluginVersions.ps1') @parameters
        return @($json | ConvertFrom-Json)
    }
    finally {
        Pop-Location
    }
}

function Test-BatchedChangesAdvanceOnce {
    $repo = New-TestRepository 'batched-changes'
    Add-PluginContent $repo 'skills/example/SKILL.md' 'change one' 'First content change'
    Add-PluginContent $repo 'skills/second/SKILL.md' 'change two' 'Second content change'

    $report = @(Invoke-Sync $repo)
    Assert-Equal 1 $report.Count 'Batched changes must produce one release.'
    Assert-Equal '0.1.5' $report[0].computed 'Batched changes must advance one patch.'
    Assert-Equal 2 @($report[0].commits).Count 'Both first-parent changes must be attributed.'

    [void](Invoke-Sync $repo -Write)
    [void](Invoke-Git $repo add plugins/sample/plugin.json plugins/sample/.codex-plugin/plugin.json plugins/sample/.claude-plugin/plugin.json)
    [void](Invoke-Git $repo commit -m 'Publish batched changes')
    Assert-Equal 0 @(Invoke-Sync $repo).Count 'Published content must not drift.'
}

function Test-GraphOnlyMergeDoesNotAdvance {
    $repo = New-TestRepository 'graph-only-merge'
    [void](Invoke-Git $repo branch stale)
    Add-PluginContent $repo 'skills/example/SKILL.md' 'published content' 'Change plugin content'
    Commit-ManifestVersions $repo '0.1.5'

    [void](Invoke-Git $repo switch stale)
    [void](Invoke-Git $repo merge main --no-ff -m 'Merge main into stale branch')
    'branch-only note' | Set-Content -LiteralPath (Join-Path $repo 'branch-note.txt')
    [void](Invoke-Git $repo add branch-note.txt)
    [void](Invoke-Git $repo commit -m 'Add branch-only note')
    [void](Invoke-Git $repo switch main)
    [void](Invoke-Git $repo merge stale --no-ff -m 'Merge stale branch')

    Assert-Equal 0 @(Invoke-Sync $repo).Count 'A graph-only merge must not advance the plugin.'
}

function Test-RevertToCheckpointDoesNotAdvance {
    $repo = New-TestRepository 'revert'
    Add-PluginContent $repo 'skills/example/SKILL.md' 'temporary content' 'Temporary plugin change'
    Add-PluginContent $repo 'skills/example/SKILL.md' 'initial content' 'Revert plugin change'
    Assert-Equal 0 @(Invoke-Sync $repo).Count 'Content restored to the checkpoint must not advance.'
}

function Test-BaseResetStartsAtZero {
    $repo = New-TestRepository 'base-reset'
    Set-JsonVersion -Path (Join-Path $repo 'plugins/sample/version.json') -Version '0.2'
    [void](Invoke-Git $repo add plugins/sample/version.json)
    [void](Invoke-Git $repo commit -m 'Start sample 0.2 release line')

    $report = @(Invoke-Sync $repo)
    Assert-Equal 1 $report.Count 'A release-base change must drift.'
    Assert-Equal '0.2.0' $report[0].computed 'A release-base change must reset patch to zero.'
    Assert-Equal $true $report[0].baseChanged 'A release-base change must be identified.'
}

function Test-MajorBaseResetStartsAtZero {
    $repo = New-TestRepository 'major-base-reset'
    Set-JsonVersion -Path (Join-Path $repo 'plugins/sample/version.json') -Version '1.0'
    [void](Invoke-Git $repo add plugins/sample/version.json)
    [void](Invoke-Git $repo commit -m 'Start sample 1.0 release line')

    $report = @(Invoke-Sync $repo)
    Assert-Equal 1 $report.Count 'A major release-base change must drift.'
    Assert-Equal '1.0.0' $report[0].computed 'A major release-base change must reset patch to zero.'
    Assert-Equal $true $report[0].baseChanged 'A major release-base change must be identified.'
}

function Test-BaseResetRejectsManualPatch {
    $repo = New-TestRepository 'base-reset-manual-patch'
    Set-JsonVersion -Path (Join-Path $repo 'plugins/sample/version.json') -Version '1.0'
    Set-ManifestVersions -Repository $repo -Version '1.0.5'
    [void](Invoke-Git $repo add plugins/sample/version.json plugins/sample/plugin.json plugins/sample/.codex-plugin/plugin.json plugins/sample/.claude-plugin/plugin.json)
    [void](Invoke-Git $repo commit -m 'Start sample 1.0 with an invalid patch')

    $report = @(Invoke-Sync $repo)
    Assert-Equal 1 $report.Count 'A base change with a manual patch must drift.'
    Assert-Equal '1.0.0' $report[0].computed 'A base change must calculate patch zero.'
    Assert-Equal $true $report[0].baseChanged 'The corrected base change must be identified.'
}

function Test-PredictionUsesCurrentMain {
    $repo = New-TestRepository 'current-main'
    [void](Invoke-Git $repo switch -c feature)
    Add-PluginContent $repo 'skills/feature/SKILL.md' 'feature content' 'Feature plugin change'
    $featureHead = Invoke-Git $repo rev-parse HEAD

    [void](Invoke-Git $repo switch main)
    Add-PluginContent $repo 'skills/main/SKILL.md' 'main content' 'Pending main plugin change'
    $currentMain = Invoke-Git $repo rev-parse HEAD
    [void](Invoke-Git $repo switch feature)

    $report = @(Invoke-Sync $repo -BaseCommit $currentMain -HeadCommit $featureHead -PredictMerge)
    Assert-Equal '0.1.6' $report[0].computed 'Prediction must include pending main and PR releases.'
}

function Test-MainOnlyBranchMergeDoesNotPredict {
    $repo = New-TestRepository 'main-only-merge'
    [void](Invoke-Git $repo branch feature)
    Add-PluginContent $repo 'skills/example/SKILL.md' 'published main content' 'Main plugin change'
    Commit-ManifestVersions $repo '0.1.5'
    $currentMain = Invoke-Git $repo rev-parse HEAD

    [void](Invoke-Git $repo switch feature)
    [void](Invoke-Git $repo merge main --no-ff -m 'Merge main into feature')
    $featureHead = Invoke-Git $repo rev-parse HEAD

    Assert-Equal 0 @(Invoke-Sync $repo -BaseCommit $currentMain -HeadCommit $featureHead -PredictMerge).Count `
        'A branch that only merges main must not predict a release.'
}

function Test-MatchingMainBaseDoesNotReset {
    $repo = New-TestRepository 'matching-main-base'
    [void](Invoke-Git $repo switch -c feature)
    Set-JsonVersion -Path (Join-Path $repo 'plugins/sample/version.json') -Version '0.2'
    Add-PluginContent $repo 'skills/feature/SKILL.md' 'feature content' 'Feature on 0.2'
    [void](Invoke-Git $repo add plugins/sample/version.json)
    [void](Invoke-Git $repo commit --amend --no-edit)
    $featureHead = Invoke-Git $repo rev-parse HEAD

    [void](Invoke-Git $repo switch main)
    Set-JsonVersion -Path (Join-Path $repo 'plugins/sample/version.json') -Version '0.2'
    Set-ManifestVersions -Repository $repo -Version '0.2.0'
    [void](Invoke-Git $repo add plugins/sample/version.json plugins/sample/plugin.json plugins/sample/.codex-plugin/plugin.json plugins/sample/.claude-plugin/plugin.json)
    [void](Invoke-Git $repo commit -m 'Publish main 0.2 release')
    $currentMain = Invoke-Git $repo rev-parse HEAD
    [void](Invoke-Git $repo switch feature)

    $report = @(Invoke-Sync $repo -BaseCommit $currentMain -HeadCommit $featureHead -PredictMerge)
    Assert-Equal '0.2.1' $report[0].computed 'A matching base already on main must not reset to 0.2.0.'
}

function Test-ConcurrentPredictionsReconcile {
    $repo = New-TestRepository 'concurrent'
    $initialMain = Invoke-Git $repo rev-parse HEAD

    [void](Invoke-Git $repo switch -c feature-a)
    Add-PluginContent $repo 'skills/a/SKILL.md' 'feature a' 'Feature A content'
    $headA = Invoke-Git $repo rev-parse HEAD
    $reportA = @(Invoke-Sync $repo -BaseCommit $initialMain -HeadCommit $headA -PredictMerge -Write)
    Assert-Equal '0.1.5' $reportA[0].computed 'Feature A prediction must be 0.1.5.'
    [void](Invoke-Git $repo add plugins/sample/plugin.json plugins/sample/.codex-plugin/plugin.json plugins/sample/.claude-plugin/plugin.json)
    [void](Invoke-Git $repo commit -m 'Stamp feature A')

    [void](Invoke-Git $repo switch main)
    [void](Invoke-Git $repo switch -c feature-b)
    Add-PluginContent $repo 'skills/b/SKILL.md' 'feature b' 'Feature B content'
    $headB = Invoke-Git $repo rev-parse HEAD
    $reportB = @(Invoke-Sync $repo -BaseCommit $initialMain -HeadCommit $headB -PredictMerge -Write)
    Assert-Equal '0.1.5' $reportB[0].computed 'Feature B prediction must also be 0.1.5.'
    [void](Invoke-Git $repo add plugins/sample/plugin.json plugins/sample/.codex-plugin/plugin.json plugins/sample/.claude-plugin/plugin.json)
    [void](Invoke-Git $repo commit -m 'Stamp feature B')

    [void](Invoke-Git $repo switch main)
    [void](Invoke-Git $repo merge feature-a --no-ff -m 'Merge feature A')
    [void](Invoke-Git $repo merge feature-b --no-ff -m 'Merge feature B')

    $report = @(Invoke-Sync $repo)
    Assert-Equal '0.1.6' $report[0].computed 'The second concurrent change must reconcile to 0.1.6.'
}

function Test-ManualManifestInflationIsRejected {
    $repo = New-TestRepository 'manual-inflation'
    Commit-ManifestVersions $repo '0.1.99'

    $report = @(Invoke-Sync $repo)
    Assert-Equal 1 $report.Count 'A manual patch inflation must drift.'
    Assert-Equal '0.1.4' $report[0].computed 'A manual patch inflation must restore the calculated version.'

    Add-PluginContent $repo 'skills/example/SKILL.md' 'content after inflation' 'Content after inflation'
    $report = @(Invoke-Sync $repo)
    Assert-Equal '0.1.5' $report[0].computed 'Content after a manual inflation must use the valid checkpoint.'
}

function Test-ManualManifestDowngradeIsRejected {
    $repo = New-TestRepository 'manual-downgrade'
    Commit-ManifestVersions $repo '0.1.1'

    $report = @(Invoke-Sync $repo)
    Assert-Equal 1 $report.Count 'A manual patch downgrade must drift.'
    Assert-Equal '0.1.4' $report[0].computed 'A manual patch downgrade must restore the calculated version.'

    Add-PluginContent $repo 'skills/example/SKILL.md' 'content after downgrade' 'Content after downgrade'
    $report = @(Invoke-Sync $repo)
    Assert-Equal '0.1.5' $report[0].computed 'Content after a manual downgrade must use the valid checkpoint.'
}

function Test-LegacyHistoryRemainsTrusted {
    $repo = New-TestRepository 'legacy-history' -LegacyHistory
    Commit-ManifestVersions $repo '0.1.99'

    Assert-Equal 0 @(Invoke-Sync $repo).Count `
        'Manifest transitions before checkpoint validation must remain a trusted migration baseline.'
}

function Test-MissingClaudeManifestIsRejected {
    $repo = New-TestRepository 'missing-claude-manifest'
    $claudeManifest = Join-Path $repo 'plugins/sample/.claude-plugin/plugin.json'
    Remove-Item -LiteralPath $claudeManifest

    $message = $null
    try {
        [void](Invoke-Sync $repo -Write)
    }
    catch {
        $message = $_.Exception.Message
    }

    Assert-Equal $true ($message -like '*missing .claude-plugin/plugin.json*') `
        'Version sync must reject a missing Claude manifest instead of copying unsafe root fields.'
    Assert-Equal $false (Test-Path $claudeManifest) `
        'Version sync must not recreate a missing Claude manifest from the root manifest.'
}

function Test-ClaudeManifestHostFieldsArePreserved {
    $repo = New-TestRepository 'claude-manifest-host-fields'
    $claudeManifest = Join-Path $repo 'plugins/sample/.claude-plugin/plugin.json'
    $content = [IO.File]::ReadAllText($claudeManifest).Replace(
        '"skills": ["./skills/"]',
        '"skills": ["./skills/"],' + [Environment]::NewLine + '  "lspServers": "./.lsp.json"')
    [IO.File]::WriteAllText($claudeManifest, $content)
    Add-PluginContent $repo 'skills/example/SKILL.md' 'changed content' 'Change plugin content'

    $report = @(Invoke-Sync $repo -Write)
    $claude = Get-Content $claudeManifest -Raw | ConvertFrom-Json
    Assert-Equal $report[0].computed $claude.version `
        'Version sync must update the Claude manifest to the computed version.'
    Assert-Equal './.lsp.json' $claude.lspServers `
        'Version sync must preserve Claude-specific manifest fields.'
}

function Test-RepositoryClaudeManifests {
    $repository = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    $pluginDirectories = Get-ChildItem (Join-Path $repository 'plugins') -Directory |
        Where-Object { Test-Path (Join-Path $_.FullName 'plugin.json') }

    foreach ($pluginDirectory in $pluginDirectories) {
        $rootManifest = Join-Path $pluginDirectory.FullName 'plugin.json'
        $claudeManifest = Join-Path $pluginDirectory.FullName '.claude-plugin/plugin.json'
        Assert-Equal $true (Test-Path $claudeManifest) `
            "Plugin '$($pluginDirectory.Name)' must carry .claude-plugin/plugin.json."
        $rootVersion = (Get-Content $rootManifest -Raw | ConvertFrom-Json).version
        $claudeVersion = (Get-Content $claudeManifest -Raw | ConvertFrom-Json).version
        Assert-Equal $rootVersion $claudeVersion `
            "Plugin '$($pluginDirectory.Name)' must keep its Claude manifest version synchronized with plugin.json."
    }

    $dotnetClaudeManifest = Get-Content `
        (Join-Path $repository 'plugins/dotnet/.claude-plugin/plugin.json') -Raw | ConvertFrom-Json
    Assert-Equal './.lsp.json' $dotnetClaudeManifest.lspServers `
        "The dotnet Claude manifest must reference Claude Code's LSP configuration."
}

function New-ReadinessRepository {
    param([string] $Name)
    $repo = New-TestRepository $Name
    $plugin = Join-Path $repo 'plugins/sample'
    $component = Join-Path $plugin 'skills/blazor-component-readiness'
    $data = Join-Path $plugin 'skills/blazor-package-readiness-resolver/scripts/resolver/data'
    [void](New-Item -ItemType Directory -Path $component, $data -Force)
    [IO.File]::WriteAllText((Join-Path $component 'SKILL.md'), 'Test consumer.')
    [IO.File]::WriteAllText((Join-Path $data 'rubric.json'), "{`"rows`":112}`r`n")
    [IO.File]::WriteAllText((Join-Path $data 'requirement-basis.json'), "{`"basis`":1}`n")
    $versionPath = Join-Path $plugin 'version.json'
    $version = Get-Content $versionPath -Raw | ConvertFrom-Json
    $version.pathFilters += @(
        ':!skills/blazor-component-readiness/plugin-manifest.json',
        ':!skills/blazor-component-readiness/references/rubric.json',
        ':!skills/blazor-component-readiness/references/requirement-basis.json')
    [IO.File]::WriteAllText($versionPath, ($version | ConvertTo-Json -Depth 5))
    [void](Invoke-Git $repo add plugins)
    [void](Invoke-Git $repo commit -m 'Add consumer and canonical data')
    $report = @(Invoke-Sync $repo -Write)
    Assert-Equal '0.1.5' $report[0].computed 'Adding consumer content advances exactly once.'
    [void](Invoke-Git $repo add plugins)
    [void](Invoke-Git $repo commit -m 'Publish generated consumer assets')
    return $repo
}

function Assert-GeneratedFiles {
    param([string] $Repository)
    $plugin = Join-Path $Repository 'plugins/sample'
    $pairs = @{
        'skills/blazor-component-readiness/plugin-manifest.json' = 'plugin.json'
        'skills/blazor-component-readiness/references/rubric.json' = 'skills/blazor-package-readiness-resolver/scripts/resolver/data/rubric.json'
        'skills/blazor-component-readiness/references/requirement-basis.json' = 'skills/blazor-package-readiness-resolver/scripts/resolver/data/requirement-basis.json'
    }
    foreach ($target in $pairs.Keys) {
        Assert-Equal ([Convert]::ToHexString([IO.File]::ReadAllBytes((Join-Path $plugin $pairs[$target])))) `
            ([Convert]::ToHexString([IO.File]::ReadAllBytes((Join-Path $plugin $target)))) `
            "Generated '$target' must be byte-identical to its authority."
    }
}

function Test-GeneratedAssetsAreRepairedWithoutReleasing {
    $repo = New-ReadinessRepository 'generated-assets'
    Assert-GeneratedFiles $repo
    Assert-Equal 0 @(Invoke-Sync $repo).Count 'Generated assets must not cause recursive releases.'
    $base = Invoke-Git $repo rev-parse HEAD
    $component = Join-Path $repo 'plugins/sample/skills/blazor-component-readiness'
    [IO.File]::WriteAllText((Join-Path $component 'plugin-manifest.json'), '{"version":"9.9.9"}')
    [IO.File]::WriteAllText((Join-Path $component 'references/rubric.json'), '{}')
    Remove-Item -LiteralPath (Join-Path $component 'references/requirement-basis.json')
    [void](Invoke-Git $repo add plugins)
    [void](Invoke-Git $repo commit -m 'Introduce output-only drift')
    $head = Invoke-Git $repo rev-parse HEAD
    $report = @(Invoke-Sync $repo -BaseCommit $base -HeadCommit $head -PredictMerge)
    Assert-Equal 1 $report.Count 'Head-scoped sync must select output-only drift.'
    Assert-Equal '0.1.5' $report[0].computed 'Generated-only drift is release-neutral.'
    Assert-Equal $false (Test-Path (Join-Path $component 'references/requirement-basis.json')) `
        'Read-only sync must not write missing outputs.'
    [void](Invoke-Sync $repo -BaseCommit $base -HeadCommit $head -PredictMerge -Write)
    Assert-GeneratedFiles $repo
    [void](Invoke-Git $repo add plugins)
    [void](Invoke-Git $repo commit -m 'Repair generated outputs')
    Assert-Equal 0 @(Invoke-Sync $repo).Count 'Committed output repairs must not advance content height.'
    Assert-Equal $true ([string]::IsNullOrWhiteSpace((Invoke-Git $repo status --porcelain))) `
        'Generated repairs must be idempotent.'
}

function Test-GeneratedAssetsFollowTheirAuthorities {
    $repo = New-ReadinessRepository 'generated-authorities'
    $base = Invoke-Git $repo rev-parse HEAD
    $manifest = Join-Path $repo 'plugins/sample/plugin.json'
    [IO.File]::WriteAllText($manifest,
        ([IO.File]::ReadAllText($manifest).Replace('Test plugin.', 'Updated description.')) + "`r`n")
    [void](Invoke-Git $repo add plugins/sample/plugin.json)
    [void](Invoke-Git $repo commit -m 'Update authoritative metadata only')
    $head = Invoke-Git $repo rev-parse HEAD
    $report = @(Invoke-Sync $repo -BaseCommit $base -HeadCommit $head -PredictMerge -Write)
    Assert-Equal 1 $report.Count 'A root-only metadata change must synchronize its bundled snapshot.'
    Assert-Equal '0.1.5' $report[0].computed 'A root-only metadata change must remain release-neutral.'
    Assert-GeneratedFiles $repo
    [void](Invoke-Git $repo add plugins)
    [void](Invoke-Git $repo commit -m 'Update manifest description')
    Assert-Equal 0 @(Invoke-Sync $repo).Count 'Manifest-only metadata and its snapshot are release-neutral.'
    Add-PluginContent $repo 'skills/blazor-package-readiness-resolver/scripts/resolver/data/rubric.json' `
        '{"rows":113}' 'Change canonical rubric'
    $report = @(Invoke-Sync $repo -Write)
    Assert-Equal '0.1.6' $report[0].computed 'Changing an authority must advance content exactly once.'
    Assert-GeneratedFiles $repo
    [void](Invoke-Git $repo add plugins)
    [void](Invoke-Git $repo commit -m 'Publish changed canonical data')
    Assert-Equal 0 @(Invoke-Sync $repo).Count 'Regenerated data must not cause a second release.'
}

function Test-GeneratedSnapshotUsesCurrentMainPrediction {
    $repo = New-ReadinessRepository 'generated-stale-base'
    [void](Invoke-Git $repo switch -c feature)
    Add-PluginContent $repo 'skills/example/SKILL.md' 'feature' 'Feature content'
    $head = Invoke-Git $repo rev-parse HEAD
    [void](Invoke-Git $repo switch main)
    Add-PluginContent $repo 'skills/main/SKILL.md' 'main' 'Main content'
    [void](Invoke-Sync $repo -Write)
    [void](Invoke-Git $repo add plugins)
    [void](Invoke-Git $repo commit -m 'Publish current main')
    $main = Invoke-Git $repo rev-parse HEAD
    [void](Invoke-Git $repo switch feature)
    $report = @(Invoke-Sync $repo -BaseCommit $main -HeadCommit $head -PredictMerge -Write)
    Assert-Equal '0.1.7' $report[0].computed 'A stale consumer must predict from newer current main.'
    Assert-GeneratedFiles $repo
    Assert-Equal 0 @(Invoke-Sync $repo -BaseCommit $main -HeadCommit $head -PredictMerge).Count `
        'Current-main prediction must be read-only and idempotent after synchronization.'
}

[void](New-Item -ItemType Directory -Path $testRoot)
try {
    Test-BatchedChangesAdvanceOnce
    Test-GraphOnlyMergeDoesNotAdvance
    Test-RevertToCheckpointDoesNotAdvance
    Test-BaseResetStartsAtZero
    Test-MajorBaseResetStartsAtZero
    Test-BaseResetRejectsManualPatch
    Test-PredictionUsesCurrentMain
    Test-MainOnlyBranchMergeDoesNotPredict
    Test-MatchingMainBaseDoesNotReset
    Test-ConcurrentPredictionsReconcile
    Test-ManualManifestInflationIsRejected
    Test-ManualManifestDowngradeIsRejected
    Test-LegacyHistoryRemainsTrusted
    Test-MissingClaudeManifestIsRejected
    Test-ClaudeManifestHostFieldsArePreserved
    Test-GeneratedAssetsAreRepairedWithoutReleasing
    Test-GeneratedAssetsFollowTheirAuthorities
    Test-GeneratedSnapshotUsesCurrentMainPrediction
    Test-RepositoryClaudeManifests
    Write-Host "Passed $script:assertions plugin-version assertions."
}
finally {
    if ($KeepTestRepositories) {
        Write-Host "Kept test repositories at $testRoot"
    }
    else {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
