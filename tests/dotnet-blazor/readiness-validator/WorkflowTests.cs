using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

internal static class WorkflowTests
{
    private static readonly string[] RequiredReferences =
    [
        "report-contract.md",
        "feedback-contract.md",
        "library-assessment.md",
        "worker-execution.md",
        "artifact-acquisition.md",
        "documentation-discovery.md",
        "status-boundaries.md",
        "targeted-profiles.md",
        "learning-loop.md",
        "blinded-comparison.md",
        "area-provenance-integrity.md",
        "area-security-privacy.md",
        "area-accessibility.md",
        "area-blazor-runtime.md",
        "area-trim-performance.md",
        "area-ci-release.md",
        "area-support-lifecycle.md",
        "area-conditional-families.md",
        "overlay-scaffolder.md",
        "overlay-ai-skill.md",
        "docx-crosswalk.md"
    ];

    private static readonly string[] Statuses =
    [
        "verified",
        "gap",
        "owner evidence required",
        "not tested",
        "not applicable"
    ];

    public static void Run(string pluginRoot)
    {
        var skillRoot = Path.Combine(pluginRoot, "skills", "blazor-component-readiness");
        var skillPath = Path.Combine(skillRoot, "SKILL.md");
        var referencesRoot = Path.Combine(skillRoot, "references");
        var skill = File.ReadAllText(skillPath);

        Assert(File.ReadLines(skillPath).Count() < 500, "portable skill must remain below 500 lines");
        Assert(skill.Length < 20_000, "portable skill must remain below the 5,000-token chars/4 warning proxy");

        foreach (var reference in RequiredReferences)
        {
            var path = Path.Combine(referencesRoot, reference);
            Assert(File.Exists(path), $"required flattened reference is missing: {reference}");
            Assert(
                skill.Contains($"references/{reference}", StringComparison.Ordinal),
                $"portable skill must progressively link reference: {reference}");
        }

        foreach (Match match in Regex.Matches(skill, @"\]\(([^)]+)\)"))
        {
            var value = match.Groups[1].Value;
            if (value.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith('#'))
            {
                continue;
            }

            Assert(!Path.IsPathRooted(value), $"skill link must be relative: {value}");
            var normalized = value.Replace('\\', '/').Split('#')[0];
            Assert(
                normalized.Split('/', StringSplitOptions.RemoveEmptyEntries).Length <= 2,
                $"skill link must be at most one directory deep: {value}");
            Assert(File.Exists(Path.Combine(skillRoot, normalized)), $"broken skill link: {value}");
        }

        AssertContains(skill, "explicit vendor self-assessment", "explicit-intent router");
        AssertContains(skill, "ordinary Blazor authoring/debugging", "ordinary-work dormancy");
        AssertContains(skill, "first-party framework review", "first-party dormancy");
        AssertContains(skill, "generic NuGet help", "NuGet dormancy");
        AssertContains(skill, "CI/PR/issue triage", "triage dormancy");
        AssertContains(skill, "implementation-only work", "implementation dormancy");
        AssertContains(skill, "certification", "certification boundary");
        AssertContains(skill, "Requires an active .NET 11 SDK", ".NET 11 prerequisite");
        AssertContains(skill, "structural validation", "structural/factual boundary");
        AssertContains(skill, "121-ID operational crosswalk", "core count");
        AssertContains(skill, "60 `repository-wide` / 61 `component-specific`", "scope ownership");
        AssertContains(skill, "`source-available`, `closed-source`, or `unresolved`", "source availability");
        AssertContains(skill, "owner-supplied-internal-evidence", "owner evidence");
        AssertContains(skill, "owner-supplied-public-evidence", "public owner evidence");
        AssertContains(skill, "current-generation.json", "authoritative library index pointer");
        AssertContains(skill, "every claimed render mode", "render-mode coverage");
        AssertContains(skill, "dynamic_child_lifecycle.applicability", "conditional lifecycle gate");
        AssertContains(skill, "comparison inputs-freeze", "blinded comparison freeze");
        AssertContains(skill, "comparison inputs-validate", "blinded comparison validation");
        AssertContains(skill, "coverage surface", "blinded comparison evidence-surface coverage");
        AssertContains(skill, "`source-proof-v1`", "structured source proof");
        AssertContains(skill, "`public-absence-v1`", "typed public absence proof");
        AssertContains(skill, "`direct-failure-v1`", "typed direct failure proof");
        AssertContains(skill, "source capture-archive", "archive source capture command");
        AssertContains(skill, "Never run Git metadata commands inside an archive", "archive Git boundary");
        AssertContains(skill, "same-job source build plus privileged signing/publishing is a gap", "release job trust boundary");
        AssertContains(skill, "one mutable path is not a digest-bound immutable handoff", "immutable artifact boundary");
        AssertContains(skill, "component assignment through a public `[Parameter]` setter is mutation", "parameter mutation boundary");
        AssertContains(skill, "mutable cascade proves `PERF-05` applicability, not a gap", "cascading rerender measurement boundary");
        AssertContains(skill, "legacy v1", "legacy assessment verification");
        AssertContains(skill, "Package-only", "package-only mode");
        AssertContains(skill, "components: []", "empty package inventory");
        AssertContains(skill, "no component worker", "package-only worker boundary");
        AssertContains(skill, "Skip this step for package-only.", "package-only skips library orchestration");
        AssertContains(skill, "Single component, unified", "unified mode");
        AssertContains(skill, "Single package, split", "split mode");
        AssertContains(skill, "Full library", "library mode");
        AssertContains(skill, "unsupported host: full-library assessment requires isolated workers", "unsupported-host stop");
        AssertContains(skill, "never use a shared-context or serialized fallback", "no shared-context fallback");
        AssertContains(skill, "interruption", "resume behavior");
        AssertContains(skill, "feedback", "feedback workflow");
        AssertContains(skill, "factual correction", "correction workflow");
        AssertContains(skill, "decision-guidance.md", "decision guidance");
        AssertContains(skill, "source validation-manifest SHA-256", "guidance source digest");
        AssertContains(skill, "Run automatically", "automatic validation");
        Assert(
            Regex.IsMatch(
                skill,
                @"assessment init --kind unified\b[^\r\n]*--component <component-id>"),
            "unified assessment init example requires the component identity");

        foreach (var status in Statuses)
        {
            AssertContains(skill, $"`{status}`", $"status '{status}'");
        }

        foreach (var command in new[]
        {
            "package inspect",
            "source capture-archive",
            "inputs discover",
            "inputs confirm",
            "inputs validate",
            "evidence ledger-build",
            "evidence ledger-validate",
            "evidence bundle",
            "assessment init --kind unified",
            "assessment init --kind package",
            "assessment init --kind component",
            "assessment canonicalize",
            "assessment export-identity",
            "assessment validate",
            "assessment revise",
            "report render",
            "report verify",
            "inventory discover",
            "inventory confirm",
            "inventory status",
            "library reconcile",
            "library validate",
            "library index"
        })
        {
            AssertContains(skill, command, $"CLI command '{command}'");
        }

        foreach (var limit in new[] { "256 MiB nupkg", "1 MiB nuspec", "4 MiB authored ledger",
                     "64 MiB serialized", "32 supplemental" })
        {
            AssertContains(
                File.ReadAllText(Path.Combine(referencesRoot, "artifact-acquisition.md")),
                limit,
                $"resource limit '{limit}'");
        }

        AssertRubricIsSoleRequirementSource(referencesRoot);
        AssertNoForbiddenCoupling(pluginRoot);
        AssertAgents(pluginRoot);
        AssertContracts(referencesRoot);
        AssertWorkerLaunchContract(pluginRoot);
        AssertReadinessLauncherExample(skillRoot);
    }

    private static void AssertRubricIsSoleRequirementSource(string referencesRoot)
    {
        using var rubric = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(referencesRoot, "rubric.json")));
        var ids = rubric.RootElement.GetProperty("core").GetProperty("requirements")
            .EnumerateArray()
            .Select(row => row.GetProperty("id").GetString()!)
            .ToArray();
        Assert(ids.Length == 121 && ids.Distinct(StringComparer.Ordinal).Count() == 121,
            "rubric.json remains the sole current 121-ID source");

        var checklist = File.ReadAllText(Path.Combine(referencesRoot, "checklist.md"));
        AssertContains(checklist, "Generated from rubric.json. Do not edit by hand.", "generated checklist marker");
        foreach (var path in Directory.GetFiles(referencesRoot, "*.md"))
        {
            if (Path.GetFileName(path) is "checklist.md" or "checklist.v1.3.0.md")
            {
                continue;
            }

            var text = File.ReadAllText(path);
            var duplicatedDefinitions = ids.Count(id =>
                Regex.IsMatch(text, $@"(?m)^\s*-\s+\*\*{Regex.Escape(id)}\*\*\s+"));
            Assert(duplicatedDefinitions == 0, $"{Path.GetFileName(path)} must not redefine rubric rows");
        }
    }

    private static void AssertNoForbiddenCoupling(string pluginRoot)
    {
        var files = Directory.GetFiles(pluginRoot, "*.md", SearchOption.AllDirectories);
        foreach (var path in files)
        {
            var text = File.ReadAllText(path);
            foreach (var forbidden in new[]
            {
                "/Users/",
                ".copilot/",
                ".github/agents/blazor-component-readiness",
                "eng/skill-evals",
                "source activate",
                "--legacy-evidence",
                "--shared-row-projection",
                "--producer-validator"
            })
            {
                Assert(
                    !text.Contains(forbidden, StringComparison.OrdinalIgnoreCase),
                    $"{Path.GetFileName(path)} contains forbidden coupling '{forbidden}'");
            }
        }
    }

    private static void AssertAgents(string pluginRoot)
    {
        var coordinator = File.ReadAllText(Path.Combine(
            pluginRoot, "agents", "blazor-component-readiness.agent.md"));
        var worker = File.ReadAllText(Path.Combine(
            pluginRoot, "agents", "blazor-component-readiness-worker.agent.md"));

        AssertContains(coordinator, "user-invocable: true", "coordinator invocation");
        AssertContains(coordinator, "disable-model-invocation: true", "coordinator ambient routing");
        AssertContains(coordinator, "ask_user", "confirmation tool");
        AssertContains(
            coordinator,
            "Inspect every supplied local artifact before asking for missing information",
            "local discovery before clarification");
        AssertContains(
            coordinator,
            "explicitly requests separate execution",
            "explicit single-unit worker override");
        foreach (var tool in new[]
        {
            "\"skill\"", "\"read\"", "\"search\"", "\"edit\"", "\"execute\"",
            "\"web_search\"", "\"web_fetch\"", "\"Skill\"", "\"Read\"", "\"Glob\"",
            "\"Grep\"", "\"Edit\"", "\"Write\"", "\"Bash\"", "\"read_file\"", "\"replace\"",
            "\"write_file\"", "\"glob\"", "\"grep_search\"", "\"run_shell_command\""
        })
        {
            AssertContains(coordinator, tool, $"coordinator tool {tool}");
        }

        Assert(!coordinator.Contains("\"agent\"", StringComparison.Ordinal), "coordinator must not expose nested agent dispatch");
        Assert(!coordinator.Contains("\"Task\"", StringComparison.Ordinal), "coordinator must not expose nested task dispatch");
        AssertContains(coordinator, "Never invoke the worker through a nested agent/task tool.", "nested worker prohibition");
        AssertContains(coordinator, "package-only", "coordinator package-only mode");
        AssertContains(coordinator, "no component worker", "coordinator package-only worker boundary");
        AssertContains(coordinator, "assessment init --kind package", "code-owned package assessment kind");
        AssertContains(coordinator, "do not require inventory, workers, or an index", "package-only completion boundary");
        AssertContains(coordinator, "absolute trusted plugin root", "coordinator trusted plugin context");
        AssertContains(coordinator, "explicit trusted plugin root", "coordinator explicit source context");
        AssertContains(coordinator, "exact source path", "coordinator source identity receipt");
        AssertContains(coordinator, "permissions or content exclusion", "coordinator denial boundary");
        AssertContains(coordinator, "matching inherited `PWD`", "coordinator cwd/PWD launch contract");
        AssertContains(coordinator, "native argv", "coordinator native launch receipt");
        AssertContains(coordinator, "A validated revision is not proof that the requested investigation finished.", "investigation completion boundary");
        AssertContains(coordinator, "do not accept a blanket not-tested template as a completed assessment", "placeholder handoff rejection");
        AssertContains(coordinator, "Pass absolute `--root`, `--revision`, `--output`, and `--package-revision` paths", "absolute verification arguments");
        AssertContains(coordinator, "exactly one top-level `blazor-component-readiness-worker` session", "top-level worker isolation");
        AssertContains(coordinator, "unsupported host: full-library assessment requires isolated workers", "coordinator unsupported-host stop");
        AssertContains(coordinator, "decision-guidance.md", "coordinator decision guidance");
        AssertContains(coordinator, "reconcile", "coordinator interruption recovery");

        AssertContains(worker, "user-invocable: false", "worker invocation");
        AssertContains(worker, "selected as the top-level agent", "top-level worker requirement");
        AssertContains(worker, "A package unit may have", "worker empty package input");
        AssertContains(worker, "activation_method=explicit-file", "worker explicit file activation receipt");
        AssertContains(worker, "Do not invoke an unqualified `blazor-component-readiness` skill by name", "worker source-first activation");
        AssertContains(worker, "absolute trusted plugin root", "worker trusted plugin context");
        AssertContains(worker, "permissions or content exclusion", "worker denial boundary");
        AssertContains(worker, "unsupported host: readiness worker requires a top-level writable session", "nested worker stop");
        Assert(Regex.IsMatch(worker, @"(?m)^tools:\s*\[(?!\s*\])"), "worker tools must be non-empty");
        AssertContains(worker, "exactly one coordinator-assigned", "worker single-unit scope");
        AssertContains(worker, "Do not discover or add components", "worker scope prohibition");
        AssertContains(worker, "every claimed render mode", "worker mode coverage");
        AssertContains(worker, "Missing supplied probe results are work to perform", "active evidence collection");
        AssertContains(worker, "`RepositoryUrl` is not `ProjectUrl`", "distinct metadata fields");
        AssertContains(worker, "Absence of a feature claim does not establish absence of the feature", "conditional applicability evidence");
        AssertContains(worker, "only when the requested investigation and final verification are finished", "meaningful worker completion");
        AssertContains(worker, "Do not use a blanket not-tested assignment as the final assessment.", "blanket placeholder rejection");
        Assert(!NormalizeWhitespace(worker).Contains(
            "For a complete validated revision, return `blockers: []`", StringComparison.Ordinal),
            "structural validation alone must not authorize completed handoff");
        AssertContains(worker, "comparison inputs-validate", "blind worker input gate");
        AssertContains(worker, "browser interop, styles/assets, tests, and samples", "worker source closure");
        AssertContains(worker, "`source-proof-v1`", "worker structured source proof");
        AssertContains(worker, "`public-absence-v1`", "worker public absence proof");
        AssertContains(worker, "`direct-failure-v1`", "worker direct failure proof");
        AssertContains(worker, "privileged job that executes source build steps", "worker release job trust boundary");
        AssertContains(worker, "one mutable workspace path", "worker immutable artifact boundary");
        AssertContains(worker, "component-owned assignment through a public `[Parameter]` setter", "worker parameter mutation boundary");
        AssertContains(worker, "require direct descendant render evidence for a gap", "worker cascading rerender measurement boundary");
        AssertContains(worker, "unit_id:", "worker handoff unit");
        AssertContains(worker, "revision_path:", "worker handoff revision");
        AssertContains(worker, "report_path:", "worker handoff report");
        AssertContains(worker, "validation_manifest_path:", "worker handoff manifest");
        AssertContains(worker, "validation_manifest_sha256:", "worker handoff digest");
        AssertContains(worker, "blockers:", "worker handoff blockers");
        AssertContains(worker, "Never modify reviewed source, inventory, sibling artifacts, or remotes.", "worker mutation boundary");
    }

    private static void AssertContracts(string referencesRoot)
    {
        var feedback = File.ReadAllText(Path.Combine(referencesRoot, "feedback-contract.md"));
        AssertContains(feedback, "# Assessment feedback", "feedback heading");
        AssertContains(feedback, "| Requirement IDs | Feedback |", "feedback header");
        AssertContains(feedback, "raw feedback cell payload is rendered verbatim", "feedback preservation");
        AssertContains(feedback, "never creates, rewrites, normalizes, or deletes it", "feedback ownership");

        var report = File.ReadAllText(Path.Combine(referencesRoot, "report-contract.md"));
        AssertContains(report, "| ID | Scope | Area | Requirement | Status | Factual observation | Evidence and provenance | Owner action | Assessment follow-up / rationale |", "report table contract");
        AssertContains(report, "Source validation manifest SHA-256:", "guidance digest header");
        AssertContains(report, "outside `revisions/`", "guidance placement");
        AssertContains(report, "unbound, regenerable", "guidance binding boundary");
        AssertContains(report, "Replace it only after another explicit guidance request.", "guidance replacement");
        AssertContains(report, "Schema-version-1 assessments remain parseable and verifiable", "legacy assessment policy");

        var status = File.ReadAllText(Path.Combine(referencesRoot, "status-boundaries.md"));
        AssertContains(status, "direct-evidence-satisfies", "verified decision boundary");
        AssertContains(status, "direct-evidence-conflicts", "gap decision boundary");
        AssertContains(status, "owner-held-evidence-only", "owner decision boundary");
        AssertContains(status, "applicable-evidence-not-obtained", "not-tested decision boundary");
        AssertContains(status, "confirmed-not-applicable", "not-applicable decision boundary");
        AssertContains(status, "New assessments use schema version 2", "current assessment schema");
        AssertContains(status, "Schema version 1 is retained only for immutable", "legacy assessment schema");
        AssertContains(status, "only one directed-gap protocol family", "directed-gap exclusivity");
        AssertContains(status, "A keyed reorder behavior probe passes", "mechanism/outcome boundary example");
        AssertContains(status, "confirmed complete public-policy corpus", "public-absence boundary example");

        var ciRelease = File.ReadAllText(Path.Combine(referencesRoot, "area-ci-release.md"));
        AssertContains(ciRelease, "actual release job graph", "CI-07 job graph rule");
        AssertContains(ciRelease, "path equality and in-place ordering are not an immutable handoff", "CI-08 path identity rule");

        var runtime = File.ReadAllText(Path.Combine(referencesRoot, "area-blazor-runtime.md"));
        AssertContains(runtime, "event handlers, callbacks, conditional branches", "BEQ-09 assignment coverage");

        var performance = File.ReadAllText(Path.Combine(referencesRoot, "area-trim-performance.md"));
        AssertContains(performance, "no repeated identity surface", "PERF-02 applicability boundary");
        AssertContains(performance, "missing `IsFixed` establishes an applicable rerender risk", "PERF-05 source risk boundary");
        AssertContains(performance, "Without descendant render counts", "PERF-05 measurement requirement");

        var provenance = File.ReadAllText(Path.Combine(referencesRoot, "area-provenance-integrity.md"));
        AssertContains(provenance, "For `PI-06`, `PI-07`, `PI-10`, and `PI-11`, publication is the required surface", "SBOM/provenance absence boundary");
        AssertContains(provenance, "the absence is direct evidence, not an unrun probe", "SBOM/provenance direct evidence");
        AssertContains(provenance, "For `PI-08` and `PI-09`, missing SBOM bytes alone are insufficient", "asset/notice representation boundary");

        var comparison = File.ReadAllText(Path.Combine(referencesRoot, "blinded-comparison.md"));
        AssertContains(comparison, "Schema version 2", "comparison schema version");
        AssertContains(comparison, "browser-interop-and-style-assets", "browser interop coverage");
        AssertContains(comparison, "performance-measurements", "performance coverage");
        AssertContains(comparison, "`browser-interop-source`", "typed browser interop role");
        AssertContains(comparison, "`component-source-closure`", "typed component source role");
        AssertContains(comparison, "`origin_kind`", "coverage provenance origin");
        AssertContains(comparison, "Schema-version-1 confirmed comparison manifests remain canonical", "legacy comparison gate");

        var library = File.ReadAllText(Path.Combine(referencesRoot, "library-assessment.md"));
        AssertContains(library, "append-only state receipt", "library state receipts");
        AssertContains(library, "`pending`, `active`, `completed`, `blocked`, or `incomplete`", "library states");
        AssertContains(library, "one top-level writable worker session per unit", "library isolation");
        AssertContains(library, "factual status counts", "factual library index");
        AssertContains(library, "current-generation.json", "generation index publication");
        AssertContains(library, "compatibility caches", "index cache recovery");

        var workerExecution = File.ReadAllText(Path.Combine(referencesRoot, "worker-execution.md"));
        AssertContains(workerExecution, "Nested custom agents are text-only", "nested agent boundary");
        AssertContains(workerExecution, "complete", "complete file activation");
        AssertContains(workerExecution, "Record the activation method", "activation receipt");
        AssertContains(workerExecution, "cd \"$UNIT\"", "launch directory setup");
        AssertContains(workerExecution, "export PWD=\"$UNIT\" TMPDIR=\"$UNIT/tmp\"", "unit-local PWD/TMPDIR setup");
        AssertContains(workerExecution, "--effort <owner-approved-effort>", "explicit effort");
        AssertContains(workerExecution, "set inherited `PWD` to that same absolute path", "cwd/PWD alignment");
        AssertContains(workerExecution, "Invoke `copilot` from `PATH`", "PATH launcher");
        AssertContains(workerExecution, "--session-id <new-session-uuid>", "native session identity");
        AssertContains(workerExecution, "--log-dir \"$UNIT/logs\"", "native log directory");
        AssertContains(workerExecution, "tool-call IDs/results", "raw tool receipt");
        AssertContains(workerExecution, "--agent <plugin-name>:blazor-component-readiness-worker", "qualified CLI worker");
        AssertContains(workerExecution, "prepare-worker-launch.sh", "validated worker launch helper");
        AssertContains(workerExecution, "use both `--plugin-dir \"$CLI_PLUGIN_DIR\"` and the generated `WORKER_PROMPT_FILE`", "shared plugin root handoff");
        AssertContains(workerExecution, "set -euo pipefail", "preparation failure stops launch");
        AssertContains(workerExecution, "-p \"$(cat \"$WORKER_PROMPT_FILE\")\"", "generated prompt used in launch");
        Assert(!workerExecution.Contains("-p <bounded-worker-prompt>", StringComparison.Ordinal), "no independent prompt launch recipe");
        AssertContains(
            File.ReadAllText(Path.Combine(referencesRoot, "..", "..", "..", "agents", "blazor-component-readiness.agent.md")),
            "prepare-worker-launch.sh",
            "coordinator uses shipped launch contract");
        AssertContains(workerExecution, "Never add `--allow-all-paths`", "worker path sandbox");
        AssertContains(workerExecution, "Recomputes the validation-manifest SHA-256", "worker digest acceptance");
        AssertContains(workerExecution, "resolve returned paths to absolute paths", "cross-root verification");
        AssertContains(workerExecution, "accessible requested probes were never attempted is unfinished work", "unattempted coverage rejection");
    }

    private static void AssertWorkerLaunchContract(string pluginRoot)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var helper = Path.Combine(
            pluginRoot,
            "skills",
            "blazor-component-readiness",
            "scripts",
            "prepare-worker-launch.sh");
        Assert(File.Exists(helper), "worker launch helper exists");

        var testRoot = Path.Combine(
            Directory.GetParent(pluginRoot)?.FullName
                ?? throw new InvalidOperationException("plugin parent is required"),
            $"readiness worker launch {Guid.NewGuid():N}");
        var unitRoot = Path.Combine(testRoot, "unit");
        var relocatedPlugin = Path.Combine(unitRoot, "tooling", "relocated-plugin");
        var outsidePlugin = Path.Combine(testRoot, "outside-plugin");
        var promptFile = Path.Combine(unitRoot, "prompt.txt");
        var contractFile = Path.Combine(unitRoot, "launch.env");

        try
        {
            Directory.CreateDirectory(unitRoot);
            CopyDirectory(pluginRoot, relocatedPlugin);
            CopyDirectory(pluginRoot, outsidePlugin);
            File.WriteAllText(promptFile, "Run the assigned readiness worker.");

            var valid = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", "tooling/relocated-plugin",
                "--prompt-file", promptFile,
                "--output", contractFile);
            Assert(valid.ExitCode == 0, $"valid worker launch contract: {valid.StandardError}");

            var expectedRoot = Path.GetFullPath(relocatedPlugin);
            var sourced = SourceContract(contractFile);
            Assert(sourced[0] == expectedRoot, "worker plugin root is absolute");
            Assert(sourced[1] == expectedRoot, "CLI and worker roots are identical");
            var generatedPrompt = File.ReadAllText(sourced[2]);
            var expectedSkill = Path.Combine(
                expectedRoot,
                "skills",
                "blazor-component-readiness",
                "SKILL.md");
            Assert(
                generatedPrompt.Contains($"Authoritative bundled skill source: {expectedSkill}", StringComparison.Ordinal),
                "worker prompt names exact staged skill source");
            Assert(
                generatedPrompt.Contains("load the complete authoritative bundled skill source above first", StringComparison.Ordinal),
                "worker prompt requires source-first activation");
            Assert(
                generatedPrompt.Contains("Do not invoke an unqualified registered skill by name", StringComparison.Ordinal),
                "worker prompt avoids ambiguous global lookup");
            Assert(
                !generatedPrompt.Contains("host-registered", StringComparison.OrdinalIgnoreCase) &&
                !generatedPrompt.Contains("Skill not found", StringComparison.OrdinalIgnoreCase),
                "worker prompt does not make explicit-root activation depend on lookup results");

            var missing = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", "tooling/missing-plugin",
                "--prompt-file", promptFile,
                "--output", Path.Combine(unitRoot, "missing.env"));
            Assert(missing.ExitCode != 0 && missing.StandardError.Contains("does not exist", StringComparison.Ordinal), "missing plugin rejected before launch");

            var outside = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", outsidePlugin,
                "--prompt-file", promptFile,
                "--output", Path.Combine(unitRoot, "outside.env"));
            Assert(outside.ExitCode != 0 && outside.StandardError.Contains("inside worker unit", StringComparison.Ordinal), "out-of-unit plugin rejected before launch");

            var outsideOutput = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", Path.GetFullPath(relocatedPlugin),
                "--prompt-file", promptFile,
                "--output", Path.Combine(testRoot, "outside.env"));
            Assert(outsideOutput.ExitCode != 0 && outsideOutput.StandardError.Contains("inside worker unit", StringComparison.Ordinal), "out-of-unit output rejected before launch");

            var missingOutputDirectory = Path.Combine(testRoot, "outside-missing");
            var missingOutput = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", relocatedPlugin,
                "--prompt-file", promptFile,
                "--output", Path.Combine(missingOutputDirectory, "launch.env"));
            Assert(missingOutput.ExitCode != 0, "missing output parent rejected");
            Assert(!Directory.Exists(missingOutputDirectory), "rejected output does not create outside directory");

            var originalPrompt = File.ReadAllText(promptFile);
            var collidingPrompt = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", Path.GetFullPath(relocatedPlugin),
                "--prompt-file", promptFile,
                "--output", promptFile);
            Assert(collidingPrompt.ExitCode != 0 && collidingPrompt.StandardError.Contains("overwrite the worker prompt", StringComparison.Ordinal), "worker prompt is protected from overwrite");
            Assert(File.ReadAllText(promptFile) == originalPrompt, "rejected output leaves worker prompt unchanged");

            var generatedPromptPath = Path.Combine(unitRoot, "worker-prompt.txt");
            var collidingGeneratedPrompt = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", Path.GetFullPath(relocatedPlugin),
                "--prompt-file", promptFile,
                "--output", generatedPromptPath);
            Assert(collidingGeneratedPrompt.ExitCode != 0 && collidingGeneratedPrompt.StandardError.Contains("generated worker prompt", StringComparison.Ordinal), "generated worker prompt is protected from overwrite");
            Assert(File.ReadAllText(promptFile) == originalPrompt, "rejected generated-prompt collision leaves input unchanged");

            File.WriteAllText(generatedPromptPath, originalPrompt);
            var generatedPromptBefore = File.ReadAllText(generatedPromptPath);
            var collidingInput = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", relocatedPlugin,
                "--prompt-file", generatedPromptPath,
                "--output", contractFile);
            Assert(collidingInput.ExitCode != 0, "generated prompt cannot be reused as base input");
            Assert(File.ReadAllText(generatedPromptPath) == generatedPromptBefore, "rejected input collision leaves generated prompt unchanged");

            File.WriteAllText(promptFile, $"Trusted plugin root: {outsidePlugin}");
            var mismatched = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", relocatedPlugin,
                "--prompt-file", promptFile,
                "--output", Path.Combine(unitRoot, "mismatched.env"));
            Assert(mismatched.ExitCode != 0 && mismatched.StandardError.Contains("independent plugin root", StringComparison.Ordinal), "absolute mismatched worker root rejected");
            Assert(!File.Exists(Path.Combine(unitRoot, "mismatched.env")), "mismatched handoff produces no contract");

            File.WriteAllText(promptFile, "Plugin root tooling/dotnet-blazor; use fallback if no skill.");
            var relative = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", Path.GetFullPath(relocatedPlugin),
                "--prompt-file", promptFile,
                "--output", Path.Combine(unitRoot, "relative.env"));
            Assert(relative.ExitCode != 0 && relative.StandardError.Contains("independent plugin root", StringComparison.Ordinal), "relative worker root rejected");
            Assert(!File.Exists(Path.Combine(unitRoot, "relative.env")), "relative handoff produces no contract");

            File.WriteAllText(promptFile, originalPrompt);
            var stagedSkill = Path.Combine(relocatedPlugin, "skills", "blazor-component-readiness", "SKILL.md");
            File.Delete(stagedSkill);
            var missingSkill = RunHelper(
                helper,
                "--unit", unitRoot,
                "--plugin-dir", relocatedPlugin,
                "--prompt-file", promptFile,
                "--output", Path.Combine(unitRoot, "missing-skill.env"));
            Assert(missingSkill.ExitCode != 0 && missingSkill.StandardError.Contains("missing blazor-component-readiness SKILL.md", StringComparison.Ordinal), "missing bundled skill rejected");
        }
        finally
        {
            if (Directory.Exists(testRoot))
            {
                Directory.Delete(testRoot, recursive: true);
            }
        }
    }

    private static void AssertReadinessLauncherExample(string skillRoot)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var skill = File.ReadAllText(Path.Combine(skillRoot, "SKILL.md")).Replace("\r\n", "\n", StringComparison.Ordinal);
        var functionStart = skill.IndexOf("readiness()\n{", StringComparison.Ordinal);
        Assert(functionStart >= 0, "documented readiness function exists");
        var functionEnd = skill.IndexOf("\n}", functionStart, StringComparison.Ordinal);
        Assert(functionEnd > functionStart, "documented readiness function closes");
        var function = skill[functionStart..(functionEnd + 2)];
        var testRoot = Path.Combine(Path.GetTempPath(), $"readiness launcher example {Guid.NewGuid():N}");
        var outputRoot = Path.Combine(testRoot, "output root with spaces");
        var validatorRoot = Path.Combine(testRoot, "validator root with spaces");
        var validatorDirectory = Path.Combine(validatorRoot, "scripts", "validator");
        var stub = Path.Combine(validatorDirectory, "run-validator.sh");
        var script = Path.Combine(testRoot, "invoke readiness.sh");
        var result = Path.Combine(outputRoot, "result.txt");

        try
        {
            Directory.CreateDirectory(validatorDirectory);
            Directory.CreateDirectory(outputRoot);
            File.WriteAllText(
                stub,
                """
                #!/usr/bin/env bash
                set -euo pipefail
                printf 'temp=%s\nargc=%s\n' "$READINESS_TEMP" "$#" > "$RESULT_FILE"
                for argument in "$@"; do
                  printf '<%s>\n' "$argument" >> "$RESULT_FILE"
                done
                exit 7
                """);
            File.WriteAllText(
                script,
                $$"""
                set -euo pipefail
                SKILL_DIR="$1"
                OUTPUT="$2"
                export RESULT_FILE="$3"
                shift 3
                mkdir -p "$OUTPUT/.validator-cache"
                {{function}}
                readiness "$@"
                """);

            var invocation = RunHelper(
                script,
                validatorRoot,
                outputRoot,
                result,
                "arg with spaces",
                "literal $dollar and apostrophe '");
            Assert(invocation.ExitCode == 7, "readiness forwards nonzero exit code");
            Assert(invocation.StandardError == string.Empty, "readiness example has no shell error");
            var lines = File.ReadAllLines(result);
            Assert(
                Path.Combine(outputRoot, ".validator-cache") == lines[0]["temp=".Length..],
                "readiness forwards environment value");
            Assert(lines[1] == "argc=2", "readiness forwards argument count");
            Assert(lines[2] == "<arg with spaces>", "readiness preserves spaced argument");
            Assert(lines[3] == "<literal $dollar and apostrophe '>", "readiness preserves literal argument");
        }
        finally
        {
            if (Directory.Exists(testRoot))
            {
                Directory.Delete(testRoot, recursive: true);
            }
        }
    }

    private static ProcessResult RunHelper(string helper, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("/bin/bash")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add(helper);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("could not start worker launch helper");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return new ProcessResult(
            process.ExitCode,
            standardOutput.GetAwaiter().GetResult(),
            standardError.GetAwaiter().GetResult());
    }

    private static string[] SourceContract(string contract)
    {
        var startInfo = new ProcessStartInfo("/bin/bash")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(". \"$1\"; printf '%s\\n' \"$PLUGIN_ROOT\" \"$CLI_PLUGIN_DIR\" \"$WORKER_PROMPT_FILE\"");
        startInfo.ArgumentList.Add("source-contract");
        startInfo.ArgumentList.Add(contract);

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("could not source worker launch contract");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        var output = standardOutput.GetAwaiter().GetResult();
        var error = standardError.GetAwaiter().GetResult();
        Assert(process.ExitCode == 0, $"sourcing worker launch contract: {error}");
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.GetFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        }

        foreach (var directory in Directory.GetDirectories(source))
        {
            CopyDirectory(directory, Path.Combine(destination, Path.GetFileName(directory)));
        }
    }

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

    private static void AssertContains(string value, string expected, string name) =>
        Assert(
            NormalizeWhitespace(value).Contains(NormalizeWhitespace(expected), StringComparison.Ordinal),
            $"{name} is missing '{expected}'");

    private static string NormalizeWhitespace(string value) =>
        Regex.Replace(value, @"\s+", " ").Trim();

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
