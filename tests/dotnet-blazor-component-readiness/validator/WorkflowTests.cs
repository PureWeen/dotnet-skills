using System.Text.Json;
using System.Text.RegularExpressions;

internal static class WorkflowTests
{
    private static readonly string[] RequiredReferences =
    [
        "report-contract.md",
        "feedback-contract.md",
        "library-assessment.md",
        "artifact-acquisition.md",
        "documentation-discovery.md",
        "status-boundaries.md",
        "targeted-profiles.md",
        "learning-loop.md",
        "area-provenance-integrity.md",
        "area-security-privacy.md",
        "area-accessibility.md",
        "area-blazor-runtime.md",
        "area-trim-performance.md",
        "area-ci-release.md",
        "area-support-lifecycle.md",
        "area-conditional-families.md",
        "overlay-scaffolder.md",
        "overlay-ai-skill.md"
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
        AssertContains(skill, "110-row public baseline", "core count");
        AssertContains(skill, "46 `repository-wide` / 64 `component-specific`", "scope ownership");
        AssertContains(skill, "`source-available`, `closed-source`, or `unresolved`", "source availability");
        AssertContains(skill, "owner-supplied-internal-evidence", "owner evidence");
        AssertContains(skill, "owner-supplied-public-evidence", "public owner evidence");
        AssertContains(skill, "current-generation.json", "authoritative library index pointer");
        AssertContains(skill, "every claimed render mode", "render-mode coverage");
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
            "inputs discover",
            "inputs confirm",
            "inputs validate",
            "evidence ledger-build",
            "evidence ledger-validate",
            "evidence bundle",
            "assessment init --kind unified",
            "assessment init --kind package",
            "assessment init --kind component",
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
    }

    private static void AssertRubricIsSoleRequirementSource(string referencesRoot)
    {
        using var rubric = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(referencesRoot, "rubric.json")));
        var ids = rubric.RootElement.GetProperty("core").GetProperty("requirements")
            .EnumerateArray()
            .Select(row => row.GetProperty("id").GetString()!)
            .ToArray();
        Assert(ids.Length == 110, "rubric.json remains the sole 110-ID source");

        var checklist = File.ReadAllText(Path.Combine(referencesRoot, "checklist.md"));
        AssertContains(checklist, "Generated from rubric.json. Do not edit by hand.", "generated checklist marker");
        foreach (var path in Directory.GetFiles(referencesRoot, "*.md"))
        {
            if (Path.GetFileName(path) == "checklist.md")
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
                "--producer-validator",
                "PureWeen",
                "Infragistics",
                "Syncfusion"
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
        AssertContains(coordinator, "  - blazor-component-readiness-worker", "worker registration");
        AssertContains(coordinator, "ask_user", "confirmation tool");
        AssertContains(
            coordinator,
            "Inspect every supplied local artifact before asking for missing information",
            "local discovery before clarification");
        AssertContains(
            coordinator,
            "explicitly requests isolated delegation",
            "explicit single-unit worker override");
        foreach (var tool in new[]
        {
            "\"agent\"", "\"skill\"", "\"read\"", "\"search\"", "\"edit\"", "\"execute\"",
            "\"web_search\"", "\"web_fetch\"", "\"Task\"", "\"Skill\"", "\"Read\"", "\"Glob\"",
            "\"Grep\"", "\"Edit\"", "\"Write\"", "\"Bash\"", "\"read_file\"", "\"replace\"",
            "\"write_file\"", "\"glob\"", "\"grep_search\"", "\"run_shell_command\""
        })
        {
            AssertContains(coordinator, tool, $"coordinator tool {tool}");
        }

        AssertContains(coordinator, "exactly one `blazor-component-readiness-worker` for every confirmed package unit", "package-worker isolation");
        AssertContains(coordinator, "exactly one for", "component-worker isolation");
        AssertContains(coordinator, "unsupported host: full-library assessment requires isolated workers", "coordinator unsupported-host stop");
        AssertContains(coordinator, "decision-guidance.md", "coordinator decision guidance");
        AssertContains(coordinator, "reconcile", "coordinator interruption recovery");

        AssertContains(worker, "user-invocable: false", "worker invocation");
        Assert(Regex.IsMatch(worker, @"(?m)^tools:\s*\[(?!\s*\])"), "worker tools must be non-empty");
        AssertContains(worker, "exactly one coordinator-assigned", "worker single-unit scope");
        AssertContains(worker, "Do not discover or add components", "worker scope prohibition");
        AssertContains(worker, "every claimed render mode", "worker mode coverage");
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

        var library = File.ReadAllText(Path.Combine(referencesRoot, "library-assessment.md"));
        AssertContains(library, "append-only state receipt", "library state receipts");
        AssertContains(library, "`pending`, `active`, `completed`, `blocked`, or `incomplete`", "library states");
        AssertContains(library, "one isolated worker per unit", "library isolation");
        AssertContains(library, "factual status counts", "factual library index");
        AssertContains(library, "current-generation.json", "generation index publication");
        AssertContains(library, "compatibility caches", "index cache recovery");
    }

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
