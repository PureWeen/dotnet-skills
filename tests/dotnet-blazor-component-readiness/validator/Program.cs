using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

var root = FindRepositoryRoot();
var plugin = Path.Combine(root, "plugins", "dotnet-blazor-component-readiness");
var references = Path.Combine(plugin, "skills", "blazor-component-readiness", "references");

using var rubricDocument = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(references, "rubric.json")));
var rubric = rubricDocument.RootElement;
var core = rubric.GetProperty("core").GetProperty("requirements").EnumerateArray().ToArray();
var overlays = rubric.GetProperty("overlays").EnumerateArray().ToArray();

AssertEqual(1, rubric.GetProperty("schema_version").GetInt32(), "rubric schema version");
AssertEqual("1.3.0", rubric.GetProperty("rubric_version").GetString(), "rubric version");
AssertEqual(1, rubric.GetProperty("scope_schema_version").GetInt32(), "scope schema version");
AssertEqual(
    "A public, versioned vendor self-assessment baseline. It is not certification or a Microsoft acceptance requirement.",
    rubric.GetProperty("positioning").GetString(),
    "non-certification positioning");

var expectedStatuses = new[]
{
    "verified",
    "gap",
    "owner evidence required",
    "not tested",
    "not applicable"
};
AssertSequence(expectedStatuses, Strings(rubric.GetProperty("statuses")), "status vocabulary");

var expectedCoreIds = Expand(
    ("LP", 10),
    ("PI", 12),
    ("SEC", 13),
    ("A11Y", 12),
    ("BEQ", 24),
    ("TA", 8),
    ("PERF", 10),
    ("CI", 11),
    ("SUP", 10));
AssertSequence(expectedCoreIds, core.Select(Id), "110 core IDs and canonical order");
AssertEqual(110, core.Length, "core requirement count");

var expectedRepositoryWide = new HashSet<string>(StringComparer.Ordinal)
{
    "LP-01", "LP-02", "LP-03", "LP-04", "LP-05", "LP-06", "LP-07", "LP-08", "LP-09", "LP-10",
    "PI-01", "PI-02", "PI-03", "PI-04", "PI-05", "PI-06", "PI-07", "PI-08", "PI-09", "PI-10", "PI-11", "PI-12",
    "SEC-04", "SEC-05", "SEC-06", "SEC-07", "SEC-08", "SEC-09",
    "BEQ-21", "BEQ-24",
    "TA-07", "TA-08",
    "CI-01", "CI-05", "CI-06", "CI-07", "CI-08",
    "SUP-01", "SUP-02", "SUP-03", "SUP-04", "SUP-05", "SUP-06", "SUP-07", "SUP-08", "SUP-10"
};
var actualRepositoryWide = core
    .Where(requirement => Scope(requirement) == "repository-wide")
    .Select(Id)
    .ToHashSet(StringComparer.Ordinal);
AssertSet(expectedRepositoryWide, actualRepositoryWide, "46 repository-wide IDs");
AssertEqual(46, actualRepositoryWide.Count, "repository-wide requirement count");

var expectedComponentSpecific = expectedCoreIds
    .Where(id => !expectedRepositoryWide.Contains(id))
    .ToHashSet(StringComparer.Ordinal);
var actualComponentSpecific = core
    .Where(requirement => Scope(requirement) == "component-specific")
    .Select(Id)
    .ToHashSet(StringComparer.Ordinal);
AssertSet(expectedComponentSpecific, actualComponentSpecific, "64 component-specific IDs");
AssertEqual(64, actualComponentSpecific.Count, "component-specific requirement count");
AssertEqual(
    "bca63be737c7a02d56bc40387ca1e56b1e07ce6dd7146e5b6bfa9fa165045382",
    RequirementDigest(core, includeScope: true),
    "core ID, wording, and scope digest");

AssertEqual(2, overlays.Length, "overlay count");
AssertOverlay(
    overlays[0],
    "scaffolder",
    "Scaffolder readiness overlay",
    "1.0.0",
    Expand(("SCF", 6)),
    "6f7699d61df9350f7d718551178753cdc1c4637245794767bbd02f68c51ab063");
AssertOverlay(
    overlays[1],
    "ai-skill",
    "AI-skill readiness overlay",
    "1.0.0",
    Expand(("AI", 6)),
    "a88cdbd85879b841d131de95a3e1ba5056839a655e3cfc39b9368e0ec69b43ab");

AssertSequence(expectedCoreIds, SelectIds(core, overlays, []), "core-only overlay selection");
AssertSequence(
    expectedCoreIds.Concat(Expand(("SCF", 6))),
    SelectIds(core, overlays, ["scaffolder"]),
    "scaffolder-only selection");
AssertSequence(
    expectedCoreIds.Concat(Expand(("AI", 6))),
    SelectIds(core, overlays, ["ai-skill"]),
    "AI-skill-only selection");
AssertSequence(
    expectedCoreIds.Concat(Expand(("SCF", 6))).Concat(Expand(("AI", 6))),
    SelectIds(core, overlays, ["scaffolder", "ai-skill"]),
    "both-overlay selection");

var checklistPath = Path.Combine(references, "checklist.md");
AssertEqual(RenderChecklist(rubric), File.ReadAllText(checklistPath), "rubric/checklist generated-view parity");

var manifestPaths = new[]
{
    Path.Combine(plugin, "plugin.json"),
    Path.Combine(plugin, ".claude-plugin", "plugin.json"),
    Path.Combine(plugin, ".codex-plugin", "plugin.json")
};
var manifestBytes = manifestPaths.Select(File.ReadAllBytes).ToArray();
Assert(manifestBytes.Skip(1).All(bytes => bytes.SequenceEqual(manifestBytes[0])), "plugin manifests must be byte-identical");
using (var manifest = JsonDocument.Parse(manifestBytes[0]))
{
    AssertEqual("dotnet-blazor-component-readiness", manifest.RootElement.GetProperty("name").GetString(), "plugin name");
    AssertEqual("0.1.0", manifest.RootElement.GetProperty("version").GetString(), "initial plugin version");
    AssertSequence(
        ["./agents/blazor-component-readiness.agent.md", "./agents/blazor-component-readiness-worker.agent.md"],
        Strings(manifest.RootElement.GetProperty("agents")),
        "plugin agents");
}

using (var version = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(plugin, "version.json"))))
{
    AssertEqual("0.1", version.RootElement.GetProperty("version").GetString(), "version base");
    AssertSequence(
        [".", ":!plugin.json", ":!.codex-plugin/plugin.json", ":!.claude-plugin/plugin.json", ":!version.json"],
        Strings(version.RootElement.GetProperty("pathFilters")),
        "canonical version path filters");
}

const string marketplaceDescription =
    "Vendor self-assessment for released or release-candidate Blazor component packages using a versioned public rubric and local deterministic validation.";
var marketplacePaths = new[]
{
    Path.Combine(root, ".github", "plugin", "marketplace.json"),
    Path.Combine(root, ".claude-plugin", "marketplace.json"),
    Path.Combine(root, ".cursor-plugin", "marketplace.json"),
    Path.Combine(root, ".agents", "plugins", "marketplace.json")
};
foreach (var marketplacePath in marketplacePaths)
{
    using var marketplace = JsonDocument.Parse(File.ReadAllBytes(marketplacePath));
    var entries = marketplace.RootElement.GetProperty("plugins").EnumerateArray()
        .Where(entry => entry.GetProperty("name").GetString() == "dotnet-blazor-component-readiness")
        .ToArray();
    AssertEqual(1, entries.Length, $"marketplace entry count in {marketplacePath}");
    AssertEqual("./plugins/dotnet-blazor-component-readiness", entries[0].GetProperty("source").GetString(), "marketplace source");
    AssertEqual(marketplaceDescription, entries[0].GetProperty("description").GetString(), "marketplace description");
}

Assert(
    File.ReadAllText(Path.Combine(root, "README.md")).Contains(
        $"| [dotnet-blazor-component-readiness](plugins/dotnet-blazor-component-readiness/) | {marketplaceDescription} |",
        StringComparison.Ordinal),
    "README plugin row");
var codeowners = File.ReadAllText(Path.Combine(root, ".github", "CODEOWNERS"));
Assert(codeowners.Contains("/plugins/dotnet-blazor-component-readiness/ @dotnet/aspnet", StringComparison.Ordinal), "plugin CODEOWNERS entry");
Assert(codeowners.Contains("/tests/dotnet-blazor-component-readiness/ @dotnet/aspnet", StringComparison.Ordinal), "tests CODEOWNERS entry");

var worker = File.ReadAllText(Path.Combine(plugin, "agents", "blazor-component-readiness-worker.agent.md"));
Assert(
    Regex.IsMatch(worker, @"(?m)^tools:\s*\[(?!\s*\])"),
    "nested worker tools frontmatter must be present and non-empty");

FoundationTests.Run(root, plugin);
EvidenceTests.Run(root, plugin);

Console.WriteLine("All Blazor component readiness Commit 1 through Commit 3 tests passed.");

static string FindRepositoryRoot()
{
    var configuredRoot = Environment.GetEnvironmentVariable("READINESS_REPOSITORY_ROOT");
    if (!string.IsNullOrWhiteSpace(configuredRoot) && IsRepositoryRoot(configuredRoot))
    {
        return Path.GetFullPath(configuredRoot);
    }

    foreach (var start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
    {
        for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
        {
            if (IsRepositoryRoot(directory.FullName))
            {
                return directory.FullName;
            }
        }
    }

    throw new InvalidOperationException("Could not locate the repository root.");
}

static bool IsRepositoryRoot(string path) =>
    File.Exists(Path.Combine(path, "README.md")) &&
    Directory.Exists(Path.Combine(path, "plugins")) &&
    Directory.Exists(Path.Combine(path, "tests"));

static string[] Expand(params (string Prefix, int Count)[] groups) =>
    groups.SelectMany(group => Enumerable.Range(1, group.Count).Select(number => $"{group.Prefix}-{number:00}")).ToArray();

static string[] Strings(JsonElement array) =>
    array.EnumerateArray().Select(item => item.GetString() ?? throw new InvalidDataException("Expected a string.")).ToArray();

static string Id(JsonElement requirement) =>
    requirement.GetProperty("id").GetString() ?? throw new InvalidDataException("Requirement ID is missing.");

static string Requirement(JsonElement requirement) =>
    requirement.GetProperty("requirement").GetString() ?? throw new InvalidDataException("Requirement wording is missing.");

static string Scope(JsonElement requirement) =>
    requirement.GetProperty("scope").GetString() ?? throw new InvalidDataException("Requirement scope is missing.");

static string RequirementDigest(IEnumerable<JsonElement> requirements, bool includeScope)
{
    var projection = string.Concat(requirements.Select(requirement =>
        includeScope
            ? $"{Id(requirement)}\t{Requirement(requirement)}\t{Scope(requirement)}\n"
            : $"{Id(requirement)}\t{Requirement(requirement)}\n"));
    return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(projection)));
}

static void AssertOverlay(
    JsonElement overlay,
    string id,
    string name,
    string version,
    IReadOnlyList<string> expectedIds,
    string expectedDigest)
{
    AssertEqual(id, overlay.GetProperty("id").GetString(), $"{id} overlay ID");
    AssertEqual(name, overlay.GetProperty("name").GetString(), $"{id} overlay name");
    AssertEqual(version, overlay.GetProperty("version").GetString(), $"{id} overlay version");
    AssertEqual("explicit", overlay.GetProperty("selection").GetString(), $"{id} overlay selection");
    var requirements = overlay.GetProperty("requirements").EnumerateArray().ToArray();
    AssertSequence(expectedIds, requirements.Select(Id), $"{id} overlay IDs");
    AssertEqual(6, requirements.Length, $"{id} overlay requirement count");
    AssertEqual(expectedDigest, RequirementDigest(requirements, includeScope: false), $"{id} ID and wording digest");
}

static IEnumerable<string> SelectIds(
    IEnumerable<JsonElement> core,
    IEnumerable<JsonElement> overlays,
    IReadOnlyCollection<string> selectedOverlayIds)
{
    foreach (var requirement in core)
    {
        yield return Id(requirement);
    }

    foreach (var overlay in overlays.Where(overlay =>
                 selectedOverlayIds.Contains(overlay.GetProperty("id").GetString()!, StringComparer.Ordinal)))
    {
        foreach (var requirement in overlay.GetProperty("requirements").EnumerateArray())
        {
            yield return Id(requirement);
        }
    }
}

static string RenderChecklist(JsonElement rubric)
{
    var lines = new List<string>
    {
        "<!-- Generated from rubric.json. Do not edit by hand. -->",
        "# Blazor component readiness checklist",
        "",
        $"**Rubric version:** {rubric.GetProperty("rubric_version").GetString()}",
        $"**Scope schema version:** {rubric.GetProperty("scope_schema_version").GetInt32()}",
        "",
        rubric.GetProperty("positioning").GetString()!,
        "",
        "## Status vocabulary",
        ""
    };
    lines.AddRange(Strings(rubric.GetProperty("statuses")).Select(status => $"- `{status}`"));

    string? currentArea = null;
    foreach (var requirement in rubric.GetProperty("core").GetProperty("requirements").EnumerateArray())
    {
        var area = requirement.GetProperty("area").GetString();
        if (area != currentArea)
        {
            lines.Add("");
            lines.Add($"## {area}");
            lines.Add("");
            currentArea = area;
        }

        lines.Add($"- **{Id(requirement)}** (`{Scope(requirement)}`) {Requirement(requirement)}");
    }

    foreach (var overlay in rubric.GetProperty("overlays").EnumerateArray())
    {
        lines.Add("");
        lines.Add($"## Optional overlay: {overlay.GetProperty("name").GetString()}");
        lines.Add("");
        lines.Add($"**Overlay ID:** `{overlay.GetProperty("id").GetString()}`");
        lines.Add($"**Overlay version:** {overlay.GetProperty("version").GetString()}");
        lines.Add("**Selection:** Explicit only");
        lines.Add("");
        lines.AddRange(overlay.GetProperty("requirements").EnumerateArray()
            .Select(requirement => $"- **{Id(requirement)}** {Requirement(requirement)}"));
    }

    return string.Join('\n', lines) + '\n';
}

static void AssertSet(IReadOnlySet<string> expected, IReadOnlySet<string> actual, string name)
{
    Assert(
        expected.SetEquals(actual),
        $"{name} mismatch. Expected [{string.Join(", ", expected.Order())}], actual [{string.Join(", ", actual.Order())}].");
}

static void AssertSequence<T>(IEnumerable<T> expected, IEnumerable<T> actual, string name)
{
    var expectedArray = expected.ToArray();
    var actualArray = actual.ToArray();
    Assert(
        expectedArray.SequenceEqual(actualArray),
        $"{name} mismatch. Expected [{string.Join(", ", expectedArray)}], actual [{string.Join(", ", actualArray)}].");
}

static void AssertEqual<T>(T expected, T actual, string name) =>
    Assert(EqualityComparer<T>.Default.Equals(expected, actual), $"{name}: expected '{expected}', actual '{actual}'.");

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
