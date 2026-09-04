using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.IO;

namespace BlazorComponentReadiness.Validator.Validation;

public static class RubricLoader
{
    private const string ExpectedRubricDigest =
        "6a36fc581af3a2710fec3a70a484c7dc751cdf2c248dcd98e49ce4bb9cf8c49f";
    private const string ExpectedCoreDigest =
        "bca63be737c7a02d56bc40387ca1e56b1e07ce6dd7146e5b6bfa9fa165045382";
    private const string ExpectedScopeDigest =
        "023a6204a20be9a6558cdba8b284a1729ffe0439781c1c73b94d577fe66279d5";
    private static readonly string[] ExpectedStatuses =
    [
        "verified",
        "gap",
        "owner evidence required",
        "not tested",
        "not applicable"
    ];

    public static RubricContract Load()
    {
        var rubricPath = ResolveRubricPath();
        var bytes = BoundedIO.ReadAllBytes(
            rubricPath,
            ResourceLimits.SerializedArtifactBytes,
            "rubric");
        using var document = StrictJson.Parse(bytes, ResourceLimits.SerializedArtifactBytes, "rubric");
        var root = document.RootElement;
        ContractJson.RequireProperties(
            root,
            "schema_version",
            "rubric_version",
            "scope_schema_version",
            "positioning",
            "statuses",
            "core",
            "overlays");
        if (ContractJson.Int32(root, "schema_version") != 1)
        {
            throw new DeterministicValidationException("Rubric schema_version must be 1.");
        }

        var statuses = ContractJson.StringArray(root, "statuses");
        if (!statuses.SequenceEqual(ExpectedStatuses, StringComparer.Ordinal))
        {
            throw new DeterministicValidationException("Rubric status vocabulary has drifted.");
        }

        var coreObject = ContractJson.Object(root, "core");
        ContractJson.RequireProperties(coreObject, "name", "requirements");
        _ = ContractJson.NormalizeText(ContractJson.String(coreObject, "name"), "rubric core name", 256);
        var core = ContractJson.Array(coreObject, "requirements")
            .EnumerateArray()
            .Select(ParseCoreRequirement)
            .ToArray();
        if (core.Length != 110 ||
            core.Count(requirement => requirement.Scope == "repository-wide") != 46 ||
            core.Count(requirement => requirement.Scope == "component-specific") != 64 ||
            core.Select(requirement => requirement.Id).Distinct(StringComparer.Ordinal).Count() != 110)
        {
            throw new DeterministicValidationException("Rubric must contain canonical 110/46/64 core ownership.");
        }

        var overlays = ContractJson.Array(root, "overlays")
            .EnumerateArray()
            .Select(ParseOverlay)
            .ToArray();
        if (!overlays.Select(overlay => overlay.Id)
                .SequenceEqual(new[] { "scaffolder", "ai-skill" }, StringComparer.Ordinal))
        {
            throw new DeterministicValidationException("Rubric overlays must be scaffolder then ai-skill.");
        }

        var rubricDigest = ContractJson.RawDigest(bytes);
        var coreDigest = ProjectionDigest(core, includeScope: true);
        var scopeDigest = ScopeDigest(core);
        if (rubricDigest.Value != ExpectedRubricDigest ||
            coreDigest.Value != ExpectedCoreDigest ||
            scopeDigest.Value != ExpectedScopeDigest)
        {
            throw new DeterministicValidationException(
                "Rubric/checklist contract digest has drifted from the frozen public-v1 baseline.");
        }

        return new RubricContract(
            ContractJson.String(root, "rubric_version"),
            ContractJson.Int32(root, "scope_schema_version"),
            ContractJson.String(root, "positioning"),
            statuses,
            rubricDigest,
            coreDigest,
            scopeDigest,
            core,
            overlays);
    }

    public static IReadOnlyList<RubricRequirement> Select(
        RubricContract rubric,
        string kind,
        IReadOnlyList<string> selectedOverlays)
    {
        var core = kind switch
        {
            "unified" => rubric.CoreRequirements,
            "package" => rubric.CoreRequirements.Where(row => row.Scope == "repository-wide").ToArray(),
            "component" => rubric.CoreRequirements.Where(row => row.Scope == "component-specific").ToArray(),
            _ => throw new DeterministicValidationException($"Unknown assessment kind '{kind}'.")
        };
        var overlaySet = selectedOverlays.ToHashSet(StringComparer.Ordinal);
        if (overlaySet.Count != selectedOverlays.Count)
        {
            throw new DeterministicValidationException("Selected overlays cannot contain duplicates.");
        }

        var unknown = overlaySet.Except(rubric.Overlays.Select(overlay => overlay.Id), StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new DeterministicValidationException($"Unknown overlay '{unknown[0]}'.");
        }

        return core.Concat(rubric.Overlays
                .Where(overlay => overlaySet.Contains(overlay.Id))
                .SelectMany(overlay => overlay.Requirements))
            .ToArray();
    }

    private static string ResolveRubricPath()
    {
        var skillRoot = Environment.GetEnvironmentVariable("READINESS_SKILL_ROOT");
        if (string.IsNullOrWhiteSpace(skillRoot))
        {
            throw new DeterministicValidationException(
                "READINESS_SKILL_ROOT must identify the loaded blazor-component-readiness skill.");
        }

        var fullRoot = Path.GetFullPath(skillRoot);
        if (!File.Exists(Path.Combine(fullRoot, "SKILL.md")))
        {
            throw new DeterministicValidationException("READINESS_SKILL_ROOT does not contain SKILL.md.");
        }

        return SafePath.ResolveUnderRoot(
            fullRoot,
            "references/rubric.json",
            requireExisting: true,
            requireFile: true);
    }

    private static RubricRequirement ParseCoreRequirement(JsonElement element)
    {
        ContractJson.RequireProperties(element, "id", "requirement", "scope", "area");
        var scope = ContractJson.String(element, "scope");
        if (scope is not ("repository-wide" or "component-specific"))
        {
            throw new DeterministicValidationException($"Invalid rubric scope '{scope}'.");
        }

        return new RubricRequirement(
            ContractJson.NormalizeText(ContractJson.String(element, "id"), "requirement id", 16),
            ContractJson.NormalizeText(ContractJson.String(element, "requirement"), "requirement wording", 1024),
            scope,
            ContractJson.NormalizeText(ContractJson.String(element, "area"), "requirement area", 256),
            null);
    }

    private static RubricOverlay ParseOverlay(JsonElement element)
    {
        ContractJson.RequireProperties(element, "id", "name", "version", "selection", "requirements");
        var id = ContractJson.String(element, "id");
        if (ContractJson.String(element, "selection") != "explicit")
        {
            throw new DeterministicValidationException("Overlay selection must be explicit.");
        }

        var name = ContractJson.String(element, "name");
        var requirements = ContractJson.Array(element, "requirements").EnumerateArray().Select(row =>
        {
            ContractJson.RequireProperties(row, "id", "requirement");
            return new RubricRequirement(
                ContractJson.String(row, "id"),
                ContractJson.String(row, "requirement"),
                "overlay",
                name,
                id);
        }).ToArray();
        if (requirements.Length != 6)
        {
            throw new DeterministicValidationException($"Overlay '{id}' must contain six requirements.");
        }

        return new RubricOverlay(
            id,
            name,
            ContractJson.String(element, "version"),
            ProjectionDigest(requirements, includeScope: false),
            requirements);
    }

    private static Sha256Digest ProjectionDigest(
        IEnumerable<RubricRequirement> requirements,
        bool includeScope)
    {
        var projection = string.Concat(requirements.Select(requirement =>
            includeScope
                ? $"{requirement.Id}\t{requirement.Requirement}\t{requirement.Scope}\n"
                : $"{requirement.Id}\t{requirement.Requirement}\n"));
        return ContractJson.RawDigest(Encoding.UTF8.GetBytes(projection));
    }

    private static Sha256Digest ScopeDigest(IEnumerable<RubricRequirement> requirements)
    {
        var projection = string.Concat(requirements.Select(requirement =>
            $"{requirement.Id}\t{requirement.Scope}\n"));
        return ContractJson.RawDigest(Encoding.UTF8.GetBytes(projection));
    }
}
