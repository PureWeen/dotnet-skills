using System.Text.RegularExpressions;

namespace BlazorPackageResolver;

public sealed class Lp03DependencyLicensesResolver : IDeterministicResolver
{
    internal const string Contract =
        "The caller designates the bound raw SBOM as the authoritative release-wide inventory; " +
        "structural checks do not independently establish completeness or publication. " +
        "Each included NuGet dependency is classified from its exact checked nupkg declaration " +
        "using LP-01 policy 1.0.0 and SPDX 3.27.0. No ordinary grant, reviewer or owner approval " +
        "is required. No legal sufficiency, notice compliance or build correspondence is established.";
    public string RowId => "LP-03";
    public string ResolverId => "lp03-dependency-licenses";
    public string Version => "1.2.0";
    internal static bool ValidId(string value) => NuGetPackageIdentity.ValidId(value);
    internal static bool ValidVersion(string value) => NuGetPackageIdentity.ValidVersion(value);

    public CaseResult Resolve(ResolverCase input)
    {
        var inputs = input.CheckedInputs;
        if (!inputs.ContainsKey("package")) return Result(input, "missing-package");
        if (!inputs.ContainsKey("assessment")) return Result(input, "scope-missing");
        // Admission diagnoses legacy scope before optional policy or old protocol roles.
        var admission = Spdx22InventoryAdmission.Admit(inputs);
        if (admission.Code == "input-invalid") return Result(input, admission.Code, admission.Detail);
        if (inputs.Keys.Any(role => role is not ("package" or "assessment" or "sbom" or "policy" or "corpus") &&
            !Regex.IsMatch(role, @"\Adependency-[0-9]{3}\z", RegexOptions.CultureInvariant)) ||
            inputs.Values.Sum(value => (long)value.Content.Length) > 64 * 1024 * 1024 ||
            inputs.Any(pair => !Lp02PublicSourceResolver.SafePath(pair.Value.Identity.Path) ||
                (pair.Key == "package" || pair.Key.StartsWith("dependency-", StringComparison.Ordinal)) &&
                pair.Value.Content.Length is 0 or > 8 * 1024 * 1024))
            return Result(input, "input-invalid", "Unsupported roles, paths or LP-03 checked-byte limits.");
        if (!inputs.TryGetValue("policy", out var policyBytes) ||
            !inputs.TryGetValue("corpus", out var corpusBytes) ||
            Lp01LicensePolicyResolver.ReadPolicy(policyBytes.Content.Span, corpusBytes.Content.Span) is not { } policy)
            return Result(input, "policy-unavailable");
        if (admission.Inventory is not { } inventory)
            return Result(input, admission.Code, admission.Detail);
        var used = new HashSet<string>(["package", "assessment", "sbom", "policy", "corpus"], StringComparer.Ordinal);
        var missing = new List<string>();
        var unresolved = new List<string>();
        var incompatible = new List<string>();
        for (var index = 0; index < inventory.Dependencies.Length; index++)
        {
            var component = inventory.Dependencies[index];
            var role = "dependency-" + index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture);
            used.Add(role);
            if (!inputs.TryGetValue(role, out var dependency))
            {
                missing.Add(component.Key);
                continue;
            }
            var actual = Lp03PackageEvidence.Read(dependency.Content, null);
            if (actual is null) return Result(input, "input-invalid", "Unsafe exact dependency archive: " + component.Key);
            if (actual.Id != component.Id || actual.Version != component.Version)
                return Result(input, "binding-conflict", "SBOM member and exact nupkg identity/version disagree: " + component.Key);
            var state = Lp01LicensePolicyResolver.InspectPackage(dependency.Content, policy);
            if (state.Branch == "approved-non-copyleft") continue;
            if (state.Branch is "copyleft" or "weak-copyleft" or "non-osi") incompatible.Add(component.Key);
            else unresolved.Add(component.Key + " (" + state.Branch + ")");
        }
        if (inputs.Keys.Any(role => !used.Contains(role)))
            return Result(input, "binding-conflict", "Extra dependency role is not an admitted SBOM member.");
        string Details(List<string> values) => string.Join(", ", values.Take(8)) +
            (values.Count > 8 ? $"; {values.Count} total, complete inventory retained in sbom." : "");
        if (missing.Count != 0) return Result(input, "dependency-bytes-missing", "Missing exact SBOM dependency bytes: " + Details(missing));
        if (unresolved.Count != 0) return Result(input, "license-evidence-unresolved", "Unsupported or ambiguous exact-package declarations: " + Details(unresolved));
        return Result(input, incompatible.Count != 0 ? "incompatible-dependency-license" : "dependencies-policy-satisfied",
            incompatible.Count != 0 ? Details(incompatible) :
                $"{inventory.Dependencies.Length} exact NuGet dependency declarations pass; the caller's bound designation supplies authoritative release-wide scope." +
                (inventory.Diagnostics.Length != 0 ? " " + string.Join(" ", inventory.Diagnostics.Take(2)) : ""));
    }

    private CaseResult Result(ResolverCase input, string branch, string? detail = null)
    {
        var (missing, required, next) = branch switch
        {
            "missing-package" => ("The exact root package is missing.", "package", "package-acquisition"),
            "scope-missing" => ("The exact root and release-wide SBOM assessment binding is missing.", "assessment", "assessment-scope"),
            "input-invalid" => (detail ?? "Malformed, ambiguous or out-of-bounds inventory evidence.", "supported-release-sbom-packet", "evidence-repair"),
            "policy-unavailable" => ("The pinned policy and SPDX catalog are missing or inconsistent.", "pinned-policy-and-corpus", "policy-acquisition"),
            "binding-conflict" => (detail ?? "Exact root, SBOM, designation or dependency bindings disagree.", "consistent-checked-bindings", "evidence-repair"),
            "evidence-missing" => (detail ?? "The retained raw release SBOM is missing.", "release-sbom", "dependency-acquisition"),
            "closure-unresolved" => (detail ?? "Release inventory structure or caller designation is unsupported or incomplete.", "authoritative-release-inventory", "dependency-acquisition"),
            "dependency-bytes-missing" => (detail ?? "An exact inventoried dependency archive is unavailable.", "exact-dependency-bytes", "dependency-acquisition"),
            "license-evidence-unresolved" => (detail ?? "An exact-package license declaration is missing, ambiguous or unsupported.", "exact-dependency-license-declaration", "license-investigation"),
            "incompatible-dependency-license" or "dependencies-policy-satisfied" => ((string?)null, null, null),
            _ => throw new InvalidOperationException("Unknown LP-03 branch: " + branch)
        };
        var finding = branch switch
        {
            "dependencies-policy-satisfied" =>
                "Under the caller's exact-root/raw-SBOM authoritative release-wide designation, all admitted dependency declarations satisfy the pinned OSI-approved non-copyleft policy. " +
                detail + " Structural admission does not independently prove completeness or publication.",
            "incompatible-dependency-license" =>
                "An exact dependency in the caller-designated release inventory declares an incompatible copyleft or non-OSI license under the pinned policy: " + detail,
            _ => null
        };
        return new(RowId, ResolverId, Version, branch, finding is null ? "escalated" : "deterministic",
            finding is null ? "unknown" : "applicable", input.Inputs,
            input.Inputs.Select(i => $"input:{i.Role}:{i.Sha256}").ToArray(), Contract, finding, missing, required, next);
    }
}
