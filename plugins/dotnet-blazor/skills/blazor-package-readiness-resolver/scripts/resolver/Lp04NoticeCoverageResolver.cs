using System.Text;
using System.Text.RegularExpressions;

namespace BlazorPackageResolver;

public sealed class Lp04NoticeCoverageResolver : IDeterministicResolver
{
    internal const string Contract =
        "Package-byte classification under bundled-web-assets/1, not a legal determination. " +
        "Only the assessed nupkg is inspected; no origin, SBOM, applicability or notice conclusion is inferred. " +
        "Other representations were not assessed. Legacy notice-coverage-v1 deciding packets are retired.";
    internal const string EmptyObservation =
        "No JS/CSS assets detected in the supported package layouts; other representations were not assessed.";

    public string RowId => "LP-04";
    public string ResolverId => "lp04-notice-coverage";
    public string Version => "2.0.0";

    internal static bool SafePath(string? value) => Lp02PublicSourceResolver.SafePath(value) &&
        value!.Split('/').All(part => !part.EndsWith('.') && !part.EndsWith(' ') &&
            !Regex.IsMatch(part.Split('.')[0], @"\A(?:con|prn|aux|nul|com[1-9]|lpt[1-9])\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    private static bool Legacy(string role) =>
        role is "assessment" or "notice-coverage" or "admission" or "dependency-inventory" or
            "asset-inventory" or "obligation-reviews" or "notice-mapping" ||
        Regex.IsMatch(role, @"\A(?:dependency|asset|reference|entry)-[0-9]{3}\z",
            RegexOptions.CultureInvariant);

    public CaseResult Resolve(ResolverCase input)
    {
        CaseResult Result(string branch, string missing, string required, string next,
            BundledWebAssetsEvidence? inventory = null) =>
            new(RowId, ResolverId, Version, branch, "escalated", "unknown", input.Inputs,
                [], Contract, null, missing, required, next) { BundledWebAssets = inventory };

        if (!input.CheckedInputs.TryGetValue("package", out var package))
            return Result("missing-package", "The exact root package is missing.",
                "package", "package-acquisition");
        if (input.CheckedInputs.Any(pair => pair.Key != pair.Value.Identity.Role ||
                !SafePath(pair.Value.Identity.Path) ||
                Catalog.Digest(pair.Value.Content.Span) != pair.Value.Identity.Sha256) ||
            input.Inputs.Count != input.CheckedInputs.Count ||
            input.Inputs.Any(pin => !input.CheckedInputs.TryGetValue(pin.Role, out var item) || item.Identity != pin))
            return Result("input-invalid", "Checked package inputs are not safely and exactly bound.",
                "exact-bound-package", "evidence-repair");

        var inventory = Lp04PackageEvidence.Read(package.Content);
        if (inventory is null)
            return Result("input-invalid", "The package is unsafe, malformed, incomplete or outside the bounded supported profile.",
                "safe-bounded-package", "evidence-repair");
        if (input.CheckedInputs.Keys.Any(Legacy))
            return Result("legacy-protocol", "A retired notice-coverage-v1 role or packet was supplied; it cannot decide LP-04.",
                "package-only-request", "evidence-repair");
        if (input.CheckedInputs.Keys.Any(role => role != "package"))
            return Result("input-invalid", "The package-only LP-04 request contains an unsupported evidence role.",
                "package-only-request", "evidence-repair");

        var summary = Lp04PackageEvidence.Summary(inventory);
        if (inventory.UnsupportedCandidates.Count != 0)
            return Result("surface-unsupported",
                $"{summary} {inventory.UnsupportedCandidates.Count} unsupported candidates are retained in bundled_web_assets.unsupported_candidates; their origin and notice obligations are unknown.",
                "supported-surface-or-separate-assessment", "notice-investigation", inventory);
        if (inventory.Assets.Count == 0)
            return Result("no-supported-layout-assets",
                $"{EmptyObservation} Scanned suffixes: .js, .mjs, .cjs, .css, .map. {summary}",
                "evidence-of-applicability-or-other-representations", "notice-investigation", inventory);
        return Result("origin-review-missing",
            $"{summary} Origin and notice obligations are unknown; no origin, SBOM, applicability or notice conclusion is inferred.",
            "asset-origin-and-notice-obligations", "notice-investigation", inventory);
    }
}
