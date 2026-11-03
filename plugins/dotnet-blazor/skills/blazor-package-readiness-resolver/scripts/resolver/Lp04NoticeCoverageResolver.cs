using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BlazorPackageResolver;

public sealed class Lp04NoticeCoverageResolver : IDeterministicResolver
{
    internal const string Contract =
        "Package-byte classification under bundled-web-assets/1, not a legal determination. " +
        "Only the assessed nupkg is inspected; no origin, SBOM, applicability or notice conclusion is inferred. " +
        "Other representations were not assessed. Legacy notice-coverage-v1 deciding packets are retired.";
    internal const string ProvenanceContract =
        "Checked package and SLSA v1 build provenance packet under bundled-web-assets/1. " +
        "Positive notice coverage requires helper-admitted provenance, exact-commit source acquisition, " +
        "digest-bound per-asset component maps and complete supported SPDX license clauses for the runtime lock closure; " +
        "unresolved outcomes remain not tested.";
    internal const string EmptyObservation =
        "No JS/CSS assets detected in the supported package layouts; other representations were not assessed.";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly string[] ProvenanceOnlyRoles =
        ["release-package", "provenance-bundle", "provenance-attestation", "source-archive"];
    private static readonly string[] NonShippingPrefixes =
        ["samples/", "tests/", "test/", "demos/", "docs/", "stories/", "templates/", "benchmarks/"];
    private static readonly string[] ThirdPartyDirMarkers =
        ["/node_modules/", "/vendor/", "/third_party/", "/third-party/", "/external/", "/bower_components/", "/lib/", "/libs/"];
    private static readonly string[] RootLicenseCandidates =
        ["LICENSE", "LICENSE.txt", "LICENSE.md"];
    private static readonly string[] RootNoticeCandidates =
        ["THIRD-PARTY-LICENSES.md", "THIRD-PARTY-LICENSES.txt", "THIRD-PARTY-NOTICES.md", "THIRD-PARTY-NOTICES.txt", "THIRD-PARTY-NOTICES"];

    public string RowId => "LP-04";
    public string ResolverId => "lp04-notice-coverage";
    public string Version => "2.1.0";

    internal static bool SafePath(string? value) => Lp02PublicSourceResolver.SafePath(value) &&
        value!.Split('/').All(part => !part.EndsWith('.') && !part.EndsWith(' ') &&
            !Regex.IsMatch(part.Split('.')[0], @"\A(?:con|prn|aux|nul|com[1-9]|lpt[1-9])\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    private static bool Legacy(string role) =>
        role is "assessment" or "notice-coverage" or "admission" or "dependency-inventory" or
            "asset-inventory" or "obligation-reviews" or "notice-mapping" ||
        Regex.IsMatch(role, @"\A(?:dependency|asset|reference|entry)-[0-9]{3}\z",
            RegexOptions.CultureInvariant);

    private static bool IsProvenanceRole(string role) =>
        ProvenanceOnlyRoles.Contains(role, StringComparer.Ordinal);

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
        var hasProvenanceRole = input.CheckedInputs.Keys.Any(IsProvenanceRole);
        if (!hasProvenanceRole && input.CheckedInputs.Keys.Any(role => role != "package"))
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
        if (hasProvenanceRole)
            return ResolveProvenance(input, package, inventory, summary);
        return Result("origin-review-missing",
            $"{summary} Origin and notice obligations are unknown; no origin, SBOM, applicability or notice conclusion is inferred.",
            "asset-origin-and-notice-obligations", "notice-investigation", inventory);
    }

    private CaseResult ResolveProvenance(ResolverCase input, CheckedInput package,
        BundledWebAssetsEvidence inventory, string summary)
    {
        CaseResult Unverified(string detail) =>
            new(RowId, ResolverId, Version, "provenance-notices-unverified", "escalated", "unknown",
                input.Inputs,
                input.Inputs.Select(item => $"input:{item.Role}:{item.Sha256}")
                    .Distinct(StringComparer.Ordinal).ToArray(),
                ProvenanceContract, null,
                $"{summary} Supplied SLSA v1 build provenance and web-asset notice packet could not verify notice coverage ({detail}); web-asset origin and notice obligations remain unverified.",
                "verified-slsa-provenance-and-web-asset-notice-coverage", "notice-investigation")
            { BundledWebAssets = inventory };

        if (!Lp10BinaryAttributionResolver.TryVerifyProvenanceContext(input, package, out var prov, out var provError) ||
            prov is null)
            return Unverified(provError);

        if (!TryFindRootTextEntry(prov.PackageEntries, RootLicenseCandidates, out var licenseFile, out var licenseText) ||
            !licenseText.Contains("Copyright", StringComparison.OrdinalIgnoreCase))
            return Unverified("package lacks a root LICENSE file with copyright attribution");

        var runtimeDeps = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (fullPath, bytes) in prov.SourceFiles)
        {
            var rel = fullPath[prov.RootPrefix.Length..];
            if (!rel.Equals("package.json", StringComparison.OrdinalIgnoreCase) &&
                !rel.EndsWith("/package.json", StringComparison.OrdinalIgnoreCase))
                continue;
            if (NonShippingPrefixes.Any(prefix => rel.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) ||
                ThirdPartyDirMarkers.Any(marker => ("/" + rel).Contains(marker, StringComparison.OrdinalIgnoreCase)))
                continue;
            if (!TryParsePackageJsonDependencies(bytes, out var deps, out var hasUnsupportedDeps) || hasUnsupportedDeps)
                return Unverified($"malformed or unsupported dependency section in {rel}");
            foreach (var (depName, depVer) in deps)
                runtimeDeps[depName] = depVer;
        }

        if (runtimeDeps.Count > 0)
            return VerifyBundledNpmNoticeCoverage(input, package, inventory, summary, prov,
                licenseFile, licenseText, runtimeDeps, Unverified);

        return VerifyFirstPartyWebAssetNoticeCoverage(input, package, inventory, summary, prov,
            licenseFile, licenseText, Unverified);
    }

    private CaseResult VerifyFirstPartyWebAssetNoticeCoverage(ResolverCase input, CheckedInput package,
        BundledWebAssetsEvidence inventory, string summary,
        Lp10BinaryAttributionResolver.VerifiedProvenanceContext prov,
        string licenseFile, string licenseText, Func<string, CaseResult> unverified)
    {
        if (!CanonicalLicenseBody.TryMatchAny(licenseText, out var rootCanonicalSpdx))
            return unverified($"root license file {licenseFile} lacks a complete canonical license body");

        foreach (var candidate in RootLicenseCandidates)
        {
            if (prov.SourceFiles.TryGetValue(prov.RootPrefix + candidate, out var srcLicenseBytes) &&
                TryStrictUtf8(srcLicenseBytes, out var srcLicenseText))
            {
                var normPkg = licenseText.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
                var normSrc = srcLicenseText.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
                if (!string.Equals(normPkg, normSrc, StringComparison.Ordinal))
                    return unverified($"package root {licenseFile} diverges from source repository {candidate}");
            }
        }

        if (Lp10BinaryAttributionResolver.HasBundlerManifestEntry(prov.PackageEntries))
            return unverified("package contains a bundler manifest while declaring zero runtime npm dependencies");

        foreach (var (fullPath, bytes) in prov.SourceFiles)
        {
            var rel = fullPath[prov.RootPrefix.Length..];
            if (NonShippingPrefixes.Any(prefix => rel.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) ||
                ThirdPartyDirMarkers.Any(marker => ("/" + rel).Contains(marker, StringComparison.OrdinalIgnoreCase)))
                continue;
            var fileName = Path.GetFileName(rel);
            if (fileName.StartsWith("vite.config.", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith("webpack.config.", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith("rollup.config.", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith("esbuild.", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith("tsup.config.", StringComparison.OrdinalIgnoreCase) ||
                fileName.StartsWith("parcel.config.", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals(".parcelrc", StringComparison.OrdinalIgnoreCase))
                return unverified($"shipping source contains bundler configuration {rel} without declared runtime dependencies");
            if (fileName.Equals("package.json", StringComparison.OrdinalIgnoreCase) &&
                HasBundlerScriptInPackageJson(bytes))
                return unverified($"shipping {rel} declares a bundler script while declaring zero runtime dependencies");
            if (fileName.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase) &&
                !TryVerifyDevOnlyLockfile(bytes))
                return unverified($"shipping lockfile {rel} contains non-dev or malformed package entries while package.json declares zero runtime dependencies");
        }

        var sourcePathsBySha = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (fullPath, bytes) in prov.SourceFiles)
        {
            var rel = fullPath[prov.RootPrefix.Length..];
            var sha = Catalog.Digest(bytes);
            if (!sourcePathsBySha.TryGetValue(sha, out var list))
                sourcePathsBySha[sha] = list = [];
            list.Add(rel);
        }

        var exactSourceMatchCount = 0;
        var razorCssBundleCount = 0;
        var razorCssComponentCount = 0;

        foreach (var asset in inventory.Assets)
        {
            if (!asset.Path.StartsWith("staticwebassets/", StringComparison.Ordinal) ||
                !prov.PackageEntries.TryGetValue(asset.Path, out var rawBytes) ||
                !TryStrictUtf8(rawBytes, out var text))
                return unverified($"web asset {asset.Path} could not be decoded as a staticwebassets UTF-8 text asset");

            if (asset.Path.EndsWith(".bundle.scp.css", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryVerifyRazorScopedCssBundle(text, prov.Declaration.Id, prov.SourceFiles, prov.RootPrefix,
                        out var componentCount))
                    return unverified($"scoped CSS bundle {asset.Path} does not map every _content section header to a shipping .razor.css source file");
                razorCssBundleCount++;
                razorCssComponentCount += componentCount;
            }
            else
            {
                if (!sourcePathsBySha.TryGetValue(asset.Sha256, out var matchingRelPaths) ||
                    matchingRelPaths.Count == 0)
                    return unverified($"web asset {asset.Path} lacks an exact SHA-256 match in the attested source archive");
                var shippingRelPaths = matchingRelPaths
                    .Where(rel => !NonShippingPrefixes.Any(prefix => rel.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                    .ToList();
                if (shippingRelPaths.Count == 0)
                    return unverified($"web asset {asset.Path} matches only non-shipping source paths ({string.Join(", ", matchingRelPaths)})");
                if (shippingRelPaths.Any(rel =>
                        ThirdPartyDirMarkers.Any(marker => ("/" + rel).Contains(marker, StringComparison.OrdinalIgnoreCase))))
                    return unverified($"web asset {asset.Path} matches a vendor or third-party source path ({string.Join(", ", shippingRelPaths)})");

                var fileName = Path.GetFileName(asset.Path);
                if (Regex.IsMatch(fileName, @"-[0-9]+\.[0-9]+\.[0-9]+(?:\.min)?\.(?:m?js|cjs|css)\z",
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    return unverified($"web asset {asset.Path} has a version-stamped third-party library filename");

                if (HasMinifiedExtension(fileName) &&
                    !HasUnminifiedSourceSibling(shippingRelPaths, prov.SourceFiles, prov.RootPrefix))
                    return unverified($"minified web asset {asset.Path} lacks an unminified sibling source file in the attested source archive");

                if (asset.Path.EndsWith(".map", StringComparison.OrdinalIgnoreCase) &&
                    !TryVerifyFirstPartySourceMap(text))
                    return unverified($"source map {asset.Path} references third-party or invalid sources");

                if (text.Contains("__webpack_require__", StringComparison.Ordinal) ||
                    text.Contains("__vite_ssr_", StringComparison.Ordinal) ||
                    Regex.IsMatch(text, @"please\s+see\s+[^\r\n*]*LICENSE", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    return unverified($"web asset {asset.Path} contains bundler runtime or sidecar license markers");

                exactSourceMatchCount++;
            }

            if (!TryVerifyInlineAssetAttributions(text, licenseText, noticeText: null,
                    requiredFirstPartySpdx: rootCanonicalSpdx, out var inlineError))
                return unverified($"{inlineError} in {asset.Path}");
        }

        var cssDetail = razorCssBundleCount > 0
            ? $" and {razorCssBundleCount} Razor scoped CSS bundle(s) ({razorCssComponentCount} component .razor.css sections)"
            : "";
        var finding =
            $"{summary} SLSA v1 build provenance and first-party web-asset notice coverage verified for {prov.Declaration.Id} " +
            $"{prov.Declaration.Version} at repository {prov.Repository} commit {prov.Declaration.Commit} (workflow {prov.WorkflowPath}, " +
            $"attested release package SHA-256 {prov.ReleasePackageSha256}): shipping package.json/package-lock.json declare zero runtime npm dependencies, " +
            $"all {inventory.Assets.Count} shipped web assets ({exactSourceMatchCount} exact source-blob match(es){cssDetail}) map to first-party shipping source paths, " +
            $"and root {licenseFile} covers package copyright and license obligations with no uncovered third-party inline notices. " +
            "This does not independently prove authorship of uncredited code or legal sufficiency.";
        return new(RowId, ResolverId, Version, "provenance-notices-verified", "deterministic", "applicable",
            input.Inputs,
            input.Inputs.Select(item => $"input:{item.Role}:{item.Sha256}").ToArray(),
            ProvenanceContract, finding, null, null, null)
        { BundledWebAssets = inventory };
    }

    private CaseResult VerifyBundledNpmNoticeCoverage(ResolverCase input, CheckedInput package,
        BundledWebAssetsEvidence inventory, string summary,
        Lp10BinaryAttributionResolver.VerifiedProvenanceContext prov,
        string licenseFile, string licenseText, Dictionary<string, string> runtimeDeps,
        Func<string, CaseResult> unverified)
    {
        if (!TryFindRootTextEntry(prov.PackageEntries, RootNoticeCandidates, out var noticeFile, out var noticeText))
            return unverified("package with runtime npm dependencies lacks a root third-party notice file");

        var lockEntry = prov.SourceFiles.FirstOrDefault(kv =>
            kv.Key.Equals(prov.RootPrefix + "package-lock.json", StringComparison.OrdinalIgnoreCase) ||
            kv.Key.Equals(prov.RootPrefix + "src/package-lock.json", StringComparison.OrdinalIgnoreCase));
        if (lockEntry.Key is null ||
            !TryResolveLockClosure(lockEntry.Value, runtimeDeps.Keys, out var closure) ||
            closure.Count == 0)
            return unverified("source archive lacks a valid package-lock.json covering declared runtime npm dependencies with single SPDX license IDs");

        var closureComponents = closure.Select(dependency => (dependency.Name, dependency.Version)).ToHashSet();
        var hasManifestEntry = Lp10BinaryAttributionResolver.HasBundlerManifestEntry(prov.PackageEntries);
        Lp10BinaryAttributionResolver.AttestedViteBuildPlan? vitePlan = null;
        if (!hasManifestEntry)
        {
            Lp10BinaryAttributionResolver.TryResolveAttestedViteBuildPlan(
                prov.PackageEntries, prov.SourceFiles, prov.RootPrefix, prov.WorkflowPath,
                prov.Declaration.Id, out vitePlan);
        }

        if (hasManifestEntry)
        {
            foreach (var asset in inventory.Assets)
            {
                if (!Lp10BinaryAttributionResolver.TryBundlerAsset(prov.PackageEntries, prov.SourceFiles,
                        prov.RootPrefix, asset.Path, asset.Sha256, out var components) || components.Count == 0 ||
                    components.Any(component => !closureComponents.Contains(component)))
                    return unverified($"bundled web asset {asset.Path} lacks a digest-bound per-asset source/component map consistent with the lockfile");
            }
        }
        else if (vitePlan is null ||
                 !string.Equals(vitePlan.LicenseFileName, noticeFile, StringComparison.Ordinal) ||
                 !IsGeneratedViteLicenseNotice(noticeFile, noticeText, vitePlan, prov))
        {
            return unverified("package lacks either a digest-bound per-asset bundler manifest or an attested Vite build.license notice configuration");
        }

        var noticeSections = ParseNoticeSections(noticeText);
        if (noticeSections.Count == 0)
            return unverified($"root notice file {noticeFile} contains no valid third-party notice sections");

        var closureMap = closure.ToDictionary(c => (c.Name, c.Version), c => c.License);
        foreach (var ((secName, secVer), sec) in noticeSections)
        {
            if (!closureMap.TryGetValue((secName, secVer), out var expectedSpdx) ||
                !string.Equals(sec.Spdx, expectedSpdx, StringComparison.Ordinal) ||
                !CanonicalLicenseBody.Matches(sec.Spdx, sec.Body))
                return unverified($"root notice file {noticeFile} contains an unverified or lockfile-mismatched notice entry for {secName}@{secVer}");
        }

        var verifiedPackages = new List<string>();
        var excludedLockEntries = new List<string>();
        foreach (var (pkgName, pkgVersion, pkgLicense) in closure)
        {
            if (!noticeSections.TryGetValue((pkgName, pkgVersion), out var section))
            {
                if (vitePlan is not null &&
                    CanonicalLicenseBody.Clauses(pkgLicense) is not null &&
                    !IsPackageNamePresentInAssets(pkgName, inventory, prov.PackageEntries) &&
                    IsViteExcludedNonBrowserDependency(pkgName, pkgVersion, lockEntry.Value))
                {
                    excludedLockEntries.Add($"{pkgName}@{pkgVersion}");
                    continue;
                }
                return unverified($"root notice file {noticeFile} is missing a version-matched entry for runtime npm dependency {pkgName}@{pkgVersion}");
            }
            if (!string.Equals(section.Spdx, pkgLicense, StringComparison.Ordinal))
                return unverified($"root notice file {noticeFile} has an SPDX label that does not match the lockfile-declared license for runtime npm dependency {pkgName}@{pkgVersion}");
            if (!CanonicalLicenseBody.Matches(section.Spdx, section.Body))
                return unverified($"root notice file {noticeFile} has an incomplete or truncated license entry for runtime npm dependency {pkgName}@{pkgVersion}");
            verifiedPackages.Add(pkgName);
        }
        if (verifiedPackages.Count == 0)
            return unverified($"root notice file {noticeFile} verified zero runtime npm dependencies");

        if (vitePlan is not null)
        {
            var verifiedSet = verifiedPackages.ToHashSet(StringComparer.Ordinal);
            foreach (var asset in inventory.Assets)
            {
                var isAttributed = (asset.Path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                                    asset.Path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase))
                    ? Lp10BinaryAttributionResolver.TryAttestedViteScriptAsset(vitePlan, prov.SourceFiles, prov.RootPrefix, asset.Path)
                    : Lp10BinaryAttributionResolver.TryAttestedViteCssAsset(vitePlan, prov.SourceFiles, prov.RootPrefix, asset.Path, verifiedSet);
                if (!isAttributed)
                    return unverified($"bundled web asset {asset.Path} does not correspond to a declared Vite build output or copied dependency asset directory");
            }
        }

        foreach (var asset in inventory.Assets)
        {
            if (!asset.Path.StartsWith("staticwebassets/", StringComparison.Ordinal) ||
                !prov.PackageEntries.TryGetValue(asset.Path, out var rawBytes) ||
                !TryStrictUtf8(rawBytes, out var text))
                return unverified($"bundled web asset {asset.Path} could not be decoded as a staticwebassets UTF-8 text asset");
            if (!TryVerifyInlineAssetAttributions(text, licenseText, noticeText,
                    requiredFirstPartySpdx: null, out var inlineError))
                return unverified($"{inlineError} in {asset.Path}");
        }

        var distinctPackages = verifiedPackages.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var orderedExcluded = excludedLockEntries.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var assetAttributionPhrase = vitePlan is not null
            ? "correspond to declared Vite build outputs"
            : "have digest-bound producer-declared component/source maps";
        var closureExclusionPhrase = orderedExcluded.Length > 0
            ? $" (plus {orderedExcluded.Length} validated non-bundled type-only/SSR-shim lockfile entries: {string.Join(", ", orderedExcluded)})"
            : "";
        var finding =
            $"{summary} SLSA v1 build provenance and third-party web-asset notice coverage verified for {prov.Declaration.Id} " +
            $"{prov.Declaration.Version} at repository {prov.Repository} commit {prov.Declaration.Commit} (workflow {prov.WorkflowPath}, " +
            $"attested release package SHA-256 {prov.ReleasePackageSha256}): all {inventory.Assets.Count} shipped web assets " +
            $"{assetAttributionPhrase}, with {runtimeDeps.Count} direct and {distinctPackages.Length} bundled " +
            $"runtime npm dependencies in package-lock.json{closureExclusionPhrase}, " +
            $"and root {noticeFile} plus {licenseFile} preserve version-matched SPDX identifiers, copyright attributions, and full license texts " +
            $"for the entire bundled runtime closure ({string.Join(", ", distinctPackages)}). " +
            "This does not independently prove bundler-map completeness, exhaustive third-party discovery or legal sufficiency.";
        return new(RowId, ResolverId, Version, "provenance-notices-verified", "deterministic", "applicable",
            input.Inputs,
            input.Inputs.Select(item => $"input:{item.Role}:{item.Sha256}").ToArray(),
            ProvenanceContract, finding, null, null, null)
        { BundledWebAssets = inventory };
    }

    private static bool TryStrictUtf8(byte[] bytes, out string text)
    {
        text = "";
        try
        {
            var span = bytes.AsSpan();
            if (span.StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
                span = span[3..];
            text = StrictUtf8.GetString(span);
            return !text.Contains('\0');
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool TryFindRootTextEntry(Dictionary<string, byte[]> entries, string[] candidates,
        out string fileName, out string text)
    {
        foreach (var candidate in candidates)
        {
            var match = entries.FirstOrDefault(kv =>
                !kv.Key.Contains('/') &&
                kv.Key.Equals(candidate, StringComparison.OrdinalIgnoreCase));
            if (match.Key is not null && TryStrictUtf8(match.Value, out var content) &&
                !string.IsNullOrWhiteSpace(content))
            {
                fileName = match.Key;
                text = content;
                return true;
            }
        }
        fileName = "";
        text = "";
        return false;
    }

    private static bool TryParsePackageJsonDependencies(byte[] bytes,
        out Dictionary<string, string> dependencies, out bool hasUnsupportedDeps)
    {
        dependencies = new(StringComparer.Ordinal);
        hasUnsupportedDeps = false;
        if (!TryStrictUtf8(bytes, out var text))
            return false;
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 32 });
            if (!JsonStringValidation.IsWellFormed(doc.RootElement) ||
                doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;
            if (doc.RootElement.TryGetProperty("dependencies", out var deps))
            {
                if (deps.ValueKind != JsonValueKind.Object)
                    return false;
                foreach (var prop in deps.EnumerateObject())
                {
                    if (prop.Value.ValueKind != JsonValueKind.String ||
                        string.IsNullOrWhiteSpace(prop.Name) ||
                        string.IsNullOrWhiteSpace(prop.Value.GetString()))
                        return false;
                    dependencies[prop.Name] = prop.Value.GetString()!;
                }
            }
            if (doc.RootElement.TryGetProperty("optionalDependencies", out var optional))
            {
                if (optional.ValueKind != JsonValueKind.Object) return false;
                hasUnsupportedDeps |= optional.EnumerateObject().Any();
            }
            foreach (var extra in new[] { "bundleDependencies", "bundledDependencies" })
            {
                if (!doc.RootElement.TryGetProperty(extra, out var value)) continue;
                if (value.ValueKind == JsonValueKind.False) continue;
                if (value.ValueKind != JsonValueKind.Array) return false;
                hasUnsupportedDeps |= value.GetArrayLength() > 0;
            }
            return true;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryResolveLockClosure(byte[] lockBytes, IEnumerable<string> roots,
        out List<(string Name, string Version, string License)> closure)
    {
        closure = [];
        if (!TryStrictUtf8(lockBytes, out var text))
            return false;
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 64 });
            if (!JsonStringValidation.IsWellFormed(doc.RootElement) ||
                doc.RootElement.ValueKind != JsonValueKind.Object ||
                !doc.RootElement.TryGetProperty("packages", out var packages) ||
                packages.ValueKind != JsonValueKind.Object)
                return false;
            foreach (var package in packages.EnumerateObject())
            {
                if (string.IsNullOrWhiteSpace(package.Name) && package.Name.Length != 0 ||
                    package.Value.ValueKind != JsonValueKind.Object) return false;
                foreach (var field in new[] { "dependencies", "optionalDependencies" })
                {
                    if (!package.Value.TryGetProperty(field, out var dependencies)) continue;
                    if (dependencies.ValueKind != JsonValueKind.Object) return false;
                    foreach (var dependency in dependencies.EnumerateObject())
                        if (string.IsNullOrWhiteSpace(dependency.Name) ||
                            dependency.Value.ValueKind != JsonValueKind.String ||
                            string.IsNullOrWhiteSpace(dependency.Value.GetString())) return false;
                }
            }
            var visitedPaths = new HashSet<string>(StringComparer.Ordinal);
            var seenPairs = new Dictionary<(string Name, string Version), string>();
            var queue = new Queue<(string ParentPath, string Name)>(roots.Select(r => ("", r)));
            while (queue.Count > 0)
            {
                var (parentPath, name) = queue.Dequeue();
                if (!TryResolveLockPackageEntry(packages, parentPath, name, out var resolvedPath, out var entry) ||
                    entry.ValueKind != JsonValueKind.Object ||
                    !entry.TryGetProperty("version", out var verProp) ||
                    verProp.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(verProp.GetString()) ||
                    entry.EnumerateObject().Count(property => property.Name == "license") != 1 ||
                    !entry.TryGetProperty("license", out var licenseProp) ||
                    licenseProp.ValueKind != JsonValueKind.String ||
                    !IsSimpleSpdxId(licenseProp.GetString()))
                    return false;
                if (!visitedPaths.Add(resolvedPath))
                    continue;
                var version = verProp.GetString()!;
                var license = licenseProp.GetString()!;
                if (seenPairs.TryGetValue((name, version), out var previousLicense))
                {
                    if (!string.Equals(previousLicense, license, StringComparison.Ordinal)) return false;
                }
                else
                {
                    seenPairs.Add((name, version), license);
                    closure.Add((name, version, license));
                }
                if (entry.TryGetProperty("optionalDependencies", out var optDeps) &&
                    optDeps.ValueKind == JsonValueKind.Object && optDeps.EnumerateObject().Any())
                    return false;
                if (entry.TryGetProperty("dependencies", out var deps) &&
                    deps.ValueKind == JsonValueKind.Object)
                {
                    foreach (var child in deps.EnumerateObject())
                        queue.Enqueue((resolvedPath, child.Name));
                }
            }
            return true;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsSimpleSpdxId(string? value) =>
        value is { Length: > 0 and <= 128 } &&
        Regex.IsMatch(value, @"\A[A-Za-z0-9][A-Za-z0-9.\-]*\z", RegexOptions.CultureInvariant) &&
        value.ToUpperInvariant() is not ("AND" or "OR" or "WITH" or "NONE" or "NOASSERTION");

    private static bool TryResolveLockPackageEntry(JsonElement packages, string parentPath, string depName,
        out string resolvedPath, out JsonElement entry)
    {
        var current = parentPath;
        while (!string.IsNullOrEmpty(current))
        {
            var candidate = current + "/node_modules/" + depName;
            if (packages.TryGetProperty(candidate, out entry))
            {
                resolvedPath = candidate;
                return true;
            }
            var idx = current.LastIndexOf("/node_modules/", StringComparison.Ordinal);
            current = idx > 0 ? current[..idx] : "";
        }
        resolvedPath = "node_modules/" + depName;
        return packages.TryGetProperty(resolvedPath, out entry);
    }

    private sealed record NoticeSection(string Name, string Version, string Spdx, string Body);

    private static Dictionary<(string Name, string Version), NoticeSection> ParseNoticeSections(string markdown)
    {
        var result = new Dictionary<(string Name, string Version), NoticeSection>();
        var matches = Regex.Matches(markdown,
            @"^##\s+(?<name>@?[A-Za-z0-9._/-]+)\s+-\s+(?<ver>[0-9A-Za-z._+-]+)\s+\((?<spdx>[^)\r\n]+)\)\s*$",
            RegexOptions.Multiline | RegexOptions.CultureInvariant);
        for (var i = 0; i < matches.Count; i++)
        {
            var current = matches[i];
            var start = current.Index + current.Length;
            var end = i + 1 < matches.Count ? matches[i + 1].Index : markdown.Length;
            var body = markdown[start..end].Trim();
            var name = current.Groups["name"].Value;
            var ver = current.Groups["ver"].Value;
            if (!result.TryAdd((name, ver), new NoticeSection(
                name,
                ver,
                current.Groups["spdx"].Value.Trim(),
                body))) return [];
        }
        return result;
    }

    private static readonly HashSet<string> InvalidHolderStopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "the", "a", "an", "owner", "holder", "notice", "authors", "contributors", "the authors", "the contributors"
    };

    private static List<string> ExtractCopyrightHolders(string text, bool allowYearlessSymbol = false)
    {
        var holders = new List<string>();
        var pattern = allowYearlessSymbol
            ? @"(?<prefix>Copyright\s+(?:\(c\)\s+|©\s*)?(?:[0-9]{4}(?:-[0-9]{4})?\s*,?\s*)?|\(c\)\s*(?<year>[0-9]{4}(?:-[0-9]{4})?\s*,?\s*)?(?=[A-Z@])|©\s*(?:[0-9]{4}(?:-[0-9]{4})?\s*,?\s*)?)(?<holder>[^\r\n*]+)"
            : @"(?<prefix>Copyright\s+(?:\(c\)\s+|©\s*)?(?:[0-9]{4}(?:-[0-9]{4})?\s*,?\s*)?|\(c\)\s*(?<year>[0-9]{4}(?:-[0-9]{4})?\s*,?\s*)|©\s*(?:[0-9]{4}(?:-[0-9]{4})?\s*,?\s*))(?<holder>[^\r\n*]+)";
        foreach (Match match in Regex.Matches(text, pattern,
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var prefix = match.Groups["prefix"].Value.TrimStart();
            if (allowYearlessSymbol &&
                prefix.StartsWith("(c)", StringComparison.OrdinalIgnoreCase) &&
                !match.Groups["year"].Success &&
                Regex.IsMatch(text[..match.Index], @"\(a\)[\s\S]*?\(b\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                continue;

            var holder = match.Groups["holder"].Value.Trim();
            var commentCloseIdx = holder.IndexOf("*/", StringComparison.Ordinal);
            if (commentCloseIdx >= 0)
                holder = holder[..commentCloseIdx].TrimEnd();
            var pipeIdx = holder.IndexOf('|');
            if (pipeIdx >= 0)
                holder = holder[..pipeIdx].TrimEnd();
            var inlineLicSplit = Regex.Match(holder,
                @"(?:\b(?:Licensed|Released)\s+under\b|\bSPDX-License-Identifier\s*:|@license\b|@preserve\b)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (inlineLicSplit.Success)
                holder = holder[..inlineLicSplit.Index].TrimEnd();
            if (holder.StartsWith("by ", StringComparison.OrdinalIgnoreCase))
                holder = holder[3..].TrimStart();
            holder = Regex.Replace(holder, @"\s*\bAll\s+rights\s+reserved\.?\s*\z", "",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            holder = holder.Trim().TrimEnd('.', ',', ';');
            if (holder.Length >= 3 &&
                !InvalidHolderStopWords.Contains(holder) &&
                !holder.StartsWith("notice", StringComparison.OrdinalIgnoreCase) &&
                !holder.StartsWith("holder", StringComparison.OrdinalIgnoreCase))
                holders.Add(holder);
        }
        foreach (Match match in Regex.Matches(text,
            @"\bLicensed\s+to\s+(?:the\s+)?(?<holder>[^\r\n*]+?)\s+under\s+one\s+or\s+more\s+agreements\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var holder = match.Groups["holder"].Value.Trim().TrimEnd('.', ',', ';');
            if (holder.Length >= 3 &&
                !InvalidHolderStopWords.Contains(holder) &&
                !holders.Contains(holder, StringComparer.OrdinalIgnoreCase))
                holders.Add(holder);
        }
        return holders;
    }

    private static List<string> ExtractLicenseCopyrightLines(string licenseText)
    {
        var lines = new List<string>();
        foreach (var rawLine in licenseText.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.Contains("[name of copyright owner]", StringComparison.OrdinalIgnoreCase))
                continue;
            if (Regex.IsMatch(line, @"\A(?:Copyright\s+(?:\(c\)|©|[0-9]{4})|\(c\)\s*[0-9]{4}|©)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                lines.Add(line);
        }
        return lines;
    }

    private static IEnumerable<string> EnumerateCommentBlocks(string text)
    {
        foreach (Match blockMatch in Regex.Matches(text, @"/\*[\s\S]*?\*/", RegexOptions.CultureInvariant))
            yield return blockMatch.Value;
        foreach (Match lineGroupMatch in Regex.Matches(text, @"(?:^[ \t]*//[^\r\n]*(?:\r?\n|\z))+",
                     RegexOptions.Multiline | RegexOptions.CultureInvariant))
            yield return lineGroupMatch.Value;
    }

    private static bool TryParseSingleProseLicenseClause(string rawClause, out string normalizedSpdx)
    {
        normalizedSpdx = "";
        var clause = rawClause.Trim();
        var commentClose = clause.IndexOf("*/", StringComparison.Ordinal);
        if (commentClose >= 0)
            clause = clause[..commentClose].Trim();
        var seeIdx = Regex.Match(clause, @"\.\s+See\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (seeIdx.Success)
            clause = clause[..seeIdx.Index].Trim();
        clause = Regex.Replace(clause, @"\s*\(the\s+""License""\)\s*\z", "",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        clause = clause.Trim().TrimEnd('.', ',', ';');
        if (clause.Length == 0 ||
            Regex.IsMatch(clause, @"\b(?:with|exception|commons\s+clause|or|and)\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            return false;

        if (Regex.IsMatch(clause, @"\A(?:the\s+)?(?:MIT(?:\s+Licen[sc]e)?)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            normalizedSpdx = "MIT";
            return true;
        }
        if (Regex.IsMatch(clause, @"\A(?:the\s+)?(?:ISC(?:\s+Licen[sc]e)?)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            normalizedSpdx = "ISC";
            return true;
        }
        if (Regex.IsMatch(clause, @"\A(?:the\s+)?(?:0BSD(?:\s+Licen[sc]e)?|Zero-Clause\s+BSD(?:\s+Licen[sc]e)?)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            normalizedSpdx = "0BSD";
            return true;
        }
        var bsdMatch = Regex.Match(clause, @"\A(?:the\s+)?BSD[-\s]+(?<n>[234])-Clause(?:\s+Licen[sc]e)?\z",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (bsdMatch.Success)
        {
            normalizedSpdx = $"BSD-{bsdMatch.Groups["n"].Value}-Clause";
            return true;
        }
        if (Regex.IsMatch(clause, @"\A(?:the\s+)?(?:Apache\s+Licen[sc]e,?\s*Version\s*2\.0|Apache[-\s]+2\.0(?:\s+Licen[sc]e)?)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            normalizedSpdx = "Apache-2.0";
            return true;
        }
        if (Regex.IsMatch(clause, @"\A(?:the\s+)?(?:Mozilla\s+Public\s+Licen[sc]e(?:,?\s*v(?:ersion)?\.?\s*2\.0)?|MPL[-\s]+2\.0(?:\s+Licen[sc]e)?)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            normalizedSpdx = "MPL-2.0";
            return true;
        }
        return false;
    }

    private static List<string> ExtractProseCommentLicenses(string commentBlock, out bool hasUnrecognizedClause)
    {
        var unrecognized = false;
        var result = new List<string>();
        void AddLic(string id)
        {
            if (!result.Contains(id, StringComparer.OrdinalIgnoreCase))
                result.Add(id);
        }

        void ValidateClauseSegments(string rawClause)
        {
            var segments = rawClause.Split(new[] { '|', ';' }, StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0)
            {
                unrecognized = true;
                return;
            }
            foreach (var rawSegment in segments)
            {
                var segment = rawSegment.Trim();
                if (segment.Length == 0)
                    continue;
                if (Regex.IsMatch(segment, @"\A(?:(?:Copyright|\(c\)|©)\b|All\s+rights\s+reserved\.?\z)",
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    continue;
                segment = Regex.Replace(segment,
                    @"\A(?:@license\s+|\b(?:Licensed|Released|licenses\s+this\s+file\s+to\s+you)\s+under\s+)",
                    "", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant).Trim();
                if (TryParseSingleProseLicenseClause(segment, out var parsedSpdx))
                    AddLic(parsedSpdx);
                else
                    unrecognized = true;
            }
        }

        foreach (Match atLicMatch in Regex.Matches(commentBlock,
                     @"@license\b(?:[ \t]+(?![\r\n*])(?<sameLine>[^\r\n*]+)|[ \t]*(?:\r?\n[ \t*]*(?<nextLine>[^\r\n*]+))?)",
                     RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            if (atLicMatch.Groups["sameLine"].Success)
            {
                var sameLine = atLicMatch.Groups["sameLine"].Value.Trim();
                if (Regex.IsMatch(sameLine, @"\A(?:Copyright|\(c\)|©)\b",
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    continue;
                ValidateClauseSegments(sameLine);
            }
            else if (atLicMatch.Groups["nextLine"].Success)
            {
                var nextLine = atLicMatch.Groups["nextLine"].Value.Trim().Trim('/');
                if (nextLine.Length == 0)
                {
                    unrecognized = true;
                    continue;
                }
                if (Regex.IsMatch(nextLine,
                        @"\A(?:(?:Copyright|\(c\)|©)\b|SPDX-License-Identifier\s*:|@license\b|@preserve\b|(?:Licensed|Released)\s+under\b)|(?:\blicenses\s+this\s+file\s+to\s+you\s+under\b)",
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    continue;
                ValidateClauseSegments(nextLine);
            }
            else
            {
                unrecognized = true;
            }
        }

        if (Regex.IsMatch(commentBlock,
                @"\b(?:Licensed|Released|licenses\s+this\s+file\s+to\s+you)\s+under(?![ \t]+[^\r\n*;|]|[ \t]*\r?\n[ \t*]*[^\r\n*;|])",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            unrecognized = true;
        }
        foreach (Match clauseMatch in Regex.Matches(commentBlock,
                     @"\b(?:Licensed|Released|licenses\s+this\s+file\s+to\s+you)\s+under(?:[ \t]+(?![\r\n*])|[ \t]*\r?\n[ \t*]*)(?<clause>[^\r\n*]+)",
                     RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            ValidateClauseSegments(clauseMatch.Groups["clause"].Value);
        }
        hasUnrecognizedClause = unrecognized;

        if (Regex.IsMatch(commentBlock, @"\bApache\s+Licen[sc]e,?\s*Version\s*2\.0\b|\bApache[-\s]+2\.0\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("Apache-2.0");
        if (Regex.IsMatch(commentBlock, @"\bMozilla\s+Public\s+Licen[sc]e\b|mozilla\.org/MPL/2\.0|\bMPL[-\s]+2\.0\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("MPL-2.0");
        if (Regex.IsMatch(commentBlock, @"\bGNU\s+(?:Lesser|Library)\s+General\s+Public\s+Licen[sc]e\b|\bLGPL-[23]\.[01](?:-only|-or-later)?\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("LGPL");
        if (Regex.IsMatch(commentBlock, @"\bGNU\s+Affero\s+General\s+Public\s+Licen[sc]e\b|\bAGPL-3\.0(?:-only|-or-later)?\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("AGPL-3.0");
        if (Regex.IsMatch(commentBlock, @"\bGNU\s+General\s+Public\s+Licen[sc]e\b|\bGPL-[23]\.[01](?:-only|-or-later)?\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("GPL");
        if (Regex.IsMatch(commentBlock, @"\bEclipse\s+Public\s+Licen[sc]e\b|\bEPL-[12]\.0\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("EPL");
        if (Regex.IsMatch(commentBlock, @"\bCreative\s+Commons\b|\bCC-BY(?:-[A-Za-z0-9.\-]+)?\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("CC-BY");
        if (Regex.IsMatch(commentBlock, @"\bCC0[-\s]+1\.0\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("CC0-1.0");
        if (Regex.IsMatch(commentBlock, @"\bUnlicense\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("Unlicense");
        if (Regex.IsMatch(commentBlock, @"\bZero-Clause\s+BSD\b|\b0BSD\b",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            AddLic("0BSD");

        var patterns = new[]
        {
            @"(?:@license|@preserve)\s+(?<lic>MIT|BSD-[234]-Clause|BSD\s+[234]-Clause|ISC|0BSD)\b",
            @"\b(?<lic>MIT|BSD-[234]-Clause|BSD\s+[234]-Clause|ISC|0BSD)\s+Licen[sc]e\b",
            @"\|\s*(?<lic>MIT|BSD-[234]-Clause|BSD\s+[234]-Clause|ISC|0BSD)\b",
            @"\b(?<lic>BSD-[234]-Clause|BSD\s+[234]-Clause)\b"
        };
        foreach (var pattern in patterns)
        {
            foreach (Match m in Regex.Matches(commentBlock, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                var raw = Regex.Replace(m.Groups["lic"].Value.Trim(), @"\s+", "-", RegexOptions.CultureInvariant);
                var normalized = CanonicalLicenseBody.NormalizeSpdxId(raw) ?? raw.ToUpperInvariant();
                AddLic(normalized);
            }
        }
        return result;
    }

    private static bool TryVerifyInlineAssetAttributions(string text, string licenseText, string? noticeText,
        string? requiredFirstPartySpdx, out string error)
    {
        error = "";
        var licenseCopyrightLines = ExtractLicenseCopyrightLines(licenseText);
        bool IsHolderCoveredByLicense(string holder) =>
            requiredFirstPartySpdx is not null
                ? licenseCopyrightLines.Any(line => line.Contains(holder, StringComparison.OrdinalIgnoreCase))
                : licenseText.Contains(holder, StringComparison.OrdinalIgnoreCase);

        var holders = ExtractCopyrightHolders(text, allowYearlessSymbol: false);
        foreach (var holder in holders)
        {
            var coveredByLicense = IsHolderCoveredByLicense(holder);
            var coveredByNotice = noticeText is not null && noticeText.Contains(holder, StringComparison.OrdinalIgnoreCase);
            if (!coveredByLicense && !coveredByNotice)
            {
                error = $"inline copyright holder '{holder}' is not covered by root license or notice files";
                return false;
            }
        }

        var spdxMatches = Regex.Matches(text, @"SPDX-License-Identifier:\s*([^\r\n*]+)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (Match spdxMatch in spdxMatches)
        {
            var rawExpr = spdxMatch.Groups[1].Value.Trim();
            var commentClose = rawExpr.IndexOf("*/", StringComparison.Ordinal);
            if (commentClose >= 0)
                rawExpr = rawExpr[..commentClose].Trim();
            rawExpr = rawExpr.Trim('(', ')').Trim();
            if (rawExpr.Length == 0)
            {
                error = "empty inline SPDX-License-Identifier expression";
                return false;
            }
            var tokens = Regex.Split(rawExpr, @"\s+(?:AND|OR|WITH)\s+",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            var validTokenCount = 0;
            foreach (var rawToken in tokens)
            {
                var token = rawToken.Trim('(', ')').Trim();
                if (token.Length == 0 || !Regex.IsMatch(token, @"\A[A-Za-z0-9.\-+]+\z", RegexOptions.CultureInvariant))
                {
                    error = $"malformed inline SPDX-License-Identifier token '{rawToken}'";
                    return false;
                }
                validTokenCount++;
                if (requiredFirstPartySpdx is not null &&
                    !string.Equals(token, requiredFirstPartySpdx, StringComparison.OrdinalIgnoreCase))
                {
                    error = $"inline SPDX identifier '{token}' does not match root license '{requiredFirstPartySpdx}'";
                    return false;
                }
                var coveredByLicense = ContainsSpdxToken(licenseText, token);
                var coveredByNotice = noticeText is not null && ContainsSpdxToken(noticeText, token);
                if (!coveredByLicense && !coveredByNotice)
                {
                    error = $"inline SPDX identifier '{token}' is not covered by root license or notice files";
                    return false;
                }
            }
            if (validTokenCount == 0)
            {
                error = "inline SPDX-License-Identifier contained no valid license tokens";
                return false;
            }
        }

        if (requiredFirstPartySpdx is not null)
        {
            foreach (var commentBlock in EnumerateCommentBlocks(text))
            {
                var blockHolders = ExtractCopyrightHolders(commentBlock, allowYearlessSymbol: true);
                foreach (var holder in blockHolders)
                {
                    if (!IsHolderCoveredByLicense(holder))
                    {
                        error = $"inline copyright holder '{holder}' is not covered by root license or notice files";
                        return false;
                    }
                }

                var proseLicenses = ExtractProseCommentLicenses(commentBlock, out var hasUnrecognizedClause);
                var hasSpdxTag = Regex.IsMatch(commentBlock, @"\bSPDX-License-Identifier\s*:",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                var hasExplicitUnderClause = Regex.IsMatch(commentBlock,
                    @"(?:@license\b|\b(?:Licensed|Released|licenses\s+this\s+file\s+to\s+you)\s+under\b)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                foreach (var lic in proseLicenses)
                {
                    if (!string.Equals(lic, requiredFirstPartySpdx, StringComparison.OrdinalIgnoreCase))
                    {
                        error = $"inline comment declares license '{lic}' which does not match root license '{requiredFirstPartySpdx}'";
                        return false;
                    }
                }

                if (hasUnrecognizedClause || (hasExplicitUnderClause && proseLicenses.Count == 0))
                {
                    error = "inline comment contains an unrecognized license declaration";
                    return false;
                }

                var isLicenseBanner = proseLicenses.Count > 0 ||
                    hasSpdxTag ||
                    hasExplicitUnderClause ||
                    Regex.IsMatch(commentBlock, @"@preserve\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                if (isLicenseBanner && blockHolders.Count == 0)
                {
                    error = "inline license banner comment lacks an explicit first-party copyright holder in the same comment block";
                    return false;
                }
            }
        }

        return true;
    }

    private static bool ContainsSpdxToken(string documentText, string spdxToken)
    {
        if (Regex.IsMatch(documentText,
                @"(?<![A-Za-z0-9.\-])" + Regex.Escape(spdxToken) + @"(?![A-Za-z0-9.\-])",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            return true;
        var canonicalId = CanonicalLicenseBody.NormalizeSpdxId(spdxToken);
        return canonicalId is not null && CanonicalLicenseBody.Matches(canonicalId, documentText);
    }

    private static readonly HashSet<string> BundlerPackageNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "vite", "webpack", "webpack-cli", "rollup", "esbuild", "parcel", "tsup",
        "@rspack/core", "@rspack/cli", "rolldown", "browserify", "@vercel/ncc", "microbundle"
    };

    private static bool HasBundlerScriptInPackageJson(byte[] pkgJsonBytes)
    {
        if (!TryStrictUtf8(pkgJsonBytes, out var text))
            return true;
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 32 });
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                !JsonStringValidation.IsWellFormed(doc.RootElement))
                return true;
            foreach (var depField in new[] { "dependencies", "devDependencies", "optionalDependencies" })
            {
                if (!doc.RootElement.TryGetProperty(depField, out var deps))
                    continue;
                if (deps.ValueKind != JsonValueKind.Object)
                    return true;
                foreach (var prop in deps.EnumerateObject())
                {
                    if (BundlerPackageNames.Contains(prop.Name))
                        return true;
                }
            }
            if (!doc.RootElement.TryGetProperty("scripts", out var scripts))
                return false;
            if (scripts.ValueKind != JsonValueKind.Object)
                return true;
            foreach (var script in scripts.EnumerateObject())
            {
                if (script.Value.ValueKind != JsonValueKind.String)
                    return true;
                var cmd = script.Value.GetString() ?? "";
                if (Regex.IsMatch(cmd, @"\b(?:vite|webpack|rollup|esbuild|parcel|tsup|rspack|rolldown|browserify|ncc|microbundle)\b|--bundle\b|\bbun\s+build\b",
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    return true;
            }
            return false;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return true;
        }
    }

    private static bool TryVerifyDevOnlyLockfile(byte[] lockBytes)
    {
        if (!TryStrictUtf8(lockBytes, out var text))
            return false;
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 64 });
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                !JsonStringValidation.IsWellFormed(doc.RootElement) ||
                !doc.RootElement.TryGetProperty("packages", out var packages) ||
                packages.ValueKind != JsonValueKind.Object)
                return false;

            var hasNonRootEntry = false;
            foreach (var entry in packages.EnumerateObject())
            {
                if (entry.Value.ValueKind != JsonValueKind.Object)
                    return false;
                if (entry.Name.Length == 0)
                {
                    if (entry.Value.TryGetProperty("dependencies", out var rootDeps) &&
                        (rootDeps.ValueKind != JsonValueKind.Object || rootDeps.EnumerateObject().Any()))
                        return false;
                    if (entry.Value.TryGetProperty("optionalDependencies", out var rootOptDeps) &&
                        (rootOptDeps.ValueKind != JsonValueKind.Object || rootOptDeps.EnumerateObject().Any()))
                        return false;
                    continue;
                }
                hasNonRootEntry = true;
                if (!entry.Value.TryGetProperty("dev", out var devProp) ||
                    devProp.ValueKind != JsonValueKind.True)
                    return false;
                if (entry.Value.TryGetProperty("devOptional", out var devOptProp) &&
                    devOptProp.ValueKind == JsonValueKind.True)
                    return false;
            }
            return hasNonRootEntry || !packages.EnumerateObject().Any(e => e.Name.Length > 0);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryVerifyRazorScopedCssBundle(string bundleText, string packageId,
        Dictionary<string, byte[]> sourceFiles, string rootPrefix, out int componentCount)
    {
        componentCount = 0;
        var trimmed = bundleText.TrimStart();
        if (!trimmed.StartsWith("/* _content/", StringComparison.Ordinal))
            return false;

        var headerMatches = Regex.Matches(trimmed,
            @"^/\* _content/(?<pkg>[^/\r\n*]+)/(?<rel>[^\r\n*]+?)\.rz\.scp\.css \*/\r?$",
            RegexOptions.Multiline | RegexOptions.CultureInvariant);
        if (headerMatches.Count == 0 || headerMatches[0].Index != 0)
            return false;

        var shippingRazorCssPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fullPath in sourceFiles.Keys)
        {
            if (!fullPath.StartsWith(rootPrefix, StringComparison.Ordinal))
                continue;
            var rel = fullPath[rootPrefix.Length..];
            if (!rel.EndsWith(".razor.css", StringComparison.OrdinalIgnoreCase))
                continue;
            if (NonShippingPrefixes.Any(prefix => rel.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) ||
                ThirdPartyDirMarkers.Any(marker => ("/" + rel).Contains(marker, StringComparison.OrdinalIgnoreCase)))
                continue;
            shippingRazorCssPaths.Add(rel);
        }

        for (var i = 0; i < headerMatches.Count; i++)
        {
            var match = headerMatches[i];
            var pkg = match.Groups["pkg"].Value;
            var relComponent = match.Groups["rel"].Value;
            if (!string.Equals(pkg, packageId, StringComparison.OrdinalIgnoreCase) ||
                relComponent.Contains("..", StringComparison.Ordinal) ||
                relComponent.Contains('\\', StringComparison.Ordinal) ||
                !relComponent.EndsWith(".razor", StringComparison.OrdinalIgnoreCase))
                return false;

            var expectedSuffix = relComponent + ".css";
            var matchedSource = shippingRazorCssPaths.Any(srcRel =>
                srcRel.Equals(expectedSuffix, StringComparison.OrdinalIgnoreCase) ||
                srcRel.EndsWith("/" + expectedSuffix, StringComparison.OrdinalIgnoreCase));
            if (!matchedSource)
                return false;

            componentCount++;
        }

        return componentCount > 0;
    }

    private static bool HasMinifiedExtension(string fileName) =>
        fileName.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase) ||
        fileName.EndsWith(".min.mjs", StringComparison.OrdinalIgnoreCase) ||
        fileName.EndsWith(".min.cjs", StringComparison.OrdinalIgnoreCase) ||
        fileName.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase);

    private static bool HasUnminifiedSourceSibling(List<string> matchingRelPaths,
        Dictionary<string, byte[]> sourceFiles, string rootPrefix)
    {
        foreach (var relPath in matchingRelPaths)
        {
            var unminifiedRel = Regex.Replace(relPath, @"\.min\.(m?js|cjs|css)\z", ".$1",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!string.Equals(unminifiedRel, relPath, StringComparison.OrdinalIgnoreCase) &&
                sourceFiles.ContainsKey(rootPrefix + unminifiedRel))
                return true;
        }
        return false;
    }

    private static bool HasUriSchemeOrRootedPath(string value) =>
        value.Contains("://", StringComparison.Ordinal) ||
        value.StartsWith('/') ||
        value.StartsWith('\\') ||
        Regex.IsMatch(value, @"\A[A-Za-z][A-Za-z0-9+.\-]*:", RegexOptions.CultureInvariant);

    private static bool TryVerifyFirstPartySourceMap(string mapJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(mapJson, new JsonDocumentOptions { MaxDepth = 32 });
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                !JsonStringValidation.IsWellFormed(doc.RootElement) ||
                !doc.RootElement.TryGetProperty("sources", out var sources) ||
                sources.ValueKind != JsonValueKind.Array)
                return false;
            var sourceRootPrefix = "";
            if (doc.RootElement.TryGetProperty("sourceRoot", out var sourceRootProp))
            {
                if (sourceRootProp.ValueKind != JsonValueKind.String)
                    return false;
                var sr = (sourceRootProp.GetString() ?? "").Trim();
                if (sr.Length > 0)
                {
                    if (HasUriSchemeOrRootedPath(sr))
                        return false;
                    sourceRootPrefix = "/" + sr.Replace('\\', '/').Trim('/') + "/";
                    if (ThirdPartyDirMarkers.Any(marker => sourceRootPrefix.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                        return false;
                }
            }
            var hasAny = false;
            foreach (var item in sources.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String)
                    return false;
                var src = (item.GetString() ?? "").Trim();
                if (src.Length == 0 || HasUriSchemeOrRootedPath(src))
                    return false;
                hasAny = true;
                var normalized = (sourceRootPrefix.Length > 0 ? sourceRootPrefix : "/") + src.Replace('\\', '/').TrimStart('/');
                if (ThirdPartyDirMarkers.Any(marker => normalized.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                    return false;
            }
            return hasAny;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsGeneratedViteLicenseNotice(string noticeFile, string noticeText,
        Lp10BinaryAttributionResolver.AttestedViteBuildPlan vitePlan,
        Lp10BinaryAttributionResolver.VerifiedProvenanceContext prov)
    {
        if (!noticeText.TrimStart().StartsWith("# Licenses", StringComparison.Ordinal) ||
            !noticeText.Contains("The app bundles dependencies which contain the following licenses:", StringComparison.Ordinal))
            return false;
        if (!prov.PackageEntries.TryGetValue(noticeFile, out var pkgNoticeBytes))
            return false;
        var normalizedPkgNotice = noticeText.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
        foreach (var (srcPath, srcBytes) in prov.SourceFiles)
        {
            var relSrcPath = srcPath.StartsWith(prov.RootPrefix, StringComparison.Ordinal)
                ? srcPath[prov.RootPrefix.Length..]
                : srcPath;
            if (relSrcPath.Equals(noticeFile, StringComparison.OrdinalIgnoreCase) ||
                relSrcPath.EndsWith("/" + noticeFile, StringComparison.OrdinalIgnoreCase))
                return false;
            if (srcBytes.AsSpan().SequenceEqual(pkgNoticeBytes))
                return false;
            if (TryStrictUtf8(srcBytes, out var srcText) &&
                srcText.Replace("\r\n", "\n", StringComparison.Ordinal).Trim().Equals(normalizedPkgNotice, StringComparison.Ordinal))
                return false;
        }
        return true;
    }

    private static bool IsPackageNamePresentInAssets(string pkgName, BundledWebAssetsEvidence inventory,
        Dictionary<string, byte[]> packageEntries)
    {
        var shortName = pkgName.Contains('/') ? pkgName[(pkgName.LastIndexOf('/') + 1)..] : pkgName;
        foreach (var asset in inventory.Assets)
        {
            if (!packageEntries.TryGetValue(asset.Path, out var raw) || !TryStrictUtf8(raw, out var text))
                return true;
            if (text.Contains(pkgName, StringComparison.OrdinalIgnoreCase) ||
                (shortName.Length >= 6 && text.Contains(shortName, StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }

    private static bool IsViteExcludedNonBrowserDependency(string pkgName, string pkgVersion, byte[] lockBytes)
    {
        if (!pkgName.StartsWith("@types/", StringComparison.Ordinal) &&
            !string.Equals(pkgName, "@lit-labs/ssr-dom-shim", StringComparison.Ordinal))
            return false;
        if (!TryStrictUtf8(lockBytes, out var text))
            return false;
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 64 });
            if (!doc.RootElement.TryGetProperty("packages", out var packages) ||
                packages.ValueKind != JsonValueKind.Object)
                return false;
            var matchedAny = false;
            foreach (var prop in packages.EnumerateObject())
            {
                if (!prop.Name.Equals("node_modules/" + pkgName, StringComparison.Ordinal) &&
                    !prop.Name.EndsWith("/node_modules/" + pkgName, StringComparison.Ordinal))
                    continue;
                if (prop.Value.ValueKind != JsonValueKind.Object ||
                    !prop.Value.TryGetProperty("version", out var verProp) ||
                    verProp.GetString() != pkgVersion)
                    continue;
                matchedAny = true;
                if (prop.Value.TryGetProperty("dependencies", out var deps) &&
                    (deps.ValueKind != JsonValueKind.Object || deps.EnumerateObject().Any()))
                    return false;
                if (prop.Value.TryGetProperty("optionalDependencies", out _) ||
                    prop.Value.TryGetProperty("peerDependencies", out _) ||
                    prop.Value.TryGetProperty("bin", out _) ||
                    prop.Value.TryGetProperty("main", out _) ||
                    prop.Value.TryGetProperty("module", out _) ||
                    prop.Value.TryGetProperty("browser", out _) ||
                    prop.Value.TryGetProperty("exports", out _) ||
                    prop.Value.TryGetProperty("hasInstallScript", out _))
                    return false;
            }
            return matchedAny;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

}
