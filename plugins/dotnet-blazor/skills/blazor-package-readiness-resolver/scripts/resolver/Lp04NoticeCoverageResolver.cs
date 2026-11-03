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

        return Unverified("exact source matches and absent third-party banners do not establish first-party authorship; Mode B cannot verify notice obligations");
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
            return unverified("source archive lacks a valid package-lock.json covering declared runtime npm dependencies");

        foreach (var asset in inventory.Assets)
        {
            if (!Lp10BinaryAttributionResolver.TryBundlerAsset(prov.PackageEntries, prov.SourceFiles,
                    prov.RootPrefix, asset.Path, asset.Sha256, out var components) || components.Count == 0 ||
                components.Any(component => !closure.Contains(component)))
                return unverified($"bundled web asset {asset.Path} lacks a digest-bound per-asset source/component map consistent with the lockfile");
        }
        var noticeSections = ParseNoticeSections(noticeText);
        var verifiedPackages = new List<string>();
        foreach (var (pkgName, pkgVersion) in closure)
        {
            if (!noticeSections.TryGetValue((pkgName, pkgVersion), out var section))
            {
                return unverified($"root notice file {noticeFile} is missing a version-matched entry for runtime npm dependency {pkgName}@{pkgVersion}");
            }
            if (!CanonicalLicenseBody.Matches(section.Spdx, section.Body))
                return unverified($"root notice file {noticeFile} has an incomplete or truncated license entry for runtime npm dependency {pkgName}@{pkgVersion}");
            verifiedPackages.Add(pkgName);
        }
        if (verifiedPackages.Count == 0)
            return unverified($"root notice file {noticeFile} verified zero runtime npm dependencies");

        foreach (var asset in inventory.Assets)
        {
            if (!asset.Path.StartsWith("staticwebassets/", StringComparison.Ordinal) ||
                !prov.PackageEntries.TryGetValue(asset.Path, out var rawBytes) ||
                !TryStrictUtf8(rawBytes, out var text))
                return unverified($"bundled web asset {asset.Path} could not be decoded as a staticwebassets UTF-8 text asset");
            foreach (var holder in ExtractCopyrightHolders(text))
            {
                if (!noticeText.Contains(holder, StringComparison.OrdinalIgnoreCase) &&
                    !licenseText.Contains(holder, StringComparison.OrdinalIgnoreCase))
                    return unverified($"inline copyright holder '{holder}' in {asset.Path} is not covered by {noticeFile} or {licenseFile}");
            }
            foreach (Match spdxMatch in Regex.Matches(text, @"SPDX-License-Identifier:\s*([A-Za-z0-9.\-]+)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                var spdxId = spdxMatch.Groups[1].Value.Trim();
                if (spdxId.Length > 0 &&
                    !noticeText.Contains(spdxId, StringComparison.OrdinalIgnoreCase) &&
                    !licenseText.Contains(spdxId, StringComparison.OrdinalIgnoreCase))
                    return unverified($"inline SPDX identifier '{spdxId}' in {asset.Path} is not covered by {noticeFile} or {licenseFile}");
            }
        }

        var distinctPackages = verifiedPackages.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var finding =
            $"{summary} SLSA v1 build provenance and third-party web-asset notice coverage verified for {prov.Declaration.Id} " +
            $"{prov.Declaration.Version} at repository {prov.Repository} commit {prov.Declaration.Commit} (workflow {prov.WorkflowPath}, " +
            $"attested release package SHA-256 {prov.ReleasePackageSha256}): all {inventory.Assets.Count} shipped web assets have " +
            $"digest-bound producer-declared component/source maps, with {runtimeDeps.Count} direct and {distinctPackages.Length} total " +
            $"runtime npm dependencies in package-lock.json, " +
            $"and root {noticeFile} plus {licenseFile} preserve version-matched SPDX identifiers, copyright attributions, and full license texts " +
            $"for the entire declared runtime closure ({string.Join(", ", distinctPackages)}). " +
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
        out List<(string Name, string Version)> closure)
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
            var seenPairs = new HashSet<(string Name, string Version)>();
            var queue = new Queue<(string ParentPath, string Name)>(roots.Select(r => ("", r)));
            while (queue.Count > 0)
            {
                var (parentPath, name) = queue.Dequeue();
                if (!TryResolveLockPackageEntry(packages, parentPath, name, out var resolvedPath, out var entry) ||
                    entry.ValueKind != JsonValueKind.Object ||
                    !entry.TryGetProperty("version", out var verProp) ||
                    verProp.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(verProp.GetString()))
                    return false;
                if (!visitedPaths.Add(resolvedPath))
                    continue;
                var version = verProp.GetString()!;
                if (seenPairs.Add((name, version)))
                    closure.Add((name, version));
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

    private static List<string> ExtractCopyrightHolders(string text)
    {
        var holders = new List<string>();
        foreach (Match match in Regex.Matches(text,
            @"(?:Copyright\s+(?:\(c\)\s+|©\s*)?(?:[0-9]{4}(?:-[0-9]{4})?\s+)?|\(c\)\s*[0-9]{4}(?:-[0-9]{4})?\s+|©\s*[0-9]{4}(?:-[0-9]{4})?\s+)([^\r\n*]+)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            var holder = match.Groups[1].Value.Trim().TrimEnd('.', ',', ';');
            if (holder.Length > 0 &&
                !holder.StartsWith("by ", StringComparison.OrdinalIgnoreCase) &&
                !holder.StartsWith("notice", StringComparison.OrdinalIgnoreCase) &&
                !holder.StartsWith("holder", StringComparison.OrdinalIgnoreCase))
                holders.Add(holder);
        }
        return holders;
    }

}
