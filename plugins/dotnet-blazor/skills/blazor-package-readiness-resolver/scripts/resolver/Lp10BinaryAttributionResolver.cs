using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace BlazorPackageResolver;

public sealed class Lp10BinaryAttributionResolver : IDeterministicResolver
{
    private const int PackageLimit = 64 * 1024 * 1024;
    private const int DirectoryLimit = 8 * 1024 * 1024;
    private const int NuspecLimit = 1024 * 1024;
    private const int EntryLimit = 8 * 1024 * 1024;
    private const int TotalLimit = 32 * 1024 * 1024;
    private const int XmlLimit = 256 * 1024;
    private const int LockfileLimit = 4 * 1024 * 1024;
    private const int XmlDepthLimit = 32;
    private const int XmlNodeLimit = 4096;
    private const int SnippetLimit = 160;
    private const int ImportDepthLimit = 8;
    private const int ImportCountLimit = 32;
    private const string MsbuildNamespace = "http://schemas.microsoft.com/developer/msbuild/2003";
    private const string NoCodeFinding =
        "No executable/code payload candidates were found among the safely classified entries; LP-10 holds vacuously for this checked package only.";
    private const string NoCodeContract =
        "All checked non-manifest entries matched the bounded passive/declaration allowlist.";
    private const string CandidatePrefix =
        "Checked code candidates (exact bytes hashed; locator snippets are display-only): ";
    private const string CandidateSuffix =
        ". These checked bytes do not establish ownership, release-commit correspondence or upstream.";
    internal const string AttributionLimit =
        "This package-only resolver accepts no source/provenance maps and performs no builds or transforms. " +
        "Retain the inventory for a separate attribution assessment against paragraph 29; no currently supported packet can verify these candidates.";

    private static readonly HashSet<string> KnownNamespaces = new(StringComparer.Ordinal)
    {
        "",
        "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2013/01/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"
    };
    private static readonly string[] MsbuildSuffixes =
        [".props", ".targets", ".proj", ".tasks", ".overridetasks"];
    private static readonly string[] ScriptSuffixes = [".ps1", ".psm1", ".sh", ".cmd", ".bat"];
    private static readonly string[] SourceSuffixes =
        [".pp", ".razor", ".ts", ".mts", ".cts", ".cs", ".fs", ".vb", ".cpp",
         ".c", ".h", ".hpp", ".java", ".py"];
    private static readonly string[] CompiledSuffixes =
        [".dll", ".exe", ".so", ".dylib", ".a", ".wasm", ".class", ".pyd"];
    private static readonly string[] DeclarationSuffixes = [".d.ts", ".d.mts", ".d.cts"];
    private static readonly string[] PassiveSuffixes =
        [".md", ".txt", ".css", ".png", ".jpg", ".jpeg", ".gif",
         ".svg", ".pdb", ".p7s", ".map", ".psmdcp", ".d.ts", ".d.mts", ".d.cts"];
    private static readonly HashSet<string> SupportJson = new(StringComparer.Ordinal)
        { "package.json", "sbom.json", "provenance.json", "sourcelink.json", "readiness-bundler-manifest.json" };
    private static readonly Regex UnsafeXmlToken = new(
        @"<![\s\u001c-\u001f]*(?:DOCTYPE|ENTITY)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex PropertyFunction = new(
        @"\$\(\s*(?:\[[^\]]+\]\s*::|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\s*\()",
        RegexOptions.CultureInvariant);
    private static readonly Regex DeclarativeFullPath = new(
        @"\A\$\(\[System\.IO\.Path\]::GetFullPath\('\$\(MSBuildThisFileDirectory\)([A-Za-z0-9_.\-/\\]+)'\)\)\z",
        RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions PrettyJson = new()
    {
        WriteIndented = true,
        NewLine = "\n",
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public string RowId => "LP-10";
    public string ResolverId => "lp10-binary-attribution";
    public string Version => "1.1.0";

    private const int ProvenanceLimit = 4 * 1024 * 1024;
    private const string ProvenanceProducer = "lp10-gh-attestation-verify/1.0.0";
    private static readonly string[] ProvenanceRoles =
        ["package", "release-package", "provenance-bundle", "provenance-attestation", "source-archive"];

    public CaseResult Resolve(ResolverCase input)
    {
        if (input.Inputs.Count == 0)
            return Result(input, "missing-package", []);
        if (!input.CheckedInputs.TryGetValue("package", out var package))
            throw new InvalidDataException("LP-10 requires exactly one checked package input.");
        var scanned = ScanArchive(package.Content);
        if (input.Inputs.Count == 1)
        {
            if (input.Inputs[0].Role != "package")
                throw new InvalidDataException("LP-10 requires exactly one checked package input.");
            return Result(input, scanned.Branch, scanned.Records);
        }
        return ResolveProvenance(input, package, scanned.Branch, scanned.Records);
    }

    private static CaseResult Result(ResolverCase input, string branch, List<EntryRecord> records)
    {
        if (branch == "no-code-payload")
            return new("LP-10", "lp10-binary-attribution", "1.1.0", branch,
                "deterministic", "applicable", input.Inputs,
                ["package:archive", "package:nuspec/metadata"], NoCodeContract,
                NoCodeFinding, null, null, null);

        var (missing, required, category) = branch switch
        {
            "missing-package" => ("The package bytes required for LP-10 were not supplied.",
                "package", "input-owner"),
            "unreadable-package" => ("The supplied checked bytes are not a readable NuGet archive.",
                "valid-nupkg", "package-owner"),
            "unsafe-archive" => ("Unsafe, aliased or duplicate ZIP entry paths prevent an unambiguous safe inventory.",
                "safe-unambiguous-nupkg", "package-owner"),
            "ambiguous-nuspec" => ("The archive has multiple root nuspec entries.",
                "unique-root-nuspec", "package-owner"),
            "missing-nuspec" => ("The archive has no nuspec entry.",
                "root-nuspec", "package-owner"),
            "missing-root-nuspec" => ("The only nuspec entry is nested in a subfolder.",
                "root-nuspec", "package-owner"),
            "unsafe-nuspec" => ("The nuspec has a DTD/entity declaration or unsupported encoding and cannot be safely inspected.",
                "safe-nuspec", "package-owner"),
            "invalid-xml" => ("The nuspec XML is not well formed.",
                "valid-nuspec", "package-owner"),
            "foreign-root" => ("The package root is not in a recognized NuGet namespace.",
                "recognized-nuspec", "package-owner"),
            "invalid-metadata" => ("The nuspec requires exactly one recognized metadata element.",
                "valid-nuspec", "package-owner"),
            "ambiguous-metadata" => ("A foreign-namespace metadata sibling makes authoritative NuGet metadata ambiguous across readers.",
                "unambiguous-nuspec", "package-owner"),
            "incomplete-inventory" => ("A required entry or build XML exceeds inspection limits or cannot be safely parsed; the package inventory is incomplete.",
                "bounded-safely-inspectable-package", "package-owner"),
            "unsupported-executable-content" => ("An executable-looking payload or active build/markup construct cannot be safely classified for attribution.",
                "separate-attribution-assessment-outside-current-resolver", "assessment-limitation"),
            "compiled-attribution-unverified" => ("Packaged compiled code lacks verified per-entry ownership and correspondence to public release-commit builds or a referenced NuGet/npm upstream.",
                "separate-attribution-assessment-outside-current-resolver", "assessment-limitation"),
            "text-code-attribution-unverified" => ("Packaged executable source-form text lacks verified per-entry ownership and exact release-commit blob correspondence, a pinned reproducible build/transform, or referenced-upstream byte correspondence.",
                "separate-attribution-assessment-outside-current-resolver", "assessment-limitation"),
            "mixed-code-attribution-unverified" => ("Packaged compiled code and executable source-form text each lack verified per-entry source or referenced-upstream correspondence.",
                "separate-attribution-assessment-outside-current-resolver", "assessment-limitation"),
            _ => throw new InvalidDataException($"Unknown LP-10 branch: {branch}")
        };
        var structural = branch is "missing-package" or "unreadable-package" or "unsafe-archive" or
            "ambiguous-nuspec" or "missing-nuspec" or "missing-root-nuspec" or "unsafe-nuspec" or
            "invalid-xml" or "foreign-root" or "invalid-metadata" or "ambiguous-metadata" or
            "incomplete-inventory";
        if (branch is "unsupported-executable-content" or "compiled-attribution-unverified" or
            "text-code-attribution-unverified" or "mixed-code-attribution-unverified")
            missing += " " + AttributionLimit;
        return new("LP-10", "lp10-binary-attribution", "1.1.0", branch, "escalated",
            structural ? "unknown" : "applicable", input.Inputs,
            branch == "missing-package" ? [] : ["package:archive"],
            structural || records.Count == 0 ? null : CandidateContract(records),
            null, missing, required, category);
    }

    private static CaseResult ResolveProvenance(ResolverCase input, CheckedInput package,
        string branch, List<EntryRecord> records)
    {
        if (branch is not ("compiled-attribution-unverified" or "text-code-attribution-unverified" or
            "mixed-code-attribution-unverified"))
            return Result(input, branch, records);

        CaseResult Unverified(string detail) =>
            new("LP-10", "lp10-binary-attribution", "1.1.0", "provenance-unverified", "escalated",
                "applicable", input.Inputs,
                input.Inputs.Select(item => $"input:{item.Role}:{item.Sha256}")
                    .Distinct(StringComparer.Ordinal).ToArray(),
                CandidateContract(records), null,
                $"Supplied SLSA v1 build provenance and source correspondence packet could not be verified ({detail}); packaged code attribution remains unverified.",
                "verified-slsa-provenance-and-source-correspondence-packet", "provenance-investigation");

        if (input.Inputs.Count != ProvenanceRoles.Length ||
            input.Inputs.Select(item => item.Role).Distinct(StringComparer.Ordinal).Count() != ProvenanceRoles.Length ||
            input.Inputs.Any(item => !ProvenanceRoles.Contains(item.Role, StringComparer.Ordinal) ||
                !Lp02PublicSourceResolver.SafePath(item.Path)) ||
            !input.CheckedInputs.TryGetValue("release-package", out var releasePackage) ||
            !input.CheckedInputs.TryGetValue("provenance-bundle", out var provenanceBundle) ||
            !input.CheckedInputs.TryGetValue("provenance-attestation", out var provenanceAttestation) ||
            !input.CheckedInputs.TryGetValue("source-archive", out var sourceArchive))
            return Unverified("incomplete or unsupported provenance input roles");

        var (pkgState, declaration) = Lp02PublicSourceResolver.InspectPackage(package.Content);
        if (pkgState != "ready" || declaration is null ||
            !Lp02PublicSourceResolver.TryRepository(declaration.RepositoryUrl, declaration.Commit,
                out var repository, out _))
            return Unverified("package lacks a canonical GitHub repository URL and 40-hex commit declaration");

        var releaseScanned = ScanArchive(releasePackage.Content);
        if (releaseScanned.Branch != branch ||
            CandidateContract(releaseScanned.Records) != CandidateContract(records) ||
            !Lp02PublicSourceResolver.TryArchive(package.Content, out var packageEntries) ||
            !Lp02PublicSourceResolver.TryArchive(releasePackage.Content, out var releaseEntries))
            return Unverified("attested release package code inventory does not match the inspected package");

        var pkgNonSig = packageEntries.Where(kv =>
            !kv.Key.Equals(".signature.p7s", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
        var relNonSig = releaseEntries.Where(kv =>
            !kv.Key.Equals(".signature.p7s", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
        if (pkgNonSig.Count == 0 || pkgNonSig.Count != relNonSig.Count ||
            !pkgNonSig.All(kv => relNonSig.TryGetValue(kv.Key, out var relBytes) &&
                kv.Value.AsSpan().SequenceEqual(relBytes)))
            return Unverified("non-signature archive entries differ between the inspected package and attested release package");

        if (!TryVerifyProvenanceBundle(provenanceBundle.Content, releasePackage.Identity.Sha256,
                repository, declaration.Commit, out var workflowPath))
            return Unverified("Sigstore SLSA v1 provenance bundle does not bind the release package digest, GitHub-hosted workflow or declared commit");

        if (!TryVerifyProvenanceAttestation(provenanceAttestation.Content, package.Identity.Sha256,
                releasePackage.Identity.Sha256, provenanceBundle.Identity.Sha256,
                sourceArchive.Identity.Sha256, sourceArchive.Content.Length, repository, declaration.Commit, workflowPath))
            return Unverified("verified attestation receipt does not bind the provenance bundle, Fulcio OIDC certificate, transparency log or declared commit");

        if (!Lp02PublicSourceResolver.TryArchive(sourceArchive.Content, out var sourceFiles,
                declaration.Commit, sourceMembers: true) || sourceFiles.Count == 0)
            return Unverified("source archive is unreadable or outside the bounded GitHub source profile");

        var rootPrefix = repository.Split('/')[^1] + "-" + declaration.Commit + "/";
        if (!TrySourceRoot(sourceFiles, rootPrefix, out rootPrefix) ||
            !sourceFiles.Keys.Any(path => path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)) ||
            !sourceFiles.ContainsKey(rootPrefix + workflowPath))
            return Unverified("source archive does not match the declared repository/commit root, attested workflow path or C# project layout");

        var sourceDigests = sourceFiles.Values.Select(bytes => Catalog.Digest(bytes)).ToHashSet(StringComparer.Ordinal);
        var hasManifestEntry = HasBundlerManifestEntry(packageEntries);
        AttestedViteBuildPlan? vitePlan = null;
        if (!hasManifestEntry)
            TryResolveAttestedViteBuildPlan(packageEntries, sourceFiles, rootPrefix, workflowPath, declaration.Id, out vitePlan);
        var compiledCount = 0;
        var exactSourceTextCount = 0;
        var builtWebAssetTextCount = 0;
        var viteWebAssetTextCount = 0;
        foreach (var record in records.Where(item => item.Classification != "passive"))
        {
            if (record.Classification == "compiled")
            {
                if (!record.Path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                    record.Reason != "pe-signature" ||
                    sourceDigests.Contains(record.Sha256) ||
                    !packageEntries.TryGetValue(record.Path, out var dllBytes) ||
                    !VerifyAssemblyMetadataConsistency(dllBytes, repository, declaration.Commit) ||
                    !HasMatchingProject(record.Path, dllBytes, sourceFiles, rootPrefix))
                    return Unverified($"compiled candidate {record.Path} lacks a matching source project/output identity, has conflicting PE repository metadata or matches a prebuilt binary in source");
                compiledCount++;
            }
            else if (record.Classification == "text")
            {
                if (sourceDigests.Contains(record.Sha256))
                    exactSourceTextCount++;
                else if (record.Reason == "executable-source-text" &&
                    record.Path.StartsWith("staticwebassets/", StringComparison.OrdinalIgnoreCase) &&
                    (record.Path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                     record.Path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase)) &&
                    hasManifestEntry &&
                    TryBundlerAsset(packageEntries, sourceFiles, rootPrefix, record.Path, record.Sha256, out _))
                    builtWebAssetTextCount++;
                else if (record.Reason == "executable-source-text" &&
                    record.Path.StartsWith("staticwebassets/", StringComparison.OrdinalIgnoreCase) &&
                    (record.Path.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                     record.Path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase)) &&
                    !hasManifestEntry && vitePlan is not null &&
                    TryAttestedViteScriptAsset(vitePlan, sourceFiles, rootPrefix, record.Path))
                    viteWebAssetTextCount++;
                else
                    return Unverified($"text candidate {record.Path} lacks exact source-blob or attested web-asset build correspondence");
            }
            else
                return Unverified($"candidate {record.Path} has unsupported classification {record.Classification}");
        }

        var totalBuiltScripts = builtWebAssetTextCount + viteWebAssetTextCount;
        if (compiledCount + exactSourceTextCount + totalBuiltScripts == 0)
            return Unverified("no non-passive code candidates were evaluated");

        var scriptSummary = viteWebAssetTextCount > 0 && builtWebAssetTextCount == 0
            ? $"{viteWebAssetTextCount} attested Vite/npm build scripts"
            : $"{builtWebAssetTextCount} digest-bound bundler-manifest scripts";
        var finding =
            $"SLSA v1 build provenance and source correspondence verified for {declaration.Id} {declaration.Version} " +
            $"at repository {repository} commit {declaration.Commit}: verified by gh attestation verify (Sigstore Tlog + Fulcio OIDC " +
            $"issuer https://token.actions.githubusercontent.com on github-hosted runner, receipt bound by SHA-256) binding release package SHA-256 " +
            $"{releasePackage.Identity.Sha256} to workflow {workflowPath}@{declaration.Commit}; all {pkgNonSig.Count} non-signature " +
            $"archive entries in package {package.Identity.Sha256} match the attested release package byte-for-byte; and all " +
            $"{compiledCount + exactSourceTextCount + totalBuiltScripts} non-passive code candidates ({compiledCount} compiled PE/CLI " +
            $"assemblies with matching source project/output identities, consistent metadata and no prebuilt source-tree binary, {exactSourceTextCount} exact source-blob text " +
            $"matches, {scriptSummary}) correspond to the attested commit. " +
            "Project/output correspondence is not a reproducible-build or exhaustive workflow/dataflow proof.";
        return new("LP-10", "lp10-binary-attribution", "1.1.0", "provenance-attributed",
            "deterministic", "applicable", input.Inputs,
            input.Inputs.Select(item => $"input:{item.Role}:{item.Sha256}").ToArray(),
            CandidateContract(records), finding, null, null, null);
    }

    internal sealed record VerifiedProvenanceContext(
        Lp02Package Declaration,
        string Repository,
        string WorkflowPath,
        string ReleasePackageSha256,
        string RootPrefix,
        Dictionary<string, byte[]> PackageEntries,
        Dictionary<string, byte[]> SourceFiles);

    internal static bool TryVerifyProvenanceContext(ResolverCase input, CheckedInput package,
        out VerifiedProvenanceContext? context, out string error)
    {
        context = null;
        error = "";
        var lp10Result = new Lp10BinaryAttributionResolver().Resolve(input with { RowId = "LP-10" });
        if (lp10Result.BranchId != "provenance-attributed")
        {
            error = lp10Result.MissingFact ?? $"LP-10 provenance check returned {lp10Result.BranchId}";
            return false;
        }
        var releasePackage = input.CheckedInputs["release-package"];
        var provenanceBundle = input.CheckedInputs["provenance-bundle"];
        var sourceArchive = input.CheckedInputs["source-archive"];
        var (_, declaration) = Lp02PublicSourceResolver.InspectPackage(package.Content);
        if (declaration is null ||
            !Lp02PublicSourceResolver.TryRepository(declaration.RepositoryUrl, declaration.Commit, out var repository, out _) ||
            !TryVerifyProvenanceBundle(provenanceBundle.Content, releasePackage.Identity.Sha256, repository, declaration.Commit, out var workflowPath) ||
            !Lp02PublicSourceResolver.TryArchive(package.Content, out var packageEntries) ||
            !Lp02PublicSourceResolver.TryArchive(sourceArchive.Content, out var sourceFiles, declaration.Commit, sourceMembers: true))
        {
            error = "failed to reconstruct verified provenance context";
            return false;
        }
        var rootPrefix = repository.Split('/')[^1] + "-" + declaration.Commit + "/";
        if (!TrySourceRoot(sourceFiles, rootPrefix, out rootPrefix))
        {
            error = "source archive root differs from the declared repository/commit";
            return false;
        }
        context = new VerifiedProvenanceContext(declaration, repository, workflowPath,
            releasePackage.Identity.Sha256, rootPrefix, packageEntries, sourceFiles);
        return true;
    }

    private static string NormalizeRepoUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var trimmed = value.Trim().TrimEnd('/');
        return trimmed.EndsWith(".git", StringComparison.OrdinalIgnoreCase)
            ? trimmed[..^4] : trimmed;
    }

    private static bool TryVerifyProvenanceBundle(ReadOnlyMemory<byte> content, string releaseSha256,
        string expectedRepository, string expectedCommit, out string workflowPath)
    {
        workflowPath = "";
        if (content.Length is <= 0 or > ProvenanceLimit)
            return false;
        try
        {
            _ = StrictUtf8.GetCharCount(content.Span);
            using var doc = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 32 });
            if (!JsonStringValidation.IsWellFormed(doc.RootElement) ||
                doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;
            var bundles = new List<JsonElement>();
            if (doc.RootElement.TryGetProperty("attestations", out var attArray) &&
                attArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in attArray.EnumerateArray())
                    if (item.ValueKind == JsonValueKind.Object &&
                        item.TryGetProperty("bundle", out var inner) &&
                        inner.ValueKind == JsonValueKind.Object)
                        bundles.Add(inner);
            }
            else
                bundles.Add(doc.RootElement);

            foreach (var bundle in bundles)
            {
                if (!bundle.TryGetProperty("mediaType", out var mediaType) ||
                    mediaType.ValueKind != JsonValueKind.String ||
                    !(mediaType.GetString()?.StartsWith("application/vnd.dev.sigstore.bundle", StringComparison.Ordinal) ?? false) ||
                    !bundle.TryGetProperty("verificationMaterial", out var vm) ||
                    vm.ValueKind != JsonValueKind.Object ||
                    !vm.TryGetProperty("certificate", out var cert) ||
                    cert.ValueKind != JsonValueKind.Object ||
                    !cert.TryGetProperty("rawBytes", out var rawCert) ||
                    rawCert.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(rawCert.GetString()) ||
                    Convert.FromBase64String(rawCert.GetString()!).Length == 0 ||
                    !vm.TryGetProperty("tlogEntries", out var tlogs) ||
                    tlogs.ValueKind != JsonValueKind.Array ||
                    tlogs.GetArrayLength() == 0 ||
                    !tlogs[0].TryGetProperty("logIndex", out var logIndex) ||
                    logIndex.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(logIndex.GetString()) ||
                    !bundle.TryGetProperty("dsseEnvelope", out var dsse) ||
                    dsse.ValueKind != JsonValueKind.Object ||
                    !dsse.TryGetProperty("payloadType", out var payloadType) ||
                    payloadType.GetString() != "application/vnd.in-toto+json" ||
                    !dsse.TryGetProperty("signatures", out var sigs) ||
                    sigs.ValueKind != JsonValueKind.Array ||
                    sigs.GetArrayLength() == 0 ||
                    !sigs[0].TryGetProperty("sig", out var sig) ||
                    sig.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(sig.GetString()) ||
                    Convert.FromBase64String(sig.GetString()!).Length == 0 ||
                    !dsse.TryGetProperty("payload", out var payloadB64) ||
                    payloadB64.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(payloadB64.GetString()))
                    continue;

                var payloadBytes = Convert.FromBase64String(payloadB64.GetString()!);
                _ = StrictUtf8.GetCharCount(payloadBytes);
                using var stmtDoc = JsonDocument.Parse(payloadBytes, new JsonDocumentOptions { MaxDepth = 32 });
                var stmt = stmtDoc.RootElement;
                if (!JsonStringValidation.IsWellFormed(stmt) ||
                    stmt.ValueKind != JsonValueKind.Object ||
                    !stmt.TryGetProperty("_type", out var stmtType) ||
                    stmtType.GetString() != "https://in-toto.io/Statement/v1" ||
                    !stmt.TryGetProperty("predicateType", out var predType) ||
                    predType.GetString() != "https://slsa.dev/provenance/v1" ||
                    !stmt.TryGetProperty("subject", out var subjects) ||
                    subjects.ValueKind != JsonValueKind.Array ||
                    !subjects.EnumerateArray().Any(sub =>
                        sub.ValueKind == JsonValueKind.Object &&
                        sub.TryGetProperty("digest", out var dig) &&
                        dig.ValueKind == JsonValueKind.Object &&
                        dig.TryGetProperty("sha256", out var shaProp) &&
                        string.Equals(shaProp.GetString(), releaseSha256, StringComparison.OrdinalIgnoreCase)) ||
                    !stmt.TryGetProperty("predicate", out var pred) ||
                    pred.ValueKind != JsonValueKind.Object ||
                    !pred.TryGetProperty("buildDefinition", out var buildDef) ||
                    buildDef.ValueKind != JsonValueKind.Object ||
                    !buildDef.TryGetProperty("buildType", out var buildType) ||
                    buildType.GetString() != "https://actions.github.io/buildtypes/workflow/v1" ||
                    !buildDef.TryGetProperty("internalParameters", out var internalParams) ||
                    internalParams.ValueKind != JsonValueKind.Object ||
                    !internalParams.TryGetProperty("github", out var githubParams) ||
                    githubParams.ValueKind != JsonValueKind.Object ||
                    !githubParams.TryGetProperty("runner_environment", out var runnerEnv) ||
                    runnerEnv.GetString() != "github-hosted" ||
                    !buildDef.TryGetProperty("externalParameters", out var externalParams) ||
                    externalParams.ValueKind != JsonValueKind.Object ||
                    !externalParams.TryGetProperty("workflow", out var workflow) ||
                    workflow.ValueKind != JsonValueKind.Object ||
                    !workflow.TryGetProperty("repository", out var wfRepo) ||
                    !string.Equals(NormalizeRepoUrl(wfRepo.GetString()), expectedRepository, StringComparison.OrdinalIgnoreCase) ||
                    !workflow.TryGetProperty("path", out var wfPathProp) ||
                    wfPathProp.ValueKind != JsonValueKind.String ||
                    !(wfPathProp.GetString() is { } wfPath &&
                      wfPath.StartsWith(".github/workflows/", StringComparison.Ordinal) &&
                      !wfPath.Contains("..", StringComparison.Ordinal) &&
                      Lp02PublicSourceResolver.SafePath(wfPath)) ||
                    !buildDef.TryGetProperty("resolvedDependencies", out var deps) ||
                    deps.ValueKind != JsonValueKind.Array ||
                    !deps.EnumerateArray().Any(dep =>
                        dep.ValueKind == JsonValueKind.Object &&
                        dep.TryGetProperty("digest", out var depDig) &&
                        depDig.ValueKind == JsonValueKind.Object &&
                        depDig.TryGetProperty("gitCommit", out var gitCommit) &&
                        string.Equals(gitCommit.GetString(), expectedCommit, StringComparison.OrdinalIgnoreCase)))
                    continue;

                workflowPath = wfPath;
                return true;
            }
            return false;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or DecoderFallbackException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryVerifyProvenanceAttestation(ReadOnlyMemory<byte> content,
        string packageSha256, string releaseSha256, string bundleSha256, string sourceSha256, int sourceSize,
        string expectedRepository, string expectedCommit, string workflowPath)
    {
        if (content.Length is <= 0 or > ProvenanceLimit)
            return false;
        try
        {
            _ = StrictUtf8.GetCharCount(content.Span);
            using var doc = HelperAdmission.Open(content);
            if (doc is null) return false;
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !HasInt32Property(root, "schema_version", 1) ||
                !root.TryGetProperty("producer", out var producer) ||
                producer.GetString() != ProvenanceProducer ||
                !root.TryGetProperty("package_sha256", out var pkgSha) ||
                pkgSha.GetString() != packageSha256 ||
                !root.TryGetProperty("release_package_sha256", out var relSha) ||
                relSha.GetString() != releaseSha256 ||
                !root.TryGetProperty("provenance_bundle_sha256", out var bndSha) ||
                bndSha.GetString() != bundleSha256 ||
                !root.TryGetProperty("source_archive_sha256", out var srcSha) ||
                srcSha.GetString() != sourceSha256 ||
                !ValidSourceAcquisition(root, packageSha256, sourceSha256, sourceSize, expectedRepository, expectedCommit) ||
                !root.TryGetProperty("verification", out var verArray) ||
                verArray.ValueKind != JsonValueKind.Array ||
                verArray.GetArrayLength() == 0)
                return false;

            var expectedConfigPrefix = expectedRepository + "/" + workflowPath + "@";
            foreach (var entry in verArray.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object ||
                    !entry.TryGetProperty("verificationResult", out var vr) ||
                    vr.ValueKind != JsonValueKind.Object ||
                    !vr.TryGetProperty("mediaType", out var mediaType) ||
                    !(mediaType.GetString()?.StartsWith("application/vnd.dev.sigstore.verificationresult", StringComparison.Ordinal) ?? false) ||
                    !vr.TryGetProperty("verifiedTimestamps", out var timestamps) ||
                    timestamps.ValueKind != JsonValueKind.Array ||
                    !timestamps.EnumerateArray().Any(ts =>
                        ts.ValueKind == JsonValueKind.Object &&
                        ts.TryGetProperty("type", out var tsType) &&
                        tsType.GetString() == "Tlog") ||
                    !vr.TryGetProperty("signature", out var sig) ||
                    sig.ValueKind != JsonValueKind.Object ||
                    !sig.TryGetProperty("certificate", out var cert) ||
                    cert.ValueKind != JsonValueKind.Object ||
                    !cert.TryGetProperty("issuer", out var issuer) ||
                    issuer.GetString() != "https://token.actions.githubusercontent.com" ||
                    !cert.TryGetProperty("runnerEnvironment", out var runnerEnv) ||
                    runnerEnv.GetString() != "github-hosted" ||
                    !cert.TryGetProperty("sourceRepositoryVisibilityAtSigning", out var visibility) ||
                    visibility.GetString() != "public" ||
                    !cert.TryGetProperty("sourceRepositoryURI", out var repoUri) ||
                    !string.Equals(NormalizeRepoUrl(repoUri.GetString()), expectedRepository, StringComparison.OrdinalIgnoreCase) ||
                    !cert.TryGetProperty("sourceRepositoryDigest", out var repoDigest) ||
                    !string.Equals(repoDigest.GetString(), expectedCommit, StringComparison.OrdinalIgnoreCase) ||
                    !cert.TryGetProperty("buildConfigDigest", out var configDigest) ||
                    !string.Equals(configDigest.GetString(), expectedCommit, StringComparison.OrdinalIgnoreCase) ||
                    !cert.TryGetProperty("buildConfigURI", out var configUri) ||
                    !(configUri.GetString()?.StartsWith(expectedConfigPrefix, StringComparison.OrdinalIgnoreCase) ?? false) ||
                    !vr.TryGetProperty("statement", out var stmt) ||
                    stmt.ValueKind != JsonValueKind.Object ||
                    !stmt.TryGetProperty("predicateType", out var predType) ||
                    predType.GetString() != "https://slsa.dev/provenance/v1" ||
                    !stmt.TryGetProperty("subject", out var subjects) ||
                    subjects.ValueKind != JsonValueKind.Array ||
                    !subjects.EnumerateArray().Any(sub =>
                        sub.ValueKind == JsonValueKind.Object &&
                        sub.TryGetProperty("digest", out var dig) &&
                        dig.ValueKind == JsonValueKind.Object &&
                        dig.TryGetProperty("sha256", out var shaProp) &&
                        string.Equals(shaProp.GetString(), releaseSha256, StringComparison.OrdinalIgnoreCase)))
                    continue;
                return true;
            }
            return false;
        }
        catch (Exception ex) when (ex is JsonException or DecoderFallbackException or InvalidOperationException or KeyNotFoundException)
        {
            return false;
        }

    }

    private static bool ValidSourceAcquisition(JsonElement receipt, string packageSha, string sourceSha,
        int sourceSize, string repository, string commit)
    {
        if (!receipt.TryGetProperty("source_acquisition", out var acquisition) ||
            acquisition.ValueKind != JsonValueKind.Object) return false;
        var retrieval = acquisition.GetProperty("retrieval_attempt");
        var capture = acquisition.GetProperty("capture_receipt");
        return acquisition.GetProperty("producer").GetString() == Lp02PublicSourceResolver.Producer &&
            acquisition.GetProperty("package_sha256").GetString() == packageSha &&
            string.Equals(acquisition.GetProperty("repository_url").GetString(), repository, StringComparison.OrdinalIgnoreCase) &&
            acquisition.GetProperty("commit").GetString() == commit &&
            HasInt32Property(acquisition, "archive_size", sourceSize) &&
            retrieval.GetProperty("url").GetString() == "https://codeload.github.com/" +
                repository["https://github.com/".Length..] + "/zip/" + commit &&
            retrieval.GetProperty("transport").GetString() == Lp02PublicSourceResolver.Transport &&
            retrieval.GetProperty("result").GetString() == "retrieved" &&
            HasInt32Property(retrieval, "http_status", 200) &&
            capture.GetProperty("role").GetString() == "source-archive" &&
            capture.GetProperty("sha256").GetString() == sourceSha;
    }

    private static bool HasInt32Property(JsonElement element, string name, int expected) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt32(out var number) && number == expected;

    internal static bool TrySourceRoot(Dictionary<string, byte[]> files, string expected, out string actual)
    {
        actual = files.Count == 0 ? "" : files.Keys.First().Split('/')[0] + "/";
        var prefix = actual;
        return actual.Equals(expected, StringComparison.OrdinalIgnoreCase) &&
            files.Keys.All(path => path.StartsWith(prefix, StringComparison.Ordinal));
    }

    private static bool HasAnyConditionAttribute(XElement element) =>
        element.Attributes().Any(attribute => attribute.Name.LocalName.Equals("Condition", StringComparison.OrdinalIgnoreCase));

    internal static bool HasMatchingProject(string assetPath, byte[] dll, Dictionary<string, byte[]> files, string prefix)
    {
        using var pe = new PEReader(new MemoryStream(dll, writable: false));
        if (!pe.HasMetadata) return false;
        var metadata = pe.GetMetadataReader();
        var name = metadata.GetString(metadata.GetAssemblyDefinition().Name);
        if (Path.GetFileNameWithoutExtension(assetPath) != name) return false;
        foreach (var (path, bytes) in files.Where(item => item.Key.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                using var reader = XmlReader.Create(new MemoryStream(bytes), new XmlReaderSettings
                { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = XmlLimit });
                var project = XDocument.Load(reader);
                var root = project.Root;
                var names = project.Descendants().Where(item =>
                    item.Name.LocalName.Equals("AssemblyName", StringComparison.OrdinalIgnoreCase)).ToArray();
                if (root is null || root.Name.LocalName != "Project" ||
                    root.Name.NamespaceName is not ("" or MsbuildNamespace) ||
                    HasAnyConditionAttribute(root) || names.Length > 1 ||
                    names.Any(item => item.HasAttributes || item.HasElements ||
                        item.Name != root.Name.Namespace + "AssemblyName" ||
                        item.Parent?.Name != root.Name.Namespace + "PropertyGroup" ||
                        item.Parent?.Parent != root ||
                        item.Ancestors().Any(HasAnyConditionAttribute))) continue;
                var output = names.Length == 1 ? names[0].Value.Trim() : Path.GetFileNameWithoutExtension(path);
                if (output.Contains("$(", StringComparison.Ordinal) || output.Contains("@(", StringComparison.Ordinal) ||
                    output.Contains("%(", StringComparison.Ordinal)) continue;
                if (output == name && path.StartsWith(prefix, StringComparison.Ordinal)) return true;
            }
            catch (XmlException) { }
        }
        return false;
    }

    internal static bool TryBundlerAsset(Dictionary<string, byte[]> packageFiles,
        Dictionary<string, byte[]> sourceFiles, string prefix, string assetPath, string digest,
        out HashSet<(string Name, string Version)> components)
    {
        components = [];
        if (!packageFiles.TryGetValue("readiness-bundler-manifest.json", out var bytes) || bytes.Length > XmlLimit)
            return false;
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            if (!JsonStringValidation.IsWellFormed(doc.RootElement) ||
                !HasInt32Property(doc.RootElement, "schema_version", 1)) return false;
            var assets = doc.RootElement.GetProperty("assets").EnumerateArray().ToArray();
            if (assets.Length is 0 or > 4096 ||
                assets.Select(a => a.GetProperty("path").GetString()).Distinct(StringComparer.Ordinal).Count() != assets.Length)
                return false;
            var matches = assets.Where(a => a.GetProperty("path").GetString() == assetPath).ToArray();
            if (matches.Length != 1 || matches[0].GetProperty("sha256").GetString() != digest) return false;
            var inputs = matches[0].GetProperty("inputs").EnumerateArray().ToArray();
            if (inputs.Length is 0 or > 4096 || inputs.Any(i =>
                !Lp02PublicSourceResolver.SafeSourceMemberPath(i.GetProperty("path").GetString()) ||
                !sourceFiles.TryGetValue(prefix + i.GetProperty("path").GetString(), out var source) ||
                Catalog.Digest(source) != i.GetProperty("sha256").GetString())) return false;
            foreach (var component in matches[0].GetProperty("components").EnumerateArray())
            {
                var name = component.GetProperty("name").GetString();
                var version = component.GetProperty("version").GetString();
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(version) ||
                    !components.Add((name, version)) || components.Count > 128) return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException)
        {
            return false;
        }
    }

    private static readonly string[] ViteNonShippingPrefixes =
        ["samples/", "tests/", "test/", "demos/", "docs/", "stories/", "templates/", "benchmarks/"];
    private static readonly string[] ViteThirdPartyDirMarkers =
        ["/node_modules/", "/vendor/", "/third_party/", "/third-party/", "/external/", "/bower_components/", "/lib/", "/libs/"];
    private static readonly string[] ViteConfigNames =
        ["vite.config.mts", "vite.config.ts", "vite.config.mjs", "vite.config.js"];

    internal sealed record AttestedViteBuildPlan(
        string NpmDirPrefix,
        string OutDir,
        string? LicenseFileName,
        HashSet<string> ExactScriptFileNames,
        HashSet<string> InitializerBaseNames,
        HashSet<string> ChunkNames,
        HashSet<(string Dependency, string Subdir)> CopiedDependencyDirs);

    internal static bool HasBundlerManifestEntry(Dictionary<string, byte[]> packageFiles) =>
        packageFiles.Keys.Any(k => k.Equals("readiness-bundler-manifest.json", StringComparison.OrdinalIgnoreCase) ||
            k.EndsWith("/readiness-bundler-manifest.json", StringComparison.OrdinalIgnoreCase));

    internal static bool TryResolveAttestedViteBuildPlan(
        Dictionary<string, byte[]> packageFiles,
        Dictionary<string, byte[]> sourceFiles,
        string rootPrefix,
        string workflowPath,
        string packageId,
        out AttestedViteBuildPlan? plan)
    {
        plan = null;
        if (HasBundlerManifestEntry(packageFiles))
            return false;

        var pkgJsonDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var lockJsonDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hasShippingTsSource = false;
        foreach (var fullPath in sourceFiles.Keys)
        {
            if (!fullPath.StartsWith(rootPrefix, StringComparison.Ordinal))
                continue;
            var rel = fullPath[rootPrefix.Length..];
            if (ViteNonShippingPrefixes.Any(p => rel.StartsWith(p, StringComparison.OrdinalIgnoreCase)) ||
                ViteThirdPartyDirMarkers.Any(m => ("/" + rel).Contains(m, StringComparison.OrdinalIgnoreCase)))
                continue;
            var slash = rel.LastIndexOf('/');
            var dir = slash >= 0 ? rel[..(slash + 1)] : "";
            var file = slash >= 0 ? rel[(slash + 1)..] : rel;
            if (file.Equals("package.json", StringComparison.OrdinalIgnoreCase))
                pkgJsonDirs.Add(dir);
            else if (file.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase))
                lockJsonDirs.Add(dir);
            else if ((file.EndsWith(".ts", StringComparison.OrdinalIgnoreCase) ||
                      file.EndsWith(".mts", StringComparison.OrdinalIgnoreCase)) &&
                     !file.EndsWith(".d.ts", StringComparison.OrdinalIgnoreCase) &&
                     !file.EndsWith(".d.mts", StringComparison.OrdinalIgnoreCase) &&
                     !ViteConfigNames.Contains(file, StringComparer.OrdinalIgnoreCase))
                hasShippingTsSource = true;
        }
        if (!hasShippingTsSource || pkgJsonDirs.Count != 1 || lockJsonDirs.Count != 1)
            return false;
        var npmDir = pkgJsonDirs.First();
        if (!npmDir.Equals(lockJsonDirs.First(), StringComparison.Ordinal) ||
            npmDir is not ("" or "src/"))
            return false;

        if (!sourceFiles.TryGetValue(rootPrefix + npmDir + "package.json", out var pkgJsonBytes) ||
            pkgJsonBytes.Length > XmlLimit ||
            !sourceFiles.TryGetValue(rootPrefix + npmDir + "package-lock.json", out var lockJsonBytes) ||
            lockJsonBytes.Length > LockfileLimit ||
            !sourceFiles.TryGetValue(rootPrefix + workflowPath, out var wfBytes) ||
            wfBytes.Length > XmlLimit)
            return false;

        var viteConfigMatches = ViteConfigNames
            .Where(name => sourceFiles.ContainsKey(rootPrefix + npmDir + name))
            .ToArray();
        if (viteConfigMatches.Length != 1 ||
            !sourceFiles.TryGetValue(rootPrefix + npmDir + viteConfigMatches[0], out var viteConfigBytes) ||
            viteConfigBytes.Length > XmlLimit)
            return false;

        string pkgJsonText, lockJsonText, wfText, viteConfigText;
        try
        {
            pkgJsonText = StrictUtf8.GetString(StripBom(pkgJsonBytes));
            lockJsonText = StrictUtf8.GetString(StripBom(lockJsonBytes));
            wfText = StrictUtf8.GetString(StripBom(wfBytes));
            viteConfigText = StrictUtf8.GetString(StripBom(viteConfigBytes));
            if (pkgJsonText.Contains('\0') || lockJsonText.Contains('\0') ||
                wfText.Contains('\0') || viteConfigText.Contains('\0'))
                return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        var directDeps = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            using var pkgDoc = JsonDocument.Parse(pkgJsonText, new JsonDocumentOptions { MaxDepth = 32 });
            if (!JsonStringValidation.IsWellFormed(pkgDoc.RootElement) ||
                pkgDoc.RootElement.ValueKind != JsonValueKind.Object ||
                !pkgDoc.RootElement.TryGetProperty("scripts", out var scripts) ||
                scripts.ValueKind != JsonValueKind.Object ||
                !scripts.TryGetProperty("build", out var buildProp) ||
                buildProp.ValueKind != JsonValueKind.String)
                return false;
            var buildScript = buildProp.GetString() ?? "";
            if (!HasValidViteBuildScript(buildScript) ||
                HasDisallowedPackageJsonLifecycleScripts(scripts))
                return false;
            if (!Lp04NoticeCoverageResolver.TryParsePackageJsonDependencies(
                    pkgJsonBytes, out var declaredDeps, out var hasUnsupportedDeps) ||
                hasUnsupportedDeps)
                return false;
            foreach (var kv in declaredDeps)
                directDeps[kv.Key] = kv.Value;

            using var lockDoc = JsonDocument.Parse(lockJsonText, new JsonDocumentOptions { MaxDepth = 64 });
            if (!JsonStringValidation.IsWellFormed(lockDoc.RootElement) ||
                lockDoc.RootElement.ValueKind != JsonValueKind.Object ||
                !lockDoc.RootElement.TryGetProperty("lockfileVersion", out var lvProp) ||
                lvProp.ValueKind != JsonValueKind.Number ||
                !lvProp.TryGetInt32(out var lv) || lv < 2 ||
                !Lp04NoticeCoverageResolver.TryResolveLockClosure(
                    lockJsonBytes, directDeps, out _, requireLicense: false))
                return false;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return false;
        }

        if (!VerifyWorkflowRunsNpmBuildInSingleJob(wfText, npmDir))
            return false;

        if (!TryParseViteConfig(viteConfigText, packageId, directDeps.Keys, sourceFiles, rootPrefix, npmDir, out plan))
            return false;

        return true;
    }

    private static ReadOnlySpan<byte> StripBom(byte[] bytes)
    {
        var span = bytes.AsSpan();
        return span.StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? span[3..] : span;
    }

    private static readonly string[] DisallowedLifecycleScripts =
        ["prebuild", "postbuild", "preinstall", "install", "postinstall", "preprepare", "postprepare", "prepublish", "prepublishOnly", "dependencies"];

    private static bool HasDisallowedPackageJsonLifecycleScripts(JsonElement scripts)
    {
        foreach (var hook in DisallowedLifecycleScripts)
        {
            if (scripts.TryGetProperty(hook, out _))
                return true;
        }
        if (scripts.TryGetProperty("prepare", out var prepProp))
        {
            if (prepProp.ValueKind != JsonValueKind.String)
                return true;
            var prep = (prepProp.GetString() ?? "").Trim();
            if (!Regex.IsMatch(prep, @"\Agit\s+config\s+core\.hooksPath\s+[A-Za-z0-9._/\-]+\z", RegexOptions.CultureInvariant))
                return true;
        }
        return false;
    }

    private static bool HasValidViteBuildScript(string script)
    {
        if (string.IsNullOrWhiteSpace(script) ||
            script.Contains("||", StringComparison.Ordinal) ||
            script.Contains(';') ||
            script.Contains('\n') ||
            script.Contains('\r') ||
            script.Contains('`') ||
            script.Contains('$'))
            return false;

        var hasViteBuild = false;
        foreach (var segment in script.Split("&&", StringSplitOptions.None))
        {
            var trimmed = segment.Trim();
            if (trimmed.Length == 0)
                return false;
            if (Regex.IsMatch(trimmed, @"\A(?:npx\s+)?vite\s+build\z", RegexOptions.CultureInvariant))
            {
                hasViteBuild = true;
            }
            else if (!Regex.IsMatch(trimmed, @"\A(?:npx\s+)?tsc(?:\s+(?:--noEmit|-p\s+[A-Za-z0-9._/\-]+))*\z", RegexOptions.CultureInvariant))
            {
                return false;
            }
        }
        return hasViteBuild;
    }

    private sealed class WorkflowStepRecord
    {
        public int PropIndent { get; set; } = -1;
        public string WorkingDir { get; set; } = "";
        public bool HasIf { get; set; }
        public bool HasContinueOnError { get; set; }
        public bool HasUses { get; set; }
        public List<string> RunLines { get; } = [];
    }

    private static bool TryParseYamlKeyValue(string text, out string key, out string val)
    {
        key = "";
        val = "";
        var m = Regex.Match(text,
            @"\A(?:'(?<sq>[^'\r\n]+)'|""(?<dq>[^""\\\r\n]+)""|(?<uq>[A-Za-z0-9_-]+))\s*:(?:\s*(?<val>.*)|\z)",
            RegexOptions.CultureInvariant);
        if (!m.Success)
            return false;
        key = m.Groups["sq"].Success ? m.Groups["sq"].Value
            : m.Groups["dq"].Success ? m.Groups["dq"].Value
            : m.Groups["uq"].Value;
        val = m.Groups["val"].Success ? m.Groups["val"].Value.Trim() : "";
        return true;
    }

    private static bool TryNormalizeWorkflowDir(string rawDir, out string normalized)
    {
        normalized = "";
        var trimmed = rawDir.Trim();
        if (trimmed.Length == 0 || trimmed is "." or "./")
            return true;
        if (trimmed.StartsWith('/') || trimmed.StartsWith('\\') || trimmed.Contains('\\'))
            return false;
        if (trimmed.StartsWith("./", StringComparison.Ordinal))
            trimmed = trimmed[2..];
        trimmed = trimmed.TrimEnd('/');
        if (trimmed.Length == 0)
            return true;
        var parts = trimmed.Split('/');
        if (parts.Any(p => p.Length == 0 || p is "." or ".."))
            return false;
        normalized = string.Join("/", parts);
        return true;
    }

    private static bool VerifyWorkflowRunsNpmBuildInSingleJob(string wfText, string npmDir)
    {
        var expectedWorkDir = npmDir.TrimEnd('/');
        var inJobs = false;
        var jobsIndent = -1;
        var currentJobIndent = -1;
        var jobPropIndent = -1;
        var inJobDefaults = false;
        var jobDefaultsIndent = -1;
        var inJobDefaultsRun = false;
        var jobDefaultsRunIndent = -1;
        var jobWorkDir = "";
        var jobHasIf = false;
        var jobHasContinueOnError = false;
        var inSteps = false;
        var stepsPropIndent = -1;
        var stepItemIndent = -1;
        var inRunBlock = false;
        var inFoldedRunBlock = false;
        var runBlockIndent = -1;
        WorkflowStepRecord? currentStep = null;
        var jobSteps = new List<WorkflowStepRecord>();

        void FlushStep()
        {
            if (currentStep is not null)
            {
                jobSteps.Add(currentStep);
                currentStep = null;
            }
            inRunBlock = false;
            inFoldedRunBlock = false;
        }

        bool EvaluateJob()
        {
            FlushStep();
            if (jobHasIf || jobHasContinueOnError)
                return false;
            var hasInstall = false;
            var hasBuild = false;
            var hasDotnetBuildOrPack = false;
            foreach (var step in jobSteps)
            {
                if (step.HasUses || step.HasIf || step.HasContinueOnError || step.RunLines.Count == 0)
                    continue;
                var rawDir = !string.IsNullOrEmpty(step.WorkingDir) ? step.WorkingDir : jobWorkDir;
                var isExpectedNpmDir = TryNormalizeWorkflowDir(rawDir, out var effectiveDir) &&
                                       string.Equals(effectiveDir, expectedWorkDir, StringComparison.Ordinal);
                foreach (var cmdLine in step.RunLines)
                {
                    if (cmdLine.Contains("||", StringComparison.Ordinal))
                        continue;
                    foreach (var segment in Regex.Split(cmdLine, @"&&|;"))
                    {
                        var rawCmd = segment.Trim();
                        if (rawCmd.Length == 0)
                            continue;
                        if (isExpectedNpmDir &&
                            Regex.IsMatch(rawCmd, @"\Anpm\s+ci\z", RegexOptions.CultureInvariant))
                        {
                            hasInstall = true;
                        }
                        else if (hasInstall && isExpectedNpmDir &&
                                 Regex.IsMatch(rawCmd, @"\Anpm\s+run(?:-script)?\s+build\z", RegexOptions.CultureInvariant))
                        {
                            hasBuild = true;
                        }
                        else if (hasInstall && hasBuild)
                        {
                            var cmd = rawCmd.TrimEnd('`').Trim();
                            if (Regex.IsMatch(cmd, @"\Adotnet\s+(?:build|pack)(?:\s+|\z)", RegexOptions.CultureInvariant))
                                hasDotnetBuildOrPack = true;
                        }
                    }
                }
            }
            return hasInstall && hasBuild && hasDotnetBuildOrPack;
        }

        void ResetJob()
        {
            FlushStep();
            jobSteps.Clear();
            jobPropIndent = -1;
            inJobDefaults = false;
            jobDefaultsIndent = -1;
            inJobDefaultsRun = false;
            jobDefaultsRunIndent = -1;
            jobWorkDir = "";
            jobHasIf = false;
            jobHasContinueOnError = false;
            inSteps = false;
            stepsPropIndent = -1;
            stepItemIndent = -1;
            inRunBlock = false;
        }

        var hasQualifyingJob = false;

        foreach (var rawLine in wfText.Split('\n'))
        {
            var line = StripYamlComment(rawLine.TrimEnd('\r'));
            if (string.IsNullOrWhiteSpace(line))
                continue;
            var indent = line.Length - line.TrimStart(' ').Length;
            var trimmed = line.Trim();

            if (inRunBlock)
            {
                if (indent > runBlockIndent)
                {
                    if (!inFoldedRunBlock)
                        currentStep?.RunLines.Add(trimmed);
                    continue;
                }
                inRunBlock = false;
                inFoldedRunBlock = false;
            }

            if (indent == 0)
            {
                if (EvaluateJob())
                    hasQualifyingJob = true;
                ResetJob();
                if (TryParseYamlKeyValue(trimmed, out var topKey, out var topVal))
                {
                    if (topKey == "defaults")
                        return false;
                    inJobs = topKey == "jobs" && topVal.Length == 0;
                }
                else if (trimmed.StartsWith('"') && trimmed.Contains('\\'))
                {
                    return false;
                }
                else
                {
                    inJobs = false;
                }
                jobsIndent = inJobs ? 0 : -1;
                currentJobIndent = -1;
                continue;
            }

            if (!inJobs)
                continue;

            if (currentJobIndent < 0 || indent <= currentJobIndent)
            {
                if (EvaluateJob())
                    hasQualifyingJob = true;
                ResetJob();
                currentJobIndent = -1;
                if (indent > jobsIndent)
                {
                    if (!TryParseYamlKeyValue(trimmed, out _, out var jobHeaderVal) ||
                        jobHeaderVal.Length != 0)
                        return false;
                    currentJobIndent = indent;
                }
                continue;
            }

            if (inSteps)
            {
                var isDashLine = trimmed == "-" || trimmed.StartsWith("- ", StringComparison.Ordinal);
                if ((stepItemIndent >= 0 && (indent < stepItemIndent || (indent == stepsPropIndent && !isDashLine))) ||
                    (stepItemIndent < 0 && indent <= stepsPropIndent && !isDashLine))
                {
                    FlushStep();
                    inSteps = false;
                    stepsPropIndent = -1;
                    stepItemIndent = -1;
                }
            }

            if (!inSteps)
            {
                if (jobPropIndent < 0)
                    jobPropIndent = indent;

                if (indent == jobPropIndent)
                {
                    inJobDefaults = false;
                    inJobDefaultsRun = false;
                    if (!TryParseYamlKeyValue(trimmed, out var jKey, out var jVal))
                    {
                        jobHasIf = true;
                        continue;
                    }
                    if (jKey == "steps")
                    {
                        if (jVal.Length == 0)
                        {
                            inSteps = true;
                            stepsPropIndent = indent;
                            stepItemIndent = -1;
                        }
                        else
                        {
                            jobHasIf = true;
                        }
                    }
                    else if (jKey == "defaults")
                    {
                        if (jVal.Length == 0)
                        {
                            inJobDefaults = true;
                            jobDefaultsIndent = indent;
                        }
                        else
                        {
                            jobHasIf = true;
                        }
                    }
                    else if (jKey == "if")
                    {
                        jobHasIf = true;
                    }
                    else if (jKey == "continue-on-error")
                    {
                        var val = jVal.Trim('\'', '"');
                        if (val.Contains('\\') || !val.Equals("false", StringComparison.OrdinalIgnoreCase))
                            jobHasContinueOnError = true;
                    }
                }
                else if (inJobDefaults && indent > jobDefaultsIndent)
                {
                    if (!TryParseYamlKeyValue(trimmed, out var dKey, out var dVal))
                    {
                        jobHasIf = true;
                        continue;
                    }
                    if (!inJobDefaultsRun || indent <= jobDefaultsRunIndent)
                    {
                        if (dKey == "run" && dVal.Length == 0)
                        {
                            inJobDefaultsRun = true;
                            jobDefaultsRunIndent = indent;
                        }
                        else
                        {
                            jobHasIf = true;
                        }
                    }
                    else if (inJobDefaultsRun && indent > jobDefaultsRunIndent)
                    {
                        if (dKey == "working-directory" && !dVal.Contains('\\'))
                            jobWorkDir = dVal.Trim('\'', '"');
                        else if (dKey == "shell" && !dVal.Contains('\\'))
                        {
                            var sh = dVal.Trim('\'', '"');
                            if (sh is not ("bash" or "sh" or "pwsh" or "powershell" or "cmd"))
                                jobHasIf = true;
                        }
                        else
                        {
                            jobHasIf = true;
                        }
                    }
                }
                continue;
            }

            var isStepStart = (stepItemIndent < 0 && indent >= stepsPropIndent || indent == stepItemIndent) &&
                              (trimmed == "-" || trimmed.StartsWith("- ", StringComparison.Ordinal));
            string stepPropText;
            if (isStepStart)
            {
                if (stepItemIndent < 0)
                    stepItemIndent = indent;
                FlushStep();
                if (trimmed == "-")
                {
                    currentStep = new WorkflowStepRecord { PropIndent = -1 };
                    continue;
                }
                var afterDash = trimmed[2..].TrimStart();
                currentStep = new WorkflowStepRecord
                {
                    PropIndent = indent + (trimmed.Length - afterDash.Length)
                };
                stepPropText = afterDash;
            }
            else
            {
                if (currentStep is null)
                    continue;
                if (currentStep.PropIndent < 0 && indent > stepItemIndent)
                    currentStep.PropIndent = indent;
                if (indent != currentStep.PropIndent)
                    continue;
                stepPropText = trimmed;
            }

            if (!TryParseYamlKeyValue(stepPropText, out var sKey, out var sVal))
            {
                currentStep.HasIf = true;
                continue;
            }

            if (sKey == "uses")
            {
                currentStep.HasUses = true;
            }
            else if (sKey == "if")
            {
                currentStep.HasIf = true;
            }
            else if (sKey == "continue-on-error")
            {
                var val = sVal.Trim('\'', '"');
                if (val.Contains('\\') || !val.Equals("false", StringComparison.OrdinalIgnoreCase))
                    currentStep.HasContinueOnError = true;
            }
            else if (sKey == "working-directory")
            {
                if (sVal.Contains('\\'))
                    currentStep.HasIf = true;
                else
                    currentStep.WorkingDir = sVal.Trim('\'', '"');
            }
            else if (sKey == "shell")
            {
                var sh = sVal.Trim('\'', '"');
                if (sVal.Contains('\\') || sh is not ("bash" or "sh" or "pwsh" or "powershell" or "cmd"))
                    currentStep.HasIf = true;
            }
            else if (sKey == "run")
            {
                if (sVal is "|" or "|-" or "|+")
                {
                    inRunBlock = true;
                    inFoldedRunBlock = false;
                    runBlockIndent = currentStep.PropIndent;
                }
                else if (sVal.StartsWith('>'))
                {
                    inRunBlock = true;
                    inFoldedRunBlock = true;
                    runBlockIndent = currentStep.PropIndent;
                }
                else if (sVal.Length > 0)
                {
                    currentStep.RunLines.Add(sVal.Trim('\'', '"'));
                }
            }
        }

        if (EvaluateJob())
            hasQualifyingJob = true;
        return hasQualifyingJob;
    }

    private static string StripYamlComment(string line)
    {
        var inSingle = false;
        var inDouble = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '\'' && !inDouble) inSingle = !inSingle;
            else if (c == '"' && !inSingle) inDouble = !inDouble;
            else if (c == '#' && !inSingle && !inDouble && (i == 0 || char.IsWhiteSpace(line[i - 1])))
                return line[..i];
        }
        return line;
    }

    private static void StripAndMaskJs(string text, out string stripped, out string masked)
    {
        var sbStripped = new StringBuilder(text.Length);
        var sbMasked = new StringBuilder(text.Length);
        char lastNonSpaceInMask = '\0';
        var i = 0;
        while (i < text.Length)
        {
            var c = text[i];
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '/')
            {
                i += 2;
                while (i < text.Length && text[i] is not ('\r' or '\n'))
                    i++;
                continue;
            }
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < text.Length && !(text[i] == '*' && text[i + 1] == '/'))
                {
                    if (text[i] == '\n')
                    {
                        sbStripped.Append('\n');
                        sbMasked.Append('\n');
                    }
                    i++;
                }
                if (i + 1 < text.Length)
                    i += 2;
                else
                    break;
                continue;
            }
            if (c is '\'' or '"' or '`')
            {
                var quote = c;
                sbStripped.Append(c);
                sbMasked.Append(c);
                i++;
                while (i < text.Length)
                {
                    var sc = text[i];
                    if (sc == '\\' && i + 1 < text.Length)
                    {
                        sbStripped.Append(sc);
                        sbStripped.Append(text[i + 1]);
                        sbMasked.Append(sc == '\n' ? '\n' : ' ');
                        sbMasked.Append(text[i + 1] == '\n' ? '\n' : ' ');
                        i += 2;
                        continue;
                    }
                    if (sc == quote)
                    {
                        sbStripped.Append(sc);
                        sbMasked.Append(sc);
                        i++;
                        break;
                    }
                    sbStripped.Append(sc);
                    sbMasked.Append(sc == '\n' ? '\n' : ' ');
                    i++;
                }
                lastNonSpaceInMask = quote;
                continue;
            }
            if (c == '/' && lastNonSpaceInMask is ':' or '=' or '(' or '[' or ',' or '!' or '&' or '|' or '?' or '{' or ';' or '\0')
            {
                sbStripped.Append(c);
                sbMasked.Append(c);
                i++;
                var inCharClass = false;
                while (i < text.Length && text[i] is not ('\r' or '\n'))
                {
                    var rc = text[i];
                    if (rc == '\\' && i + 1 < text.Length)
                    {
                        sbStripped.Append(rc);
                        sbStripped.Append(text[i + 1]);
                        sbMasked.Append("  ");
                        i += 2;
                        continue;
                    }
                    if (rc == '[') inCharClass = true;
                    else if (rc == ']') inCharClass = false;
                    if (rc == '/' && !inCharClass)
                    {
                        sbStripped.Append(rc);
                        sbMasked.Append(rc);
                        i++;
                        break;
                    }
                    sbStripped.Append(rc);
                    sbMasked.Append(' ');
                    i++;
                }
                while (i < text.Length && char.IsLetter(text[i]))
                {
                    sbStripped.Append(text[i]);
                    sbMasked.Append(' ');
                    i++;
                }
                lastNonSpaceInMask = '/';
                continue;
            }
            sbStripped.Append(c);
            sbMasked.Append(c);
            if (!char.IsWhiteSpace(c))
                lastNonSpaceInMask = c;
            i++;
        }
        stripped = sbStripped.ToString();
        masked = sbMasked.ToString();
    }

    private static bool TryExtractBalancedSlice(
        string stripped,
        string masked,
        int openIdx,
        char openChar,
        char closeChar,
        out string bodyStripped,
        out string bodyMasked,
        out int closeIdx)
    {
        bodyStripped = "";
        bodyMasked = "";
        closeIdx = -1;
        if (openIdx < 0 || openIdx >= masked.Length || masked[openIdx] != openChar)
            return false;
        var depth = 0;
        for (var i = openIdx; i < masked.Length; i++)
        {
            var c = masked[i];
            if (c == openChar)
                depth++;
            else if (c == closeChar)
            {
                depth--;
                if (depth == 0)
                {
                    closeIdx = i;
                    bodyStripped = stripped[(openIdx + 1)..closeIdx];
                    bodyMasked = masked[(openIdx + 1)..closeIdx];
                    return true;
                }
            }
        }
        return false;
    }

    private static bool TryParseViteConfig(
        string viteConfigText,
        string packageId,
        IEnumerable<string> directDeps,
        Dictionary<string, byte[]> sourceFiles,
        string rootPrefix,
        string npmDir,
        out AttestedViteBuildPlan? plan)
    {
        plan = null;
        StripAndMaskJs(viteConfigText, out var stripped, out var masked);
        var exportMatches = Regex.Matches(masked, @"\bexport\s+default\s+defineConfig\s*\(", RegexOptions.CultureInvariant);
        if (exportMatches.Count != 1)
            return false;
        var exportMatch = exportMatches[0];
        var openParenIdx = exportMatch.Index + exportMatch.Length - 1;
        if (!TryExtractBalancedSlice(stripped, masked, openParenIdx, '(', ')', out var configBody, out var configBodyMask, out var closeParenIdx))
            return false;
        if (stripped[(closeParenIdx + 1)..].Trim() is not ("" or ";"))
            return false;
        var trimmedMask = configBodyMask.Trim();
        Match? callbackHeaderMatch = null;
        if (!(trimmedMask.StartsWith('{') && trimmedMask.EndsWith('}')))
        {
            callbackHeaderMatch = Regex.Match(configBodyMask,
                @"\A\s*\(\s*(?:\{\s*(?<props>[A-Za-z_$][A-Za-z0-9_$]*(?:\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\}|(?<param>[A-Za-z_$][A-Za-z0-9_$]*))?\s*\)\s*=>\s*\{\s*(?:const\s+(?<cbConst>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[A-Za-z_$][A-Za-z0-9_$]*\s*===\s*['""]\s+['""]\s*;\s*)*return\s*\{",
                RegexOptions.CultureInvariant);
            if (!callbackHeaderMatch.Success)
                return false;
            var returnBraceIdx = callbackHeaderMatch.Index + callbackHeaderMatch.Length - 1;
            if (!TryExtractBalancedSlice(configBody, configBodyMask, returnBraceIdx, '{', '}',
                    out var returnedObj, out var returnedObjMask, out var returnCloseIdx))
                return false;
            if (!Regex.IsMatch(configBodyMask[(returnCloseIdx + 1)..], @"\A\s*;?\s*\}\s*\z", RegexOptions.CultureInvariant))
                return false;
            configBody = "{" + returnedObj + "}";
            configBodyMask = "{" + returnedObjMask + "}";
        }

        if (masked.Contains('\\') ||
            Regex.IsMatch(masked, @"\b(?:const|let|var)\s*[\{\[]", RegexOptions.CultureInvariant) ||
            Regex.IsMatch(configBodyMask, @"\b(?:const|let|var|function|return)\b", RegexOptions.CultureInvariant))
            return false;

        var preambleRaw = stripped[..exportMatch.Index];
        var preambleMask = masked[..exportMatch.Index];
        var preambleDepth = new int[preambleMask.Length + 1];
        var runningDepth = 0;
        for (var i = 0; i < preambleMask.Length; i++)
        {
            preambleDepth[i] = runningDepth;
            var ch = preambleMask[i];
            if (ch is '{' or '(' or '[')
                runningDepth++;
            else if (ch is '}' or ')' or ']')
            {
                runningDepth--;
                if (runningDepth < 0)
                    return false;
            }
        }
        preambleDepth[preambleMask.Length] = runningDepth;
        if (runningDepth != 0)
            return false;

        var declCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (Match declMatch in Regex.Matches(masked,
            @"(?:\b(?:const|let|var|function)\s+(?<id>[A-Za-z_$][A-Za-z0-9_$]*)\b|,\s*(?<id>[A-Za-z_$][A-Za-z0-9_$]*)\b(?=\s*(?::[^=;,\(\)\{\}\[\]]+)?=))",
            RegexOptions.CultureInvariant))
        {
            var id = declMatch.Groups["id"].Value;
            declCounts[id] = declCounts.GetValueOrDefault(id) + 1;
        }
        foreach (Match fnParamMatch in Regex.Matches(masked,
            @"\bfunction\s*[A-Za-z0-9_$]*\s*\((?<params>[^)]*)\)",
            RegexOptions.CultureInvariant))
        {
            var rawParams = Regex.Replace(fnParamMatch.Groups["params"].Value, @":[^,)=]+", "", RegexOptions.CultureInvariant);
            foreach (Match idMatch in Regex.Matches(rawParams, @"\b(?<id>[A-Za-z_$][A-Za-z0-9_$]*)\b", RegexOptions.CultureInvariant))
            {
                var id = idMatch.Groups["id"].Value;
                declCounts[id] = declCounts.GetValueOrDefault(id) + 1;
            }
        }
        foreach (Match arrowParamMatch in Regex.Matches(masked,
            @"(?:\(\s*(?<params>[^()]*)\s*\)|(?<single>[A-Za-z_$][A-Za-z0-9_$]*))\s*=>",
            RegexOptions.CultureInvariant))
        {
            var rawParams = arrowParamMatch.Groups["single"].Success
                ? arrowParamMatch.Groups["single"].Value
                : Regex.Replace(arrowParamMatch.Groups["params"].Value, @":[^,)=]+", "", RegexOptions.CultureInvariant);
            foreach (Match idMatch in Regex.Matches(rawParams, @"\b(?<id>[A-Za-z_$][A-Za-z0-9_$]*)\b", RegexOptions.CultureInvariant))
            {
                var id = idMatch.Groups["id"].Value;
                declCounts[id] = declCounts.GetValueOrDefault(id) + 1;
            }
        }

        var consts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match m in Regex.Matches(preambleMask,
            @"\bconst\s+(?<id>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?<q>['""])(?<lit>\s+)\k<q>\s*(?:;|\r?\n(?!\s*[+?.:\[`])|\z)",
            RegexOptions.CultureInvariant))
        {
            var id = m.Groups["id"].Value;
            if (preambleDepth[m.Index] == 0 && declCounts.GetValueOrDefault(id) == 1)
                consts[id] = stripped.Substring(m.Groups["lit"].Index, m.Groups["lit"].Length);
        }

        if (!TryParseJsObject(configBody, configBodyMask, allowOutDirShorthand: false, out var rootProps) ||
            !rootProps.TryGetValue("build", out var buildEntry) ||
            !TryParseJsObject(buildEntry.Raw, buildEntry.Mask, allowOutDirShorthand: true, out var buildProps) ||
            buildProps.ContainsKey("rollupOptions") ||
            !buildProps.TryGetValue("rolldownOptions", out var rolldownEntry) ||
            !TryParseJsObject(rolldownEntry.Raw, rolldownEntry.Mask, allowOutDirShorthand: false, out var rolldownProps) ||
            !rolldownProps.TryGetValue("output", out var outputEntry) ||
            !TryParseJsObject(outputEntry.Raw, outputEntry.Mask, allowOutDirShorthand: false, out var outputProps) ||
            outputProps.ContainsKey("dir") ||
            !buildProps.TryGetValue("outDir", out var outDirEntry))
            return false;

        string? outDir = null;
        if (outDirEntry.Mask.Equals("outDir", StringComparison.Ordinal))
        {
            consts.TryGetValue("outDir", out outDir);
        }
        else
        {
            var outDirMaskMatch = Regex.Match(outDirEntry.Mask,
                @"\A(?:(?<q>['""])(?<lit>\s+)\k<q>|(?<id>[A-Za-z_$][A-Za-z0-9_$]*))\z",
                RegexOptions.CultureInvariant);
            if (outDirMaskMatch.Success)
            {
                if (outDirMaskMatch.Groups["id"].Success)
                    outDir = consts.GetValueOrDefault(outDirMaskMatch.Groups["id"].Value);
                else
                    outDir = outDirEntry.Raw.Substring(outDirMaskMatch.Groups["lit"].Index, outDirMaskMatch.Groups["lit"].Length);
            }
        }

        if (string.IsNullOrWhiteSpace(outDir) ||
            outDir.Contains("..", StringComparison.Ordinal) ||
            outDir.Contains('\\'))
            return false;
        var normalizedOutDir = (npmDir + outDir.Trim().TrimStart('.', '/')).TrimEnd('/');
        if (normalizedOutDir is not ("wwwroot" or "src/wwwroot"))
            return false;
        if (sourceFiles.Keys.Any(k =>
                k.StartsWith(rootPrefix + normalizedOutDir + "/", StringComparison.Ordinal) &&
                (k.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                 k.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase) ||
                 k.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase) ||
                 k.EndsWith(".css", StringComparison.OrdinalIgnoreCase))))
            return false;
        var projectDir = normalizedOutDir.Equals("wwwroot", StringComparison.Ordinal)
            ? ""
            : normalizedOutDir[..^"wwwroot".Length];
        if (!sourceFiles.Keys.Any(k =>
                k.StartsWith(rootPrefix + projectDir, StringComparison.Ordinal) &&
                !k[(rootPrefix.Length + projectDir.Length)..].Contains('/') &&
                k.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)))
            return false;

        string? licenseFile = null;
        if (buildProps.TryGetValue("license", out var licEntry))
        {
            if (!licEntry.Mask.Equals("false", StringComparison.Ordinal))
            {
                var licMaskMatch = Regex.Match(licEntry.Mask,
                    @"\A\{\s*fileName\s*:\s*(?:(?<q>['""])(?<lit>\s+)\k<q>|(?<id>[A-Za-z_$][A-Za-z0-9_$]*))\s*,?\s*\}\z",
                    RegexOptions.CultureInvariant);
                if (!licMaskMatch.Success)
                    return false;
                string? rawLic = licMaskMatch.Groups["id"].Success
                    ? consts.GetValueOrDefault(licMaskMatch.Groups["id"].Value)
                    : licEntry.Raw.Substring(licMaskMatch.Groups["lit"].Index, licMaskMatch.Groups["lit"].Length);
                if (string.IsNullOrWhiteSpace(rawLic) ||
                    rawLic.Contains("..", StringComparison.Ordinal) ||
                    rawLic.Contains('/') ||
                    rawLic.Contains('\\'))
                    return false;
                licenseFile = rawLic;
            }
        }

        var directDepSet = directDeps.ToHashSet(StringComparer.Ordinal);
        var exactScripts = new HashSet<string>(StringComparer.Ordinal);
        var initializerBases = new HashSet<string>(StringComparer.Ordinal);
        var chunkNames = new HashSet<string>(StringComparer.Ordinal);
        var copiedDirs = new HashSet<(string Dependency, string Subdir)>();

        if (Regex.IsMatch(masked,
            @"\b(?:config|configResolved|options|outputOptions|resolveId|load|transform|renderChunk)\b",
            RegexOptions.CultureInvariant))
            return false;

        var fnMatches = Regex.Matches(preambleMask,
            @"\bfunction\s+(?<fn>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*\)\s*(?::\s*[A-Za-z_$][A-Za-z0-9_$]*\s*)?\{",
            RegexOptions.CultureInvariant);
        if (fnMatches.Count != Regex.Matches(preambleMask, @"\bfunction\b", RegexOptions.CultureInvariant).Count)
            return false;
        var validPluginFns = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match fnMatch in fnMatches)
        {
            if (preambleDepth[fnMatch.Index] != 0)
                return false;
            var braceIdx = fnMatch.Index + fnMatch.Length - 1;
            if (!TryExtractBalancedSlice(preambleRaw, preambleMask, braceIdx, '{', '}', out var fnBodyRaw, out var fnBodyMask, out _))
                return false;
            var retMatch = Regex.Match(fnBodyMask, @"\A\s*return\s*\{", RegexOptions.CultureInvariant);
            if (!retMatch.Success)
                return false;
            var retBraceIdx = retMatch.Length - 1;
            if (!TryExtractBalancedSlice(fnBodyRaw, fnBodyMask, retBraceIdx, '{', '}', out _, out var pluginObjMask, out var retCloseIdx) ||
                !Regex.IsMatch(fnBodyMask[(retCloseIdx + 1)..], @"\A\s*;?\s*\z", RegexOptions.CultureInvariant))
                return false;

            var pStart = 0;
            var pDepth = 0;
            var seenMembers = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i <= pluginObjMask.Length; i++)
            {
                var ch = i < pluginObjMask.Length ? pluginObjMask[i] : ',';
                if (ch is '{' or '(' or '[')
                    pDepth++;
                else if (ch is '}' or ')' or ']')
                {
                    pDepth--;
                    if (pDepth < 0)
                        return false;
                }
                else if (ch == ',' && pDepth == 0)
                {
                    var mMask = pluginObjMask[pStart..i].Trim();
                    pStart = i + 1;
                    if (mMask.Length == 0)
                    {
                        if (i < pluginObjMask.Length)
                            return false;
                        continue;
                    }
                    if (Regex.IsMatch(mMask, @"\Aname\s*:\s*(?<q>['""])\s+\k<q>\z", RegexOptions.CultureInvariant))
                    {
                        if (!seenMembers.Add("name"))
                            return false;
                        continue;
                    }
                    var hookMatch = Regex.Match(mMask,
                        @"\A(?<hook>generateBundle|closeBundle|writeBundle)\s*\(\s*(?:[A-Za-z_$][A-Za-z0-9_$]*(?:\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*)*)?\s*\)\s*\{(?<body>[\s\S]*)\}\z",
                        RegexOptions.CultureInvariant);
                    if (!hookMatch.Success || !seenMembers.Add(hookMatch.Groups["hook"].Value))
                        return false;
                }
            }
            if (pDepth != 0 || !seenMembers.Contains("name"))
                return false;
            validPluginFns.Add(fnMatch.Groups["fn"].Value);
        }

        if (rootProps.TryGetValue("plugins", out var pluginsEntry))
        {
            if (!pluginsEntry.Mask.StartsWith('[') ||
                !TryExtractBalancedSlice(pluginsEntry.Raw, pluginsEntry.Mask, 0, '[', ']', out _, out var pluginsMask, out var pluginsCloseIdx) ||
                !string.IsNullOrWhiteSpace(pluginsEntry.Mask[(pluginsCloseIdx + 1)..]))
                return false;

            var plStart = 0;
            var plDepth = 0;
            for (var i = 0; i <= pluginsMask.Length; i++)
            {
                var ch = i < pluginsMask.Length ? pluginsMask[i] : ',';
                if (ch is '{' or '(' or '[')
                    plDepth++;
                else if (ch is '}' or ')' or ']')
                {
                    plDepth--;
                    if (plDepth < 0)
                        return false;
                }
                else if (ch == ',' && plDepth == 0)
                {
                    var elemMask = pluginsMask[plStart..i].Trim();
                    plStart = i + 1;
                    if (elemMask.Length == 0)
                    {
                        if (i < pluginsMask.Length)
                            return false;
                        continue;
                    }
                    var callMatch = Regex.Match(elemMask, @"\A(?<fn>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*\)\z", RegexOptions.CultureInvariant);
                    if (!callMatch.Success ||
                        declCounts.GetValueOrDefault(callMatch.Groups["fn"].Value) != 1 ||
                        !validPluginFns.Contains(callMatch.Groups["fn"].Value))
                        return false;
                }
            }
            if (plDepth != 0)
                return false;

            if (masked.Contains("emitFile", StringComparison.Ordinal))
            {
                if (consts.TryGetValue("initializer", out var initVal) &&
                    initVal.Equals(packageId + ".lib.module.js", StringComparison.Ordinal) &&
                    Regex.IsMatch(masked, @"\bfileName\s*:\s*initializer\b\s*(?:,|\})", RegexOptions.CultureInvariant))
                {
                    initializerBases.Add(packageId);
                }
                foreach (Match initMask in Regex.Matches(masked, @"\bfileName\s*:\s*(?<q>['""])(?<lit>\s+)\k<q>\s*(?:,|\})",
                    RegexOptions.CultureInvariant))
                {
                    var litVal = stripped.Substring(initMask.Groups["lit"].Index, initMask.Groups["lit"].Length);
                    if (litVal.Equals(packageId + ".lib.module.js", StringComparison.Ordinal))
                        initializerBases.Add(packageId);
                }
            }
        }

        if (!rolldownProps.TryGetValue("input", out var inputEntry) ||
            (rootProps.TryGetValue("input", out var rootInputEntry) && !rootInputEntry.Mask.Equals("entries", StringComparison.Ordinal)))
            return false;

        var declaredEntries = new Dictionary<string, string>(StringComparer.Ordinal);
        var hasInputSpread = Regex.IsMatch(inputEntry.Mask, @"\A\{\s*\.\.\.entries\s*(?:,|\})", RegexOptions.CultureInvariant);
        if (Regex.Matches(configBodyMask, @"\.\.\.", RegexOptions.CultureInvariant).Count != (hasInputSpread ? 1 : 0))
            return false;
        if (hasInputSpread || inputEntry.Mask.Equals("entries", StringComparison.Ordinal))
        {
            if (declCounts.GetValueOrDefault("entries") != 1)
                return false;
            foreach (Match entriesBlock in Regex.Matches(preambleMask,
                @"\bconst\s+entries\b[^=]*=\s*\{(?<body>[^}]+)\}", RegexOptions.CultureInvariant))
            {
                if (preambleDepth[entriesBlock.Index] != 0)
                    return false;
                var bodyOffset = entriesBlock.Groups["body"].Index;
                var bodyMask = entriesBlock.Groups["body"].Value;
                var props = Regex.Matches(bodyMask,
                    @"(?:(?<kq>['""])(?<k1>\s+)\k<kq>|(?<k2>[A-Za-z_$][A-Za-z0-9_$]*))\s*:\s*(?<vq>['""])(?<src>\s+)\k<vq>\s*(?:,|\z)",
                    RegexOptions.CultureInvariant);
                if (props.Count == 0 || props.Count != Regex.Matches(bodyMask, ":").Count)
                    return false;
                foreach (Match prop in props)
                {
                    var key = prop.Groups["k1"].Success
                        ? stripped.Substring(bodyOffset + prop.Groups["k1"].Index, prop.Groups["k1"].Length)
                        : prop.Groups["k2"].Value;
                    var srcPath = stripped.Substring(bodyOffset + prop.Groups["src"].Index, prop.Groups["src"].Length);
                    if (srcPath.Contains("..", StringComparison.Ordinal) ||
                        !sourceFiles.ContainsKey(rootPrefix + npmDir + srcPath.TrimStart('.', '/')))
                        return false;
                    declaredEntries[key] = srcPath;
                }
            }
        }
        if (declaredEntries.Count == 0)
            return false;

        var declaredInputKeys = new HashSet<string>(declaredEntries.Keys, StringComparer.Ordinal);
        if (hasInputSpread)
        {
            var inputBlock = Regex.Match(inputEntry.Mask, @"\A\{(?<body>[^}]+)\}\z", RegexOptions.CultureInvariant);
            if (!inputBlock.Success)
                return false;
            var bodyOffset = inputBlock.Groups["body"].Index;
            var bodyMask = inputBlock.Groups["body"].Value;
            var props = Regex.Matches(bodyMask,
                @"(?:(?<kq>['""])(?<k1>\s+)\k<kq>|(?<k2>[A-Za-z_$][A-Za-z0-9_$]*))\s*:\s*(?<vq>['""])(?<val>\s+)\k<vq>\s*(?:,|\z)",
                RegexOptions.CultureInvariant);
            if (props.Count != Regex.Matches(bodyMask, ":").Count)
                return false;
            foreach (Match prop in props)
            {
                var key = prop.Groups["k1"].Success
                    ? inputEntry.Raw.Substring(bodyOffset + prop.Groups["k1"].Index, prop.Groups["k1"].Length)
                    : prop.Groups["k2"].Value;
                var val = inputEntry.Raw.Substring(bodyOffset + prop.Groups["val"].Index, prop.Groups["val"].Length);
                if (directDepSet.Contains(val))
                    declaredInputKeys.Add(key);
            }
        }

        if (!outputProps.TryGetValue("entryFileNames", out var entryFnEntry) ||
            !outputProps.TryGetValue("chunkFileNames", out var chunkFnEntry))
            return false;

        var fixedKeys = new HashSet<string>(StringComparer.Ordinal);
        if (entryFnEntry.Mask.Contains("fixedNames[", StringComparison.Ordinal))
        {
            if (declCounts.GetValueOrDefault("fixedNames") != 1)
                return false;
            foreach (Match fixedBlock in Regex.Matches(preambleMask,
                @"\bconst\s+fixedNames\b[^=]*=\s*\{(?<body>[^}]+)\}", RegexOptions.CultureInvariant))
            {
                if (preambleDepth[fixedBlock.Index] != 0)
                    return false;
                var bodyOffset = fixedBlock.Groups["body"].Index;
                var bodyMask = fixedBlock.Groups["body"].Value;
                var props = Regex.Matches(bodyMask,
                    @"(?:(?<kq>['""])(?<k1>\s+)\k<kq>|(?<k2>[A-Za-z_$][A-Za-z0-9_$]*))\s*:\s*(?<vq>['""])(?<file>\s+)\k<vq>\s*(?:,|\z)",
                    RegexOptions.CultureInvariant);
                if (props.Count == 0 || props.Count != Regex.Matches(bodyMask, ":").Count)
                    return false;
                foreach (Match prop in props)
                {
                    var key = prop.Groups["k1"].Success
                        ? stripped.Substring(bodyOffset + prop.Groups["k1"].Index, prop.Groups["k1"].Length)
                        : prop.Groups["k2"].Value;
                    var fileVal = stripped.Substring(bodyOffset + prop.Groups["file"].Index, prop.Groups["file"].Length);
                    if (!Regex.IsMatch(fileVal, @"\A[A-Za-z0-9._\-]+\.m?js\z", RegexOptions.CultureInvariant) ||
                        !declaredInputKeys.Contains(key))
                        return false;
                    fixedKeys.Add(key);
                    exactScripts.Add(fileVal);
                }
            }
        }

        var entryMaskMatch = Regex.Match(entryFnEntry.Mask,
            @"\A(?:\(\s*(?<param>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*=>\s*fixedNames\s*\[\s*(?<arg>[A-Za-z_$][A-Za-z0-9_$]*)\.name\s*\]\s*\?\?\s*)?(?<q>['""])(?<lit>\s+)\k<q>\z",
            RegexOptions.CultureInvariant);
        var chunkMaskMatch = Regex.Match(chunkFnEntry.Mask,
            @"\A(?<q>['""])(?<lit>\s+)\k<q>\z",
            RegexOptions.CultureInvariant);
        if (!entryMaskMatch.Success || !chunkMaskMatch.Success)
            return false;
        if (Regex.Matches(configBodyMask, @"=>", RegexOptions.CultureInvariant).Count != (entryMaskMatch.Groups["param"].Success ? 1 : 0))
            return false;
        if (entryMaskMatch.Groups["param"].Success)
        {
            var paramName = entryMaskMatch.Groups["param"].Value;
            var argName = entryMaskMatch.Groups["arg"].Value;
            if (!paramName.Equals(argName, StringComparison.Ordinal) ||
                paramName.Equals("fixedNames", StringComparison.Ordinal))
                return false;
        }
        var entryBundlePattern = entryFnEntry.Raw.Substring(entryMaskMatch.Groups["lit"].Index, entryMaskMatch.Groups["lit"].Length);
        var chunkBundlePattern = chunkFnEntry.Raw.Substring(chunkMaskMatch.Groups["lit"].Index, chunkMaskMatch.Groups["lit"].Length);
        if (!entryBundlePattern.Equals("[name].[hash].bundle.js", StringComparison.Ordinal) ||
            !chunkBundlePattern.Equals("[name].[hash].bundle.js", StringComparison.Ordinal))
            return false;

        foreach (var entryKey in declaredEntries.Keys)
        {
            if (!fixedKeys.Contains(entryKey))
                chunkNames.Add(entryKey);
        }

        if (outputProps.TryGetValue("codeSplitting", out var csEntry))
        {
            if (!TryParseJsObject(csEntry.Raw, csEntry.Mask, allowOutDirShorthand: false, out var csProps) ||
                !csProps.TryGetValue("groups", out var groupsEntry) ||
                !groupsEntry.Mask.StartsWith('[') ||
                !TryExtractBalancedSlice(groupsEntry.Raw, groupsEntry.Mask, 0, '[', ']', out var groupsBody, out var groupsMask, out var groupsCloseIdx) ||
                !string.IsNullOrWhiteSpace(groupsEntry.Mask[(groupsCloseIdx + 1)..]))
                return false;

            var gStart = 0;
            var gDepth = 0;
            var groupCount = 0;
            for (var i = 0; i <= groupsMask.Length; i++)
            {
                var ch = i < groupsMask.Length ? groupsMask[i] : ',';
                if (ch is '{' or '(' or '[')
                    gDepth++;
                else if (ch is '}' or ')' or ']')
                {
                    gDepth--;
                    if (gDepth < 0)
                        return false;
                }
                else if (ch == ',' && gDepth == 0)
                {
                    var elemMask = groupsMask[gStart..i].Trim();
                    var elemRaw = groupsBody[gStart..i].Trim();
                    gStart = i + 1;
                    if (elemMask.Length == 0)
                    {
                        if (i < groupsMask.Length)
                            return false;
                        continue;
                    }
                    if (!TryParseJsObject(elemRaw, elemMask, allowOutDirShorthand: false, out var groupProps) ||
                        !groupProps.TryGetValue("name", out var nameEntry) ||
                        !Regex.IsMatch(nameEntry.Mask, @"\A(?<q>['""])\s+\k<q>\z", RegexOptions.CultureInvariant) ||
                        !groupProps.TryGetValue("test", out var testEntry) ||
                        !Regex.IsMatch(testEntry.Mask, @"\A/\s+/[a-z]*\z", RegexOptions.CultureInvariant))
                        return false;
                    var nameLitMatch = Regex.Match(nameEntry.Raw,
                        @"\A(?<q>['""])(?<g>[A-Za-z0-9._\-]+)\k<q>\z", RegexOptions.CultureInvariant);
                    if (!nameLitMatch.Success)
                        return false;
                    chunkNames.Add(nameLitMatch.Groups["g"].Value);
                    groupCount++;
                }
            }
            if (gDepth != 0 || groupCount == 0)
                return false;
        }

        foreach (var (fullPath, bytes) in sourceFiles)
        {
            if (!fullPath.StartsWith(rootPrefix + npmDir, StringComparison.Ordinal) ||
                (!fullPath.EndsWith(".ts", StringComparison.OrdinalIgnoreCase) &&
                 !fullPath.EndsWith(".mts", StringComparison.OrdinalIgnoreCase)) ||
                bytes.Length > XmlLimit)
                continue;
            string tsText;
            try
            {
                tsText = StrictUtf8.GetString(StripBom(bytes));
            }
            catch (DecoderFallbackException)
            {
                continue;
            }
            StripAndMaskJs(tsText, out var tsStripped, out var tsMasked);
            foreach (Match maskedImport in Regex.Matches(tsMasked, @"\bimport\s*\(\s*['""]\s*['""]\s*\)", RegexOptions.CultureInvariant))
            {
                var slice = tsStripped.Substring(maskedImport.Index, maskedImport.Length);
                var dynImport = Regex.Match(slice,
                    @"\Aimport\s*\(\s*['""](?<dep>@?[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)?)['""]\s*\)\z",
                    RegexOptions.CultureInvariant);
                if (dynImport.Success)
                {
                    var dep = dynImport.Groups["dep"].Value;
                    if (directDepSet.Contains(dep))
                        chunkNames.Add(dep);
                }
            }
        }

        foreach (Match cpMask in Regex.Matches(masked,
            @"\bcpSync\s*\(\s*(?<q1>['""])\s+\k<q1>\s*,\s*(?:`\s+`|(?<q2>['""])\s+\k<q2>)",
            RegexOptions.CultureInvariant))
        {
            var cpMatch = Regex.Match(stripped.Substring(cpMask.Index, cpMask.Length),
                @"\AcpSync\s*\(\s*['""]node_modules/(?<dep>@?[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)?)/(?<sub1>[A-Za-z0-9._\-]+)['""]\s*,\s*(?:`\$\{outDir\}/(?<sub2>[A-Za-z0-9._\-]+)`|['""](?<litOut>[A-Za-z0-9._/\-]+)/wwwroot/(?<sub3>[A-Za-z0-9._\-]+)['""])\z",
                RegexOptions.CultureInvariant);
            if (!cpMatch.Success)
                continue;
            var dep = cpMatch.Groups["dep"].Value;
            var sub1 = cpMatch.Groups["sub1"].Value;
            var sub2 = cpMatch.Groups["sub2"].Success ? cpMatch.Groups["sub2"].Value : cpMatch.Groups["sub3"].Value;
            if (cpMatch.Groups["litOut"].Success)
            {
                var litOutDir = (npmDir + cpMatch.Groups["litOut"].Value.TrimStart('.', '/') + "/wwwroot").TrimStart('/');
                if (!litOutDir.Equals(normalizedOutDir, StringComparison.Ordinal))
                    continue;
            }
            if (sub1 == sub2 && directDepSet.Contains(dep))
                copiedDirs.Add((dep, sub1));
        }

        if (exactScripts.Count == 0 && initializerBases.Count == 0 && chunkNames.Count == 0)
            return false;

        plan = new AttestedViteBuildPlan(npmDir, normalizedOutDir, licenseFile,
            exactScripts, initializerBases, chunkNames, copiedDirs);
        return true;
    }

    private static bool TryParseJsObject(
        string objRaw,
        string objMask,
        bool allowOutDirShorthand,
        out Dictionary<string, (string Raw, string Mask)> props)
    {
        props = new Dictionary<string, (string Raw, string Mask)>(StringComparer.Ordinal);
        var trimmedMask = objMask.Trim();
        if (!trimmedMask.StartsWith('{') || !trimmedMask.EndsWith('}'))
            return false;
        var openIdx = objMask.IndexOf('{');
        if (!TryExtractBalancedSlice(objRaw, objMask, openIdx, '{', '}', out var innerRaw, out var innerMask, out var closeIdx) ||
            !string.IsNullOrWhiteSpace(objMask[(closeIdx + 1)..]))
            return false;

        var start = 0;
        var depth = 0;
        for (var i = 0; i <= innerMask.Length; i++)
        {
            var ch = i < innerMask.Length ? innerMask[i] : ',';
            if (ch is '{' or '(' or '[')
                depth++;
            else if (ch is '}' or ')' or ']')
            {
                depth--;
                if (depth < 0)
                    return false;
            }
            else if (ch == ',' && depth == 0)
            {
                var entryMask = innerMask[start..i].Trim();
                var entryRaw = innerRaw[start..i].Trim();
                start = i + 1;
                if (entryMask.Length == 0)
                    continue;
                if (allowOutDirShorthand && entryMask.Equals("outDir", StringComparison.Ordinal))
                {
                    if (!props.TryAdd("outDir", ("outDir", "outDir")))
                        return false;
                    continue;
                }
                var kvMatch = Regex.Match(entryMask,
                    @"\A(?<id>[A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?<val>[\s\S]+)\z",
                    RegexOptions.CultureInvariant);
                if (!kvMatch.Success)
                    return false;
                var key = kvMatch.Groups["id"].Value;
                var valIdx = kvMatch.Groups["val"].Index;
                var valLen = kvMatch.Groups["val"].Length;
                if (!props.TryAdd(key, (entryRaw.Substring(valIdx, valLen).Trim(), entryMask.Substring(valIdx, valLen).Trim())))
                    return false;
            }
        }
        return depth == 0;
    }

    internal static bool TryAttestedViteScriptAsset(
        AttestedViteBuildPlan plan,
        Dictionary<string, byte[]> sourceFiles,
        string rootPrefix,
        string assetPath)
    {
        if (!assetPath.StartsWith("staticwebassets/", StringComparison.Ordinal))
            return false;
        var relPath = assetPath["staticwebassets/".Length..];
        if (relPath.Length == 0 || relPath.Contains('/'))
            return false;
        if (sourceFiles.ContainsKey(rootPrefix + plan.OutDir + "/" + relPath))
            return false;
        if (plan.ExactScriptFileNames.Contains(relPath))
            return true;
        foreach (var initBase in plan.InitializerBaseNames)
        {
            if (relPath.Equals(initBase + ".lib.module.js", StringComparison.Ordinal) ||
                Regex.IsMatch(relPath, @"\A" + Regex.Escape(initBase) + @"\.[A-Za-z0-9_\-]{6,16}\.lib\.module\.js\z",
                    RegexOptions.CultureInvariant))
                return true;
        }
        var chunkMatch = Regex.Match(relPath,
            @"\A(?<chunk>[A-Za-z0-9._\-]+)\.[A-Za-z0-9_\-]{6,16}\.bundle\.js\z",
            RegexOptions.CultureInvariant);
        return chunkMatch.Success && plan.ChunkNames.Contains(chunkMatch.Groups["chunk"].Value);
    }

    internal static bool TryAttestedViteCssAsset(
        AttestedViteBuildPlan plan,
        Dictionary<string, byte[]> sourceFiles,
        string rootPrefix,
        string assetPath,
        HashSet<string> verifiedDeps)
    {
        if (!assetPath.StartsWith("staticwebassets/", StringComparison.Ordinal) ||
            !assetPath.EndsWith(".css", StringComparison.OrdinalIgnoreCase))
            return false;
        var relPath = assetPath["staticwebassets/".Length..];
        if (sourceFiles.ContainsKey(rootPrefix + plan.OutDir + "/" + relPath))
            return false;
        var slash = relPath.IndexOf('/');
        if (slash <= 0)
            return false;
        var topSubdir = relPath[..slash];
        return plan.CopiedDependencyDirs.Any(pair =>
            pair.Subdir.Equals(topSubdir, StringComparison.Ordinal) &&
            verifiedDeps.Contains(pair.Dependency));
    }
    private static bool VerifyAssemblyMetadataConsistency(byte[] bytes, string expectedRepository, string expectedCommit)
    {
        var inspected = Pi01PeInspector.Inspect(bytes);
        if (inspected.State is not ("unsigned" or "delay-signed" or "public-signed" or "verified-signed"))
            return false;
        try
        {
            using var pe = new PEReader(new MemoryStream(bytes, writable: false));
            var metadata = pe.GetMetadataReader();
            var definition = metadata.GetAssemblyDefinition();
            if (string.IsNullOrWhiteSpace(metadata.GetString(definition.Name)))
                return false;
            foreach (var handle in definition.GetCustomAttributes())
            {
                var attribute = metadata.GetCustomAttribute(handle);
                EntityHandle type;
                BlobHandle signature;
                string constructor;
                if (attribute.Constructor.Kind == HandleKind.MemberReference)
                {
                    var member = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
                    type = member.Parent;
                    signature = member.Signature;
                    constructor = metadata.GetString(member.Name);
                }
                else if (attribute.Constructor.Kind == HandleKind.MethodDefinition)
                {
                    var method = metadata.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor);
                    type = method.GetDeclaringType();
                    signature = method.Signature;
                    constructor = metadata.GetString(method.Name);
                }
                else continue;

                var (space, name) = type.Kind switch
                {
                    HandleKind.TypeReference => (metadata.GetTypeReference((TypeReferenceHandle)type).Namespace,
                        metadata.GetTypeReference((TypeReferenceHandle)type).Name),
                    HandleKind.TypeDefinition => (metadata.GetTypeDefinition((TypeDefinitionHandle)type).Namespace,
                        metadata.GetTypeDefinition((TypeDefinitionHandle)type).Name),
                    _ => (default(StringHandle), default(StringHandle))
                };
                if (constructor != ".ctor" || metadata.GetString(space) != "System.Reflection")
                    continue;
                var attributeName = metadata.GetString(name);
                var shape = metadata.GetBlobBytes(signature).AsSpan();
                var isInfoVer = attributeName == "AssemblyInformationalVersionAttribute" &&
                    shape.SequenceEqual(new byte[] { 0x20, 1, 1, 0x0e });
                var isRepoMeta = attributeName == "AssemblyMetadataAttribute" &&
                    shape.SequenceEqual(new byte[] { 0x20, 2, 1, 0x0e, 0x0e });
                if (!isInfoVer && !isRepoMeta)
                    continue;
                var reader = metadata.GetBlobReader(attribute.Value);
                if (reader.ReadUInt16() != 1)
                    return false;
                var first = reader.ReadSerializedString();
                if (isInfoVer && first is not null)
                {
                    var plus = first.IndexOf('+');
                    if (plus >= 0 && !string.Equals(first[(plus + 1)..], expectedCommit, StringComparison.OrdinalIgnoreCase))
                        return false;
                }
                else if (isRepoMeta)
                {
                    var second = reader.ReadSerializedString();
                    if (first == "RepositoryCommit" && !string.IsNullOrWhiteSpace(second) &&
                        !string.Equals(second.Trim(), expectedCommit, StringComparison.OrdinalIgnoreCase))
                        return false;
                    if (first == "RepositoryUrl" && !string.IsNullOrWhiteSpace(second) &&
                        !string.Equals(NormalizeRepoUrl(second), expectedRepository, StringComparison.OrdinalIgnoreCase))
                        return false;
                }
            }
            return true;
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    private sealed record EntryRecord(string Path, long SizeBytes, string Sha256,
        string Classification, string Reason, List<Locator> Locators);
    private sealed record Locator(string Name, Snippet Snippet);
    private sealed record Snippet(string Text, bool Truncated);
    private sealed record Classified(string Kind, string Reason, List<Locator> Locators,
        List<string> Promotions, List<string> Imports);
    private sealed record Inventory(string Branch, List<EntryRecord> Records);
    private sealed class XmlProblem(string reason) : Exception(reason);

    private static string CandidateContract(List<EntryRecord> records)
    {
        var candidates = records.Where(item => item.Classification != "passive").ToArray();
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer,
            new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStartArray();
            foreach (var item in candidates)
            {
                writer.WriteStartObject();
                writer.WriteString("classification", item.Classification);
                writer.WritePropertyName("first_locator");
                if (item.Locators.Count == 0)
                    writer.WriteNullValue();
                else
                    writer.WriteStringValue(item.Locators[0].Name);
                writer.WriteNumber("locator_count", item.Locators.Count);
                writer.WriteString("locators_sha256", LocatorDigest(item.Locators));
                writer.WriteString("path", item.Path);
                writer.WriteString("reason", item.Reason);
                writer.WriteString("sha256", item.Sha256);
                writer.WriteNumber("size_bytes", item.SizeBytes);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }
        return CandidatePrefix + AsciiJson(Encoding.UTF8.GetString(buffer.ToArray())) +
            CandidateSuffix;
    }

    private static string LocatorDigest(List<Locator> locators) =>
        Catalog.Digest(Encoding.UTF8.GetBytes(AsciiJson(JsonSerializer.Serialize(
            locators.Select(item => new
            {
                locator = item.Name,
                snippet = new { text = item.Snippet.Text, truncated = item.Snippet.Truncated }
            }).ToArray(), PrettyJson)) + "\n"));

    private static string AsciiJson(string json)
    {
        var result = new StringBuilder(json.Length);
        foreach (var character in json)
        {
            if (character > 127)
                result.Append("\\u").Append(((int)character).ToString("x4",
                    System.Globalization.CultureInfo.InvariantCulture));
            else
                result.Append(character);
        }
        return result.ToString();
    }

    private static Inventory Structural(string branch) => new(branch, []);

    private static Inventory ScanArchive(ReadOnlyMemory<byte> content)
    {
        if (content.Length > PackageLimit || !TryRawNames(content.Span, out var names))
            return Structural("unreadable-package");
        if (names.Any(name => !SafePath(name)) ||
            names.Select(AsciiLower).Distinct(StringComparer.Ordinal).Count() != names.Count)
            return Structural("unsafe-archive");
        try
        {
            using var stream = new MemoryStream(content.ToArray(), writable: false);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
            var entries = archive.Entries;
            if (entries.Count != names.Count || entries.Count > 4096 ||
                entries.Any(entry => !SafePath(entry.FullName)) ||
                entries.Select(entry => AsciiLower(entry.FullName))
                    .Distinct(StringComparer.Ordinal).Count() != entries.Count)
                return Structural("unsafe-archive");
            if (entries.Where((entry, index) => entry.FullName != names[index]).Any())
                return Structural("unreadable-package");
            var roots = entries.Where(entry =>
                entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
                !entry.FullName.Contains('/')).ToArray();
            if (roots.Length > 1)
                return Structural("ambiguous-nuspec");
            if (roots.Length == 0)
                return Structural(entries.Any(entry => entry.FullName.EndsWith(
                    ".nuspec", StringComparison.OrdinalIgnoreCase))
                    ? "missing-root-nuspec" : "missing-nuspec");
            if (roots[0].Length > NuspecLimit)
                return Structural("incomplete-inventory");
            var nuspec = ReadEntry(roots[0], NuspecLimit);
            if (nuspec is null)
                return Structural("unreadable-package");
            XElement root;
            try
            {
                root = ReadXml(nuspec, NuspecLimit, "nuspec");
            }
            catch (XmlProblem error)
            {
                return Structural(error.Message is "nuspec-encoding" or "nuspec-dtd"
                    ? "unsafe-nuspec" : "invalid-xml");
            }
            if (root.Name.LocalName != "package" ||
                !KnownNamespaces.Contains(root.Name.NamespaceName))
                return Structural("foreign-root");
            var metadata = root.Elements().Where(child => child.Name.LocalName == "metadata").ToArray();
            var recognized = metadata.Where(child => child.Name.Namespace == root.Name.Namespace).ToArray();
            if (recognized.Length > 0 && recognized.Length != metadata.Length)
                return Structural("ambiguous-metadata");
            if (recognized.Length != 1)
                return Structural("invalid-metadata");

            var others = entries.Where(entry => entry != roots[0]).ToArray();
            if (others.Any(entry => entry.Length > EntryLimit) ||
                others.Sum(entry => entry.Length) > TotalLimit)
                return Structural("incomplete-inventory");
            var contents = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var entry in others)
            {
                var bytes = ReadEntry(entry, EntryLimit);
                if (bytes is null)
                    return Structural("incomplete-inventory");
                contents.Add(entry.FullName, bytes);
            }
            return InspectEntries(contents);
        }
        catch (InvalidDataException)
        {
            return Structural("unreadable-package");
        }
        catch (NotSupportedException)
        {
            return Structural("unreadable-package");
        }
        catch (IOException)
        {
            return Structural("unreadable-package");
        }
    }

    private static byte[]? ReadEntry(ZipArchiveEntry entry, int limit)
    {
        using var stream = entry.Open();
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = stream.Read(chunk)) > 0)
        {
            if (buffer.Length + read > limit)
                return null;
            buffer.Write(chunk, 0, read);
        }
        if (buffer.Length != entry.Length)
            return null;
        var content = buffer.ToArray();
        if (Crc32(content) != entry.Crc32)
            throw new InvalidDataException("ZIP entry CRC mismatch.");
        return content;
    }

    private static uint Crc32(ReadOnlySpan<byte> content)
    {
        var crc = uint.MaxValue;
        foreach (var value in content)
        {
            crc ^= value;
            for (var index = 0; index < 8; index++)
                crc = (crc >> 1) ^ ((crc & 1) == 1 ? 0xedb88320u : 0u);
        }
        return ~crc;
    }

    private static bool TryRawNames(ReadOnlySpan<byte> content, out List<string> names)
    {
        names = [];
        for (var end = content.Length - 22; end >= Math.Max(0, content.Length - 65557); end--)
        {
            if (!content.Slice(end, 4).SequenceEqual("PK\x05\x06"u8) ||
                end + 22 + BinaryPrimitives.ReadUInt16LittleEndian(content[(end + 20)..]) != content.Length)
                continue;
            var count = BinaryPrimitives.ReadUInt16LittleEndian(content[(end + 10)..]);
            var directorySize = BinaryPrimitives.ReadUInt32LittleEndian(content[(end + 12)..]);
            var cursor = BinaryPrimitives.ReadUInt32LittleEndian(content[(end + 16)..]);
            if (count > 4096 || directorySize > DirectoryLimit ||
                (ulong)cursor + directorySize > (ulong)end)
                return false;
            var start = cursor;
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            for (var index = 0; index < count; index++)
            {
                if ((ulong)cursor + 46 > (ulong)content.Length ||
                    !content.Slice((int)cursor, 4).SequenceEqual("PK\x01\x02"u8))
                    return false;
                var flags = BinaryPrimitives.ReadUInt16LittleEndian(content[((int)cursor + 8)..]);
                var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(content[((int)cursor + 28)..]);
                var extraLength = BinaryPrimitives.ReadUInt16LittleEndian(content[((int)cursor + 30)..]);
                var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(content[((int)cursor + 32)..]);
                if ((ulong)cursor + 46u + nameLength + extraLength + commentLength > (ulong)content.Length)
                    return false;
                var bytes = content.Slice((int)cursor + 46, nameLength);
                try
                {
                    names.Add((flags & 0x800) != 0
                        ? StrictUtf8.GetString(bytes) : Encoding.GetEncoding(437).GetString(bytes));
                }
                catch (DecoderFallbackException)
                {
                    return false;
                }
                cursor += (uint)(46 + nameLength + extraLength + commentLength);
            }
            return cursor == start + directorySize;
        }
        return false;
    }

    private static bool SafePath(string name)
    {
        if (name.Length is 0 or > 512 || name.StartsWith('/') || name.Contains('\\') ||
            name.Contains('\0') || name.EndsWith('/') ||
            Regex.IsMatch(name, @"\A[A-Za-z]:", RegexOptions.CultureInvariant))
            return false;
        return name.Split('/').All(part => part is not ("" or "." or ".."));
    }

    private static string AsciiLower(string value) =>
        string.Create(value.Length, value, (output, source) =>
        {
            for (var index = 0; index < source.Length; index++)
                output[index] = source[index] is >= 'A' and <= 'Z'
                    ? (char)(source[index] + ('a' - 'A')) : source[index];
        });

    private static Inventory InspectEntries(Dictionary<string, byte[]> contents)
    {
        var available = contents.Keys.ToHashSet(StringComparer.Ordinal);
        var records = new Dictionary<string, EntryRecord>(StringComparer.Ordinal);
        var imports = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var promotions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in contents.Keys.Order(StringComparer.Ordinal))
        {
            var raw = contents[name];
            var classified = Classify(name, raw, available);
            if (classified.Kind == "incomplete")
                return Structural("incomplete-inventory");
            promotions.UnionWith(classified.Promotions);
            imports[name] = classified.Imports;
            records[name] = new(name, raw.Length, Catalog.Digest(raw), classified.Kind,
                classified.Reason, classified.Locators);
        }
        var importCount = imports.Values.Sum(items => items.Count);
        if (importCount > ImportCountLimit)
            return Structural("incomplete-inventory");

        void Follow(string name, HashSet<string> stack)
        {
            if (stack.Contains(name) || stack.Count >= ImportDepthLimit)
                throw new XmlProblem("build-import-cycle-or-depth");
            foreach (var target in imports[name])
            {
                if (!stack.Contains(target) && !records[target].Reason.StartsWith(
                    "msbuild-", StringComparison.Ordinal))
                {
                    var classified = Classify(target, contents[target], available, forceMsbuild: true);
                    if (classified.Kind == "incomplete")
                        throw new XmlProblem("build-import-target-" + classified.Reason);
                    promotions.UnionWith(classified.Promotions);
                    importCount += classified.Imports.Count;
                    if (importCount > ImportCountLimit)
                        throw new XmlProblem("build-import-count");
                    imports[target] = classified.Imports;
                    records[target] = records[target] with
                    {
                        Classification = classified.Kind,
                        Reason = classified.Reason,
                        Locators = classified.Locators
                    };
                }
                var next = new HashSet<string>(stack, StringComparer.Ordinal) { name };
                Follow(target, next);
            }
        }

        try
        {
            foreach (var name in contents.Keys.Order(StringComparer.Ordinal))
                if (imports[name].Count > 0)
                    Follow(name, new(StringComparer.Ordinal));
        }
        catch (XmlProblem)
        {
            return Structural("incomplete-inventory");
        }
        foreach (var name in promotions)
            if (records[name].Classification == "passive")
                records[name] = records[name] with
                {
                    Classification = "text",
                    Reason = "promoted-in-package-code-source"
                };
        var ordered = records.Values.OrderBy(item => item.Path, StringComparer.Ordinal).ToList();
        var compiled = ordered.Any(item => item.Classification == "compiled");
        var text = ordered.Any(item => item.Classification == "text");
        var branch = ordered.Any(item => item.Classification == "unsupported")
            ? "unsupported-executable-content"
            : compiled && text ? "mixed-code-attribution-unverified"
            : compiled ? "compiled-attribution-unverified"
            : text ? "text-code-attribution-unverified"
            : "no-code-payload";
        return new(branch, ordered);
    }

    private static Classified ClassifiedAs(string kind, string reason) =>
        new(kind, reason, [], [], []);

    private static Classified Classify(string name, byte[] raw,
        HashSet<string> available, bool forceMsbuild = false)
    {
        var lower = AsciiLower(name);
        var content = raw.AsSpan();
        var peOffset = content.Length >= 0x40
            ? BinaryPrimitives.ReadUInt32LittleEndian(content[0x3c..]) : uint.MaxValue;
        if (content.StartsWith("MZ"u8) &&
            (ulong)peOffset + 4 <= (ulong)content.Length &&
            content.Slice((int)peOffset, 4).SequenceEqual("PE\0\0"u8))
            return ClassifiedAs("compiled", "pe-signature");
        if (content.StartsWith("MZ"u8))
            return ClassifiedAs("unsupported", "incomplete-pe-signature");
        if (content.StartsWith(new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F' }))
            return ClassifiedAs("compiled", "elf-signature");
        if (content.StartsWith(new byte[] { 0xcf, 0xfa, 0xed, 0xfe }) ||
            content.StartsWith(new byte[] { 0xfe, 0xed, 0xfa, 0xcf }) ||
            content.StartsWith(new byte[] { 0xce, 0xfa, 0xed, 0xfe }) ||
            content.StartsWith(new byte[] { 0xfe, 0xed, 0xfa, 0xce }) ||
            content.StartsWith(new byte[] { 0xca, 0xfe, 0xba, 0xbe }) ||
            content.StartsWith(new byte[] { 0xbe, 0xba, 0xfe, 0xca }))
            return ClassifiedAs("compiled", "macho-signature");
        if (content.StartsWith("\0asm\x01\0\0\0"u8))
            return ClassifiedAs("compiled", "wasm-signature");
        (string Label, byte[] Bytes)[] magic =
        [
            ("zip", [0x50, 0x4b, 0x03, 0x04]), ("gzip", [0x1f, 0x8b]),
            ("ar", "!<arch>\n"u8.ToArray()), ("cfb", [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
            ("cab", "MSCF"u8.ToArray()), ("7z", [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
            ("xz", [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
            ("zstd", [0x28, 0xb5, 0x2f, 0xfd]), ("bzip2", "BZh"u8.ToArray()),
            ("rar4", [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]),
            ("rar5", [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00])
        ];
        foreach (var (label, marker) in magic)
            if (content.StartsWith(marker))
                return ClassifiedAs("unsupported", label + "-container");
        if (content.Length >= 262 && content[257..].StartsWith("ustar"u8))
            return ClassifiedAs("unsupported", "tar-container");
        if (content.StartsWith("#!"u8) ||
            content.StartsWith(new byte[] { 0xef, 0xbb, 0xbf, 0x23, 0x21 }))
        {
            try
            {
                StrictUtf8.GetString(content);
                return ClassifiedAs("text", "shebang-at-start");
            }
            catch (DecoderFallbackException)
            {
                return ClassifiedAs("unsupported", "shebang-unsupported-encoding");
            }
        }
        if (EndsWithAny(lower, [".js.gz", ".js.br", ".js.zip", ".js.nupkg"]))
            return ClassifiedAs("unsupported", "precompressed-code");

        bool project;
        try
        {
            project = !forceMsbuild && !EndsWithAny(lower, MsbuildSuffixes) &&
                StartsProject(raw);
        }
        catch (XmlProblem error)
        {
            return ClassifiedAs("incomplete", error.Message);
        }
        if (forceMsbuild || EndsWithAny(lower, MsbuildSuffixes) || project)
        {
            try
            {
                var (kind, locators, promotions, imports) = InspectMsbuild(name, raw, available);
                return new(kind, "msbuild-" + (kind == "passive" ? "declaration-only" :
                    kind == "unsupported" ? "unsupported" : "active"), locators, promotions, imports);
            }
            catch (XmlProblem error)
            {
                return ClassifiedAs("incomplete", error.Message);
            }
        }
        if (EndsWithAny(lower, [".html", ".svg", ".xslt", ".xsl", ".ps1xml"]))
        {
            try
            {
                var (kind, locators) = InspectMarkup(raw);
                return new(kind, "markup-" + (kind == "text" ? "active" : "declaration-only"),
                    locators, [], []);
            }
            catch (XmlProblem error)
            {
                return ClassifiedAs("unsupported", "markup-" + error.Message);
            }
        }
        if (EndsWithAny(lower, [".js", ".mjs", ".cjs", .. ScriptSuffixes]))
        {
            try
            {
                StrictUtf8.GetString(content);
                return ClassifiedAs("text", "executable-source-text");
            }
            catch (DecoderFallbackException)
            {
                return ClassifiedAs("unsupported", "code-unsupported-encoding");
            }
        }
        if (EndsWithAny(lower, DeclarationSuffixes))
            return ClassifiedAs("passive", "declaration-types");
        if (EndsWithAny(lower, CompiledSuffixes))
            return ClassifiedAs("unsupported", "misleading-compiled-suffix");
        if (EndsWithAny(lower, SourceSuffixes))
            return ClassifiedAs("unsupported", "consumer-source-unsupported");
        if (lower == "[content_types].xml" || lower.EndsWith(".psmdcp", StringComparison.Ordinal) ||
            (lower.EndsWith(".xml", StringComparison.Ordinal) &&
             lower.StartsWith("lib/", StringComparison.Ordinal) &&
             HasLibXmlDeclaration(content)))
            return ClassifiedAs("passive", "explicit-xml-metadata");
        if (lower.EndsWith(".json", StringComparison.Ordinal) &&
            (SupportJson.Contains(lower[(lower.LastIndexOf('/') + 1)..]) ||
             lower.Contains("attestations/", StringComparison.Ordinal) ||
             lower.Contains("sources/", StringComparison.Ordinal)))
            return ClassifiedAs("passive", "supporting-json-claim");
        if (lower is "_rels/.rels" or "license" or "notice" ||
            EndsWithAny(lower, PassiveSuffixes))
            return ClassifiedAs("passive", "explicit-passive-asset");
        return ClassifiedAs("unsupported", content.Length > 0
            ? "unknown-nonempty-payload" : "unknown-empty-entry");
    }

    private static bool EndsWithAny(string value, string[] endings) =>
        endings.Any(ending => value.EndsWith(ending, StringComparison.Ordinal));

    private static bool HasLibXmlDeclaration(ReadOnlySpan<byte> content)
    {
        var prefix = content[..Math.Min(512, content.Length)];
        while (prefix.Length > 0 && prefix[0] is 0xef or 0xbb or 0xbf)
            prefix = prefix[1..];
        return prefix.StartsWith("<?xml version=\"1.0\"?>"u8);
    }

    private static string XmlText(byte[] content, int limit, string label)
    {
        if (content.Length > limit)
            throw new XmlProblem(label + "-byte-limit");
        Encoding encoding = StrictUtf8;
        var start = 0;
        var allowed = new[] { "utf-8" };
        if (content.AsSpan().StartsWith(new byte[] { 0xff, 0xfe }))
        {
            encoding = new UnicodeEncoding(false, false, true);
            start = 2;
            allowed = ["utf-16", "utf-16le"];
        }
        else if (content.AsSpan().StartsWith(new byte[] { 0xfe, 0xff }))
        {
            encoding = new UnicodeEncoding(true, false, true);
            start = 2;
            allowed = ["utf-16", "utf-16be"];
        }
        else if (content.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
            start = 3;
        else if (content.Contains((byte)0))
            throw new XmlProblem(label + "-encoding");
        string text;
        try
        {
            text = encoding.GetString(content.AsSpan(start));
        }
        catch (DecoderFallbackException)
        {
            throw new XmlProblem(label + "-encoding");
        }
        if (text.Contains('\0') || text.StartsWith('\ufeff'))
            throw new XmlProblem(label + "-encoding");
        var declaration = Regex.Match(text,
            @"\A[\s\u001c-\u001f]*<\?xml(?=[\s\u001c-\u001f])([^?]*)\?>",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (declaration.Success)
        {
            var declared = Regex.Match(declaration.Groups[1].Value,
                "\\bencoding\\s*=\\s*[\"']([^\"']+)[\"']",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (declared.Success && !allowed.Contains(
                declared.Groups[1].Value.ToLowerInvariant(), StringComparer.Ordinal))
                throw new XmlProblem(label + "-encoding");
        }
        return text;
    }

    private static bool HasUnsafeXmlDeclaration(string text)
    {
        if (!UnsafeXmlToken.IsMatch(text))
            return false;
        var position = 0;
        while ((position = text.IndexOf('<', position)) >= 0)
        {
            var opening = text.AsSpan(position);
            var (prefix, terminator) =
                opening.StartsWith("<!--", StringComparison.Ordinal) ? ("<!--", "-->") :
                opening.StartsWith("<![CDATA[", StringComparison.Ordinal) ? ("<![CDATA[", "]]>") :
                opening.StartsWith("<?", StringComparison.Ordinal) ? ("<?", "?>") : ("", "");
            if (prefix.Length != 0)
            {
                var end = text.IndexOf(terminator, position + prefix.Length,
                    StringComparison.Ordinal);
                if (end < 0)
                    return false;
                position = end + terminator.Length;
                continue;
            }
            if (UnsafeXmlToken.IsMatch(text, position) &&
                UnsafeXmlToken.Match(text, position).Index == position)
                return true;
            char? quote = null;
            var foundEnd = false;
            for (var index = position + 1; index < text.Length; index++)
            {
                var symbol = text[index];
                if (symbol == quote)
                    quote = null;
                else if (quote is null)
                {
                    if (symbol is '\'' or '"')
                        quote = symbol;
                    else if (symbol == '>')
                    {
                        position = index + 1;
                        foundEnd = true;
                        break;
                    }
                }
            }
            if (!foundEnd)
                return false;
        }
        return false;
    }

    private static XElement ReadXml(byte[] content, int limit, string label)
    {
        var text = XmlText(content, limit, label);
        if (HasUnsafeXmlDeclaration(text))
            throw new XmlProblem(label + "-dtd");
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = limit * 2L,
                MaxCharactersFromEntities = 0
            });
            return XDocument.Load(reader, LoadOptions.PreserveWhitespace).Root
                ?? throw new XmlProblem(label + "-parse");
        }
        catch (XmlException)
        {
            throw new XmlProblem(label + "-parse");
        }
    }

    private static bool IsSpace(byte value) =>
        value is 9 or 10 or 11 or 12 or 13 or 32;

    private static bool IsPythonSpace(char value) =>
        char.IsWhiteSpace(value) || value is >= '\u001c' and <= '\u001f';

    private static bool IsPythonWord(Rune value) =>
        value.Value is '_' or '.' or '-' ||
        Rune.GetUnicodeCategory(value) is UnicodeCategory.UppercaseLetter or
            UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter or
            UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or
            UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber or
            UnicodeCategory.OtherNumber;

    private static bool IsProjectToken(string text, int offset)
    {
        var remaining = text.AsSpan(offset);
        if (!remaining.StartsWith("<", StringComparison.Ordinal))
            return false;
        var index = 1;
        if (index >= remaining.Length)
            return false;
        if (remaining[index] is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or '_')
        {
            var prefixEnd = index + 1;
            while (prefixEnd < remaining.Length &&
                   Rune.TryGetRuneAt(text, offset + prefixEnd, out var symbol) &&
                   IsPythonWord(symbol))
                prefixEnd += symbol.Utf16SequenceLength;
            if (prefixEnd < remaining.Length && remaining[prefixEnd] == ':')
                index = prefixEnd + 1;
        }
        return remaining[index..].StartsWith("Project", StringComparison.Ordinal) &&
            index + 7 < remaining.Length &&
            (IsPythonSpace(remaining[index + 7]) || remaining[index + 7] is '/' or '>');
    }

    private static bool StartsProject(byte[] content)
    {
        var prefix = content.AsSpan(0, Math.Min(content.Length, XmlLimit));
        var utf16 = prefix.StartsWith(new byte[] { 0xff, 0xfe }) ||
            prefix.StartsWith(new byte[] { 0xfe, 0xff });
        if (!utf16 && (prefix.StartsWith(new byte[] { 0x3c, 0 }) ||
                       prefix.StartsWith(new byte[] { 0, 0x3c })))
            throw new XmlProblem("build-xml-encoding");
        if (!utf16)
        {
            if (prefix.StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
                prefix = prefix[3..];
            var spaces = 0;
            while (spaces < prefix.Length && IsSpace(prefix[spaces]))
                spaces++;
            if (spaces == prefix.Length || prefix[spaces] != '<')
            {
                if (content.Length > XmlLimit && spaces == prefix.Length)
                    throw new XmlProblem("build-xml-root-limit");
                return false;
            }
        }
        var text = XmlText(content[..Math.Min(content.Length, XmlLimit)],
            XmlLimit, "build-xml");
        var cursor = 0;
        while (true)
        {
            while (cursor < text.Length && IsPythonSpace(text[cursor]))
                cursor++;
            if (text.AsSpan(cursor).StartsWith("<!--", StringComparison.Ordinal))
            {
                var end = text.IndexOf("-->", cursor + 4, StringComparison.Ordinal);
                if (end < 0)
                    throw new XmlProblem("build-xml-root-limit");
                cursor = end + 3;
            }
            else if (Regex.Match(text[cursor..],
                @"\A<\?xml(?=[\s\u001c-\u001f])[^?]*\?>",
                RegexOptions.CultureInvariant) is { Success: true } xml)
                cursor += xml.Length;
            else
                break;
        }
        if (IsProjectToken(text, cursor))
            return true;
        var unsupported = false;
        while (true)
        {
            while (cursor < text.Length && IsPythonSpace(text[cursor]))
                cursor++;
            if (text.AsSpan(cursor).StartsWith("<!--", StringComparison.Ordinal))
            {
                var end = text.IndexOf("-->", cursor + 4, StringComparison.Ordinal);
                if (end < 0)
                    throw new XmlProblem("build-xml-root-limit");
                cursor = end + 3;
            }
            else if (text.AsSpan(cursor).StartsWith("<?", StringComparison.Ordinal))
            {
                unsupported = true;
                if (content.Length > XmlLimit)
                    throw new XmlProblem("build-xml-root-limit");
                var end = text.IndexOf("?>", cursor + 2, StringComparison.Ordinal);
                if (end < 0)
                    throw new XmlProblem("build-xml-root-limit");
                cursor = end + 2;
            }
            else if (UnsafeXmlToken.Match(text, cursor) is { Success: true } unsafeToken &&
                     unsafeToken.Index == cursor)
            {
                unsupported = true;
                if (content.Length > XmlLimit)
                    throw new XmlProblem("build-xml-root-limit");
                var depth = 0;
                char? quote = null;
                var index = cursor + 2;
                for (; index < text.Length; index++)
                {
                    var remaining = text.AsSpan(index);
                    if (quote is null &&
                        (remaining.StartsWith("<!--", StringComparison.Ordinal) ||
                         remaining.StartsWith("<?", StringComparison.Ordinal)))
                    {
                        var ending = remaining.StartsWith("<!--", StringComparison.Ordinal)
                            ? "-->" : "?>";
                        var end = text.IndexOf(ending, index + 2, StringComparison.Ordinal);
                        if (end < 0)
                            throw new XmlProblem("build-xml-root-limit");
                        index = end + ending.Length - 1;
                        continue;
                    }
                    var symbol = text[index];
                    if (symbol == quote)
                        quote = null;
                    else if (quote is null)
                    {
                        if (symbol is '\'' or '"')
                            quote = symbol;
                        else if (symbol == '[')
                            depth++;
                        else if (symbol == ']' && depth > 0)
                            depth--;
                        else if (symbol == '>' && depth == 0)
                        {
                            cursor = index + 1;
                            break;
                        }
                    }
                }
                if (index == text.Length)
                    throw new XmlProblem("build-xml-root-limit");
            }
            else
                break;
        }
        if (unsupported && IsProjectToken(text, cursor))
            throw new XmlProblem("build-xml-unsupported-prolog");
        if (content.Length > XmlLimit && (cursor == text.Length ||
            text.AsSpan(cursor).StartsWith("<!--", StringComparison.Ordinal) ||
            text.AsSpan(cursor).StartsWith("<?", StringComparison.Ordinal)))
            throw new XmlProblem("build-xml-root-limit");
        return false;
    }

    private static string? ResolveInPackage(string name, string reference,
        HashSet<string> available, bool allowLiteral)
    {
        const string prefix = "$(MSBuildThisFileDirectory)";
        string relative;
        if (reference.StartsWith(prefix, StringComparison.Ordinal))
            relative = reference[prefix.Length..];
        else if (allowLiteral && !reference.Contains("$(", StringComparison.Ordinal))
            relative = reference;
        else
            return null;
        relative = relative.Replace('\\', '/');
        if (relative.Length == 0 || relative.StartsWith('/') ||
            Regex.IsMatch(relative, @"\A[A-Za-z]:") ||
            relative.IndexOfAny(['$', '*', '?', ':']) >= 0)
            return null;
        var segments = new List<string>(name.Split('/')[..^1]);
        foreach (var part in relative.Split('/'))
        {
            if (part == ".")
                continue;
            if (part == "..")
            {
                if (segments.Count == 0)
                    return null;
                segments.RemoveAt(segments.Count - 1);
            }
            else if (part.Length > 0)
                segments.Add(part);
        }
        var target = string.Join('/', segments);
        return SafePath(target) && available.Contains(target) ? target : null;
    }

    private static bool IsDeclarativeFullPath(string value, string path,
        string? attribute, string name)
    {
        var match = DeclarativeFullPath.Match(value);
        if (!match.Success)
            return false;
        const string item = @"/ItemGroup\[\d+\]/[^/]+\[\d+\]";
        if (attribute is not null)
        {
            if (attribute.Equals("Condition", StringComparison.OrdinalIgnoreCase) ||
                !Regex.IsMatch(path, item + "$"))
                return false;
        }
        else if (!Regex.IsMatch(path, item + @"/[^/]+\[\d+\]$"))
            return false;
        var relative = match.Groups[1].Value.Replace('\\', '/');
        var segments = new List<string>(name.Split('/')[..^1]);
        foreach (var part in relative.Split('/'))
        {
            if (part == ".")
                continue;
            if (part == "..")
            {
                if (segments.Count == 0)
                    return false;
                segments.RemoveAt(segments.Count - 1);
            }
            else if (part.Length > 0)
                segments.Add(part);
        }
        return SafePath(string.Join('/', segments));
    }

    private static Dictionary<XElement, string> LocatorMap(XElement root)
    {
        var paths = new Dictionary<XElement, string>();
        void Visit(XElement node, string path, int depth)
        {
            if (depth > XmlDepthLimit)
                throw new XmlProblem("build-xml-depth-limit");
            if (paths.Count >= XmlNodeLimit)
                throw new XmlProblem("build-xml-node-limit");
            paths[node] = path;
            var siblings = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var child in node.Elements())
            {
                var local = child.Name.LocalName;
                siblings.TryGetValue(local, out var index);
                siblings[local] = ++index;
                Visit(child, $"{path}/{local}[{index}]", depth + 1);
            }
        }
        Visit(root, "Project[1]", 1);
        return paths;
    }

    private static Snippet DisplaySnippet(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var length = Math.Min(bytes.Length, SnippetLimit);
        while (length > 0)
        {
            try
            {
                return new(StrictUtf8.GetString(bytes.AsSpan(0, length)),
                    bytes.Length > SnippetLimit);
            }
            catch (DecoderFallbackException)
            {
                length--;
            }
        }
        return new("", bytes.Length > SnippetLimit);
    }

    private static string TextUntilElement(XNode? current)
    {
        var text = new StringBuilder();
        for (; current is not null && current is not XElement; current = current.NextNode)
            if (current is XText part)
                text.Append(part.Value);
        return text.ToString();
    }

    private static string NodeText(XElement node) => TextUntilElement(node.FirstNode);

    private static string TailText(XElement node) => TextUntilElement(node.NextNode);

    private static bool HasPropertyFunction(string value) =>
        PropertyFunction.IsMatch(value);

    private static (string Kind, List<Locator> Locators,
        List<string> Promotions, List<string> Imports) InspectMsbuild(
        string name, byte[] raw, HashSet<string> available)
    {
        var root = ReadXml(raw, XmlLimit, "build-xml");
        if (root.Name.LocalName != "Project" ||
            root.Name.NamespaceName is not ("" or MsbuildNamespace))
            throw new XmlProblem("build-xml-foreign-root");
        var paths = LocatorMap(root);
        var locators = new List<Locator>();
        var promotions = new HashSet<string>(StringComparer.Ordinal);
        var imports = new List<string>();
        var unresolved = false;
        void Record(XElement node, string marker, string value) =>
            locators.Add(new(paths[node] + marker, DisplaySnippet(value)));

        foreach (var (node, path) in paths)
        {
            var local = node.Name.LocalName;
            var lower = local.ToLowerInvariant();
            if (lower == "import")
            {
                var reference = node.Attribute("Project")?.Value ?? "";
                var target = ResolveInPackage(name, reference, available, allowLiteral: true)
                    ?? throw new XmlProblem("build-import-unresolved");
                imports.Add(target);
            }
            if (lower == "usingtask")
            {
                var factory = node.Attribute("TaskFactory")?.Value ?? "";
                if (node.HasElements && factory.Length > 0 &&
                    !factory.Equals("RoslynCodeTaskFactory", StringComparison.OrdinalIgnoreCase) &&
                    !factory.Equals("CodeTaskFactory", StringComparison.OrdinalIgnoreCase))
                {
                    Record(node, "@TaskFactory", factory);
                    unresolved = true;
                }
                if (node.Elements().Any(child =>
                    child.Name.LocalName.ToLowerInvariant() is not ("task" or "parametergroup")))
                {
                    Record(node, "#unsupported-inline", local);
                    unresolved = true;
                }
            }
            if (lower == "code" && path.Contains("/UsingTask[", StringComparison.Ordinal))
            {
                var source = node.Attribute("Source");
                if (source is not null)
                {
                    Record(node, "@Source", source.Value);
                    var target = ResolveInPackage(name, source.Value, available,
                        allowLiteral: false);
                    if (target is not null && target != name)
                        promotions.Add(target);
                    else
                        unresolved = true;
                    if (!string.IsNullOrWhiteSpace(NodeText(node)))
                        Record(node, "#text", NodeText(node));
                }
                else
                    Record(node, "#text", node.Value);
            }
            if (lower == "task" && path.Contains("/UsingTask[", StringComparison.Ordinal) &&
                (!string.IsNullOrWhiteSpace(NodeText(node)) ||
                 node.Elements().Any(child => child.Name.LocalName.ToLowerInvariant() != "code")))
            {
                Record(node, "#unsupported-inline", NodeText(node).Length > 0
                    ? NodeText(node) : local);
                unresolved = true;
            }
            if (lower == "exec" || lower.EndsWith(".exec", StringComparison.Ordinal))
            {
                if (Regex.IsMatch(path, @"/Target\[\d+\]/[^/]+\[\d+\]$"))
                    Record(node, "@Command", node.Attribute("Command")?.Value ?? "");
                else if (Regex.IsMatch(path, @"/Target\[\d+\]/"))
                {
                    Record(node, "#unsupported-nested-exec",
                        node.Attribute("Command")?.Value ?? "");
                    unresolved = true;
                }
            }
            if (lower is "prebuildevent" or "postbuildevent" or "runcommand" ||
                lower.EndsWith("toolexe", StringComparison.Ordinal) ||
                lower.EndsWith("toolpath", StringComparison.Ordinal) ||
                lower.StartsWith("custombeforemicrosoft", StringComparison.Ordinal) ||
                lower.StartsWith("customaftermicrosoft", StringComparison.Ordinal))
                Record(node, "#text", NodeText(node) +
                    string.Concat(node.Attributes().Select(attribute => attribute.Value)));
            foreach (var attribute in node.Attributes())
            {
                if (HasPropertyFunction(attribute.Value) &&
                    !IsDeclarativeFullPath(attribute.Value, path,
                        attribute.Name.ToString(), name))
                {
                    Record(node, "@" + attribute.Name, attribute.Value);
                    unresolved = true;
                }
            }
            var nodeText = NodeText(node);
            if (nodeText.Length > 0 && HasPropertyFunction(nodeText) &&
                !IsDeclarativeFullPath(nodeText, path, null, name))
            {
                Record(node, "#property-function", nodeText);
                unresolved = true;
            }
            var tail = TailText(node);
            if (tail.Length > 0 && HasPropertyFunction(tail))
            {
                Record(node, "#tail-function", tail);
                unresolved = true;
            }
        }
        locators.Sort((left, right) => StringComparer.Ordinal.Compare(left.Name, right.Name));
        return (unresolved ? "unsupported" : locators.Count > 0 ? "text" : "passive",
            locators, promotions.Order(StringComparer.Ordinal).ToList(),
            imports.Order(StringComparer.Ordinal).ToList());
    }

    private static (string Kind, List<Locator> Locators) InspectMarkup(byte[] raw)
    {
        var root = ReadXml(raw, XmlLimit, "build-xml");
        var locators = new List<Locator>();
        foreach (var (node, path) in LocatorMap(root))
        {
            if (node.Name.LocalName.ToLowerInvariant() is "script" or "scriptblock" or "template")
                locators.Add(new(path, DisplaySnippet(node.Value)));
            foreach (var attribute in node.Attributes())
            {
                if (attribute.Name.LocalName.StartsWith("on", StringComparison.OrdinalIgnoreCase) ||
                    attribute.Value.Contains("javascript:", StringComparison.OrdinalIgnoreCase))
                    locators.Add(new(path + "@" + attribute.Name, DisplaySnippet(attribute.Value)));
            }
        }
        locators.Sort((left, right) => StringComparer.Ordinal.Compare(left.Name, right.Name));
        return (locators.Count > 0 ? "text" : "passive", locators);
    }
}
