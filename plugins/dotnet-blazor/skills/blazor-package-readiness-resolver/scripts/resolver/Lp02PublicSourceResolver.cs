using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace BlazorPackageResolver;

public sealed record Lp02Package(string Id, string Version, string RepositoryUrl, string Commit);
public sealed record Lp02RetrievalAttempt(
    string Url, string ObservedAtUtc, string Transport, string Result, int? HttpStatus);
public sealed record Lp02CaptureReceipt(string Role, string Sha256);
public sealed record Lp02SourceFile(string Kind, string Path, string Sha256);
public sealed record Lp02Observation(
    int SchemaVersion, string Producer, string PackageId, string PackageVersion,
    string PackageSha256, string RepositoryUrl, string Commit,
    Lp02RetrievalAttempt RetrievalAttempt, Lp02CaptureReceipt? CaptureReceipt,
    Lp02SourceFile[] SourceInventory, string MappingRationale);

public sealed class Lp02PublicSourceResolver : IDeterministicResolver
{
    public const int MaxArchiveBytes = 64 * 1024 * 1024;
    public const int MaxObservationBytes = 16 * 1024;
    public const int MaxSelectedFileBytes = 1024 * 1024;
    public const string Producer = "lp02-anonymous-github/1.0.0";
    public const string Transport = "direct-https-no-credentials/1";
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };
    private static readonly Regex Repository = new(
        @"\Ahttps://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex CommitPattern = new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Digest = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex RelativePath = new(
        @"\A[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\z", RegexOptions.CultureInvariant);
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public string RowId => "LP-02";
    public string ResolverId => "lp02-public-source";
    public string Version => "1.2.0";

    public CaseResult Resolve(ResolverCase input)
    {
        CaseResult Result(string branch, string? finding = null) => new(
            RowId, ResolverId, Version, branch, finding is null ? "escalated" : "deterministic",
            finding is null ? "unknown" : "applicable", input.Inputs,
            input.Inputs.Select(i => $"input:{i.Role}:{i.Sha256}").ToArray(),
            "Checked bytes only. Capture receipts are retained acquisition observations, not signed attestations. Unresolved means not tested, not a closed-source finding or gap.",
            finding, finding is null ? MissingFact(branch) : null,
            finding is null ? "exact-package-and-anonymous-source-capture" : null,
            finding is null ? "source-acquisition" : null);

        if (!input.CheckedInputs.TryGetValue("package", out var package))
            return Result("missing-package");
        var (state, declaration) = InspectPackage(package.Content);
        if (state != "ready" || declaration is null) return Result(state);
        if (!TryRepository(declaration.RepositoryUrl, declaration.Commit, out var repository, out var url))
            return Result("public-retrieval-unresolved");
        if (!input.CheckedInputs.TryGetValue("source-observation", out var observation))
            return Result("observation-missing");
        if (input.Inputs.Any(i => i.Role is not ("package" or "source-observation" or "source-archive") ||
            !SafePath(i.Path)))
            return Result("observation-invalid");
        var record = ReadObservation(observation.Content);
        if (record is null) return Result("observation-invalid");
        if (record.PackageId != declaration.Id || record.PackageVersion != declaration.Version ||
            record.PackageSha256 != package.Identity.Sha256 || record.RepositoryUrl != repository ||
            record.Commit != declaration.Commit || record.RetrievalAttempt.Url != url)
            return Result("observation-binding-conflict");
        if (record.RetrievalAttempt.Result != "retrieved")
            return Result("public-retrieval-unresolved");
        if (!input.CheckedInputs.TryGetValue("source-archive", out var source))
            return Result("observation-missing");
        if (record.CaptureReceipt!.Sha256 != source.Identity.Sha256)
            return Result("observation-binding-conflict");
        if (!TryArchive(source.Content, out var files, declaration.Commit, sourceMembers: true) || files.Count == 0)
            return Result("observation-invalid");
        var root = repository.Split('/')[^1] + "-" + declaration.Commit;
        if (files.Keys.Any(path => !path.StartsWith(root + "/", StringComparison.OrdinalIgnoreCase)))
            return Result("observation-invalid");
        foreach (var selected in record.SourceInventory)
        {
            if (!files.TryGetValue(selected.Path, out var bytes))
                return Result("source-relevance-unestablished");
            if (Catalog.Digest(bytes) != selected.Sha256)
                return Result("observation-binding-conflict");
        }
        return Result("public-source-observed",
            $"The exact package declares repository {repository} and commit {declaration.Commit}. " +
            $"At time {record.RetrievalAttempt.ObservedAtUtc}, that revision was retrieved without application credentials, " +
            "and the retained nonempty archive matches the declared repository/revision root. " +
            "This establishes public source availability at the package-declared revision. " +
            "The package declaration supplies that association; source relevance is not independently established. " +
            "It does not establish that the published binaries were built from that revision. " +
            "It also does not establish membership in the declared repository's branches or tags, " +
            "because codeload may serve fork-network commit objects.");
    }

    private static string MissingFact(string branch) => branch switch
    {
        "missing-package" => "The exact checked package is missing.",
        "package-unreadable" => "The package is outside the bounded ZIP/nuspec profile or its identity declarations are ambiguous.",
        "source-declaration-missing" => "The exact package lacks one nonblank repository URL and exact commit declaration.",
        "observation-missing" => "Declared source is unverified: the checked anonymous acquisition observation or source archive is missing.",
        "observation-invalid" => "The acquisition observation or retained archive is outside the supported evidence profile.",
        "observation-binding-conflict" => "The observation, package, revision or retained source digests do not bind exactly.",
        "public-retrieval-unresolved" => "Anonymous public retrieval is unresolved or unsupported; public source availability is not tested.",
        _ => "A selected supplemental source file is absent from the checked archive."
    };

    public static (string State, Lp02Package? Package) InspectPackage(ReadOnlyMemory<byte> bytes)
    {
        if (!TryArchive(bytes, out var entries)) return ("package-unreadable", null);
        var nuspecs = entries.Keys.Where(p => !p.Contains('/') &&
            p.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (nuspecs.Length != 1 || entries[nuspecs[0]].Length > MaxSelectedFileBytes ||
            !Lp01LicensePolicyResolver.SupportedXmlEncoding(entries[nuspecs[0]]))
            return ("package-unreadable", null);
        var read = NuGetNuspecReader.Read(bytes);
        if (read.Status != NuspecStatus.Ready || read.Metadata is null)
            return ("package-unreadable", null);
        var metadata = read.Metadata;
        var ns = metadata.Name.Namespace;
        XElement? Single(string name)
        {
            var matches = metadata.Elements().Where(e => e.Name.LocalName == name).ToArray();
            return matches.Length == 1 && matches[0].Name.Namespace == ns &&
                !matches[0].HasElements ? matches[0] : null;
        }
        var id = Single("id");
        var version = Single("version");
        if (id is null || version is null || !ShortText(id.Value, 256) ||
            !ShortText(version.Value, 256) || id.HasAttributes || version.HasAttributes)
            return ("package-unreadable", null);
        var repositories = metadata.Elements().Where(e => e.Name.LocalName == "repository").ToArray();
        if (repositories.Length > 1 || repositories.Any(e => e.Name.Namespace != ns || e.HasElements ||
            !string.IsNullOrWhiteSpace(e.Value) ||
            e.Attributes().Any(a => !a.IsNamespaceDeclaration &&
                (a.Name.NamespaceName.Length != 0 || a.Name.LocalName is not ("url" or "commit" or "type" or "branch")))))
            return ("package-unreadable", null);
        var repository = Single("repository");
        var url = ((string?)repository?.Attribute("url"))?.Trim();
        var commit = ((string?)repository?.Attribute("commit"))?.Trim().ToLowerInvariant();
        if (!ShortText(url, 256) || !ShortText(commit, 64))
            return ("source-declaration-missing", null);
        return ("ready", new(id.Value.Trim(), version.Value.Trim(), url!, commit!));
    }

    internal static bool TryRepository(string value, string commit, out string canonical, out string url)
    {
        canonical = value.EndsWith(".git", StringComparison.Ordinal) ? value[..^4] : value;
        url = "";
        var match = Repository.Match(canonical);
        if (!match.Success || match.Groups[2].Value is "." or ".." ||
            !CommitPattern.IsMatch(commit) || commit.All(c => c == '0'))
            return false;
        url = $"https://codeload.github.com/{match.Groups[1].Value}/{match.Groups[2].Value}/zip/{commit}";
        return true;
    }

    internal static bool SafePath(string? path) => path is { Length: > 0 and <= 256 } &&
        RelativePath.IsMatch(path) && !path.Split('/').Any(p => p is "." or "..");

    internal static bool TryArchive(ReadOnlyMemory<byte> bytes, out Dictionary<string, byte[]> files,
        string? sourceCommit = null, bool sourceMembers = false)
    {
        files = new(StringComparer.Ordinal);
        if (!NuGetNuspecReader.HasBoundedDirectory(bytes.Span, out var count)) return false;
        try
        {
            using var stream = new MemoryStream(bytes.ToArray(), writable: false);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, false, Lp01ArchiveIntegrity.Cp437);
            if (archive.Entries.Count != count || archive.Entries.Any(e =>
                !((sourceMembers ? SafeSourceMemberPath(e.FullName.EndsWith('/') ? e.FullName[..^1] : e.FullName) :
                    SafePath(e.FullName.EndsWith('/') ? e.FullName[..^1] : e.FullName)) ||
                    e.FullName == "[Content_Types].xml") ||
                e.FullName.EndsWith('/') && e.Length != 0 ||
                (e.ExternalAttributes >> 16 & 0xf000) == 0xa000) ||
                sourceMembers && archive.Entries.Select(e => Lp01CaseFold.Fold(e.FullName.TrimEnd('/')))
                    .Distinct(StringComparer.Ordinal).Count() != archive.Entries.Count ||
                !Lp01ArchiveIntegrity.Validate(bytes.Span, archive.Entries,
                    sourceCommit is not null && archive.Comment.Length > 0 ? Encoding.ASCII.GetBytes(sourceCommit) : []))
                return false;
            foreach (var entry in archive.Entries.Where(e => !e.FullName.EndsWith('/')))
            {
                using var source = entry.Open();
                using var buffer = new MemoryStream();
                source.CopyTo(buffer);
                files.Add(entry.FullName, buffer.ToArray());
            }
            return true;
        }
        catch (InvalidDataException) { return false; }
        catch (IOException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    internal static bool SafeSourceMemberPath(string? path) => path is { Length: > 0 and <= 256 } &&
        Regex.IsMatch(path, @"\A[A-Za-z0-9_.$ -]+(?:/[A-Za-z0-9_.$ -]+)*\z", RegexOptions.CultureInvariant) &&
        path.Split('/').All(part => part is not ("." or "..") && !part.StartsWith(' ') &&
            !part.EndsWith(' ') && !part.EndsWith('.') && !Regex.IsMatch(part.Split('.')[0],
                @"\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$|CLOCK\$)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    private static Lp02Observation? ReadObservation(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length > MaxObservationBytes) return null;
        try
        {
            _ = Utf8.GetCharCount(bytes.Span);
            using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            if (!UniqueFields(json.RootElement)) return null;
            var record = json.Deserialize<Lp02Observation>(JsonOptions);
            if (record is null || record.SchemaVersion != 1 || record.Producer != Producer ||
                !ShortText(record.PackageId, 256) || !ShortText(record.PackageVersion, 256) ||
                !IsDigest(record.PackageSha256) || record.RepositoryUrl is null || record.Commit is null ||
                record.RetrievalAttempt is not { } attempt || attempt.Transport != Transport ||
                !DateTimeOffset.TryParseExact(attempt.ObservedAtUtc, "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _) ||
                attempt.Url is null || record.SourceInventory is null ||
                record.SourceInventory.Length > 2 || !ShortText(record.MappingRationale, 1000))
                return null;
            var statusValid = attempt.Result switch
            {
                "retrieved" => attempt.HttpStatus == 200,
                "not-found" => attempt.HttpStatus == 404,
                "auth-required" => attempt.HttpStatus is 401 or 403,
                "blocked" => attempt.HttpStatus is 429 or 451,
                "unavailable" => attempt.HttpStatus is null or >= 500 and <= 599,
                "unsupported" => attempt.HttpStatus is null or >= 100 and <= 599,
                _ => false
            };
            if (!statusValid) return null;
            if (attempt.Result != "retrieved")
                return record.CaptureReceipt is null && record.SourceInventory.Length == 0 ? record : null;
            if (record.CaptureReceipt is not { Role: "source-archive" } capture || !IsDigest(capture.Sha256) ||
                record.SourceInventory.Any(f => f is null || f.Kind is not ("project" or "implementation") ||
                    !SafeSourceMemberPath(f.Path) || !IsDigest(f.Sha256)) ||
                record.SourceInventory.Select(f => f.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() !=
                    record.SourceInventory.Length ||
                record.SourceInventory.Select(f => f.Kind).Distinct(StringComparer.Ordinal).Count() !=
                    record.SourceInventory.Length)
                return null;
            return record;
        }
        catch (JsonException) { return null; }
        catch (DecoderFallbackException) { return null; }
        // JSON field/string access can defer decoding escaped Unicode until after parsing.
        catch (InvalidOperationException) { return null; }
    }

    private static bool UniqueFields(JsonElement node) => node.ValueKind switch
    {
        JsonValueKind.Object => node.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() ==
            node.EnumerateObject().Count() && node.EnumerateObject().All(p => UniqueFields(p.Value)),
        JsonValueKind.Array => node.EnumerateArray().All(UniqueFields),
        _ => true
    };

    private static bool IsDigest(string? text) => text is not null && Digest.IsMatch(text);
    private static bool ShortText(string? text, int limit) => !string.IsNullOrWhiteSpace(text) &&
        text.Length <= limit && text.All(c => c is >= ' ' and <= '~');

}
