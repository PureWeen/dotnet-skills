using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Validation;

namespace BlazorComponentReadiness.Validator.Assessment;

internal sealed class AuthorizedPackageScope
{
    internal const string Kind = "authorized-package-report-scope";
    internal const string Filename = "authorized-package-report-scope.json";
    private const string ApprovedManifestSha256 =
        "198408473143cfead54e9632bd8f5b7d6c7d096624170f1538fbeff9b9442984";
    private readonly byte[] _bytes;
    private readonly Regex _excludedIds;

    private AuthorizedPackageScope(
        byte[] bytes,
        string authorizationId,
        string documentFilename,
        Sha256Digest documentDigest,
        EvidencePackageIdentity package,
        IReadOnlyList<RubricRequirement> requirements,
        Sha256Digest selectedSetDigest,
        IEnumerable<string> excludedIds)
    {
        _bytes = bytes;
        AuthorizationId = authorizationId;
        DocumentFilename = documentFilename;
        DocumentDigest = documentDigest;
        Package = package;
        Requirements = requirements;
        SelectedSetDigest = selectedSetDigest;
        _excludedIds = new Regex(
            @"(?<![A-Z0-9])(?:" + string.Join("|", excludedIds.Select(Regex.Escape)) + @")(?![A-Z0-9])",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    }

    internal string AuthorizationId { get; }
    internal string DocumentFilename { get; }
    internal Sha256Digest DocumentDigest { get; }
    internal EvidencePackageIdentity Package { get; }
    internal IReadOnlyList<RubricRequirement> Requirements { get; }
    internal Sha256Digest SelectedSetDigest { get; }
    internal Sha256Digest ManifestDigest => new("sha256", ApprovedManifestSha256);
    internal byte[] CopyBytes() => (byte[])_bytes.Clone();

    internal string Declaration =>
        $"**Requirement source:** `{DocumentFilename}` (SHA-256 `{DocumentDigest.Value}`).\n" +
        $"**Authorized package-report scope:** `{AuthorizationId}`; {Requirements.Count} DOCX-grounded package requirements.\n" +
        $"**Scope manifest SHA-256:** `{ManifestDigest.Value}`.\n" +
        $"**Selected-set SHA-256:** `{SelectedSetDigest.Value}`.";

    internal static bool IsRequested(InputManifest input) =>
        input.EvidenceInputs.Any(IsScopeInput);

    private static bool IsScopeInput(InputEvidenceArtifact item) =>
        item.Kind.StartsWith(Kind, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(item.Basename, Filename, StringComparison.OrdinalIgnoreCase);

    internal static AuthorizedPackageScope? Load(string? root, InputManifest input)
    {
        var entries = input.EvidenceInputs.Where(IsScopeInput).ToArray();
        if (entries.Length == 0)
        {
            return null;
        }

        if (entries is not [{ Kind: Kind, Basename: Filename }] || root is null)
        {
            throw new DeterministicValidationException(
                "Authorized package scope requires exactly one supported retained manifest and an input root; it cannot fall back to ordinary selection.");
        }

        var entry = entries[0];
        var path = SafePath.ResolveUnderRoot(root, entry.Basename, requireExisting: true, requireFile: true);
        var bytes = BoundedIO.ReadAllBytes(path, ResourceLimits.SerializedArtifactBytes, "authorized package scope");
        if (entry.Size != bytes.LongLength || entry.ContentDigest != ContractJson.RawDigest(bytes))
        {
            throw new DeterministicValidationException("Authorized package scope differs from its confirmed input binding.");
        }

        var scope = Parse(bytes);
        if (scope.Package != new EvidencePackageIdentity(
                input.Package.PackageId, input.Package.Version, input.Package.NupkgDigest))
        {
            throw new DeterministicValidationException("Authorized package scope belongs to a different exact package.");
        }

        var document = input.EvidenceInputs.Where(item => item.Basename == scope.DocumentFilename).ToArray();
        if (document.Length != 1 || document[0].ContentDigest != scope.DocumentDigest)
        {
            throw new DeterministicValidationException("Authorized package scope requires the exact frozen DOCX input.");
        }

        var documentBytes = BoundedIO.ReadAllBytes(
            SafePath.ResolveUnderRoot(root, scope.DocumentFilename, requireExisting: true, requireFile: true),
            ResourceLimits.SupplementalInputAggregateBytes,
            "frozen requirements DOCX");
        if (document[0].Size != documentBytes.LongLength ||
            ContractJson.RawDigest(documentBytes) != scope.DocumentDigest)
        {
            throw new DeterministicValidationException("Frozen requirements DOCX differs from the authorized scope.");
        }

        return scope;
    }

    internal static AuthorizedPackageScope Parse(ReadOnlyMemory<byte> bytes)
    {
        using var document = StrictJson.Parse(bytes, ResourceLimits.SerializedArtifactBytes, "authorized package scope");
        var value = document.RootElement;
        ContractJson.RequireProperties(value, "schema_version", "kind", "authorization_id", "requirement_source",
            "package", "rubric_version", "selected_ids", "row_count", "selected_set_sha256",
            "scope_correction", "recovery_authorization");
        var source = ContractJson.Object(value, "requirement_source");
        ContractJson.RequireProperties(source, "filename", "sha256");
        var package = ContractJson.Object(value, "package");
        ContractJson.RequireProperties(package, "package_id", "version", "nupkg_sha256");
        foreach (var name in new[] { "scope_correction", "recovery_authorization" })
        {
            var reference = ContractJson.Object(value, name);
            ContractJson.RequireProperties(reference, "basename", "sha256");
            _ = Canonicalization.Basename(ContractJson.String(reference, "basename"), name);
            _ = ContractJson.Digest(ContractJson.Object(reference, "sha256"));
        }

        var rubric = RubricLoader.Load(ContractJson.String(value, "rubric_version"));
        var packageRows = RubricLoader.Select(rubric, "package", []);
        var selected = packageRows.Where(row => row.Basis is { RequiresPolicyApproval: false }).ToArray();
        var ids = ContractJson.StringArray(value, "selected_ids");
        var selectedDigest = ContractJson.Digest(ContractJson.Object(value, "selected_set_sha256"));
        var idBytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartArray();
            foreach (var id in ids)
            {
                writer.WriteStringValue(id);
            }

            writer.WriteEndArray();
        });
        if (ContractJson.Int32(value, "schema_version") != 1 ||
            ContractJson.String(value, "kind") != Kind ||
            rubric.RubricVersion != RubricLoader.CurrentVersion ||
            selected.Length != 48 ||
            ContractJson.Int32(value, "row_count") != selected.Length ||
            !ids.SequenceEqual(selected.Select(row => row.Id), StringComparer.Ordinal) ||
            selectedDigest != ContractJson.RawDigest(idBytes))
        {
            throw new DeterministicValidationException(
                "Authorized package scope must contain exactly the approved DOCX-grounded package IDs in canonical order, with matching count and selected-set digest.");
        }

        ContractJson.RequireCanonical(bytes.Span, StrictJson.SerializeCanonical(value.WriteTo), "authorized package scope");
        // Authority is pinned outside the supplied document, not asserted by its contents or path.
        if (ContractJson.RawDigest(bytes.Span).Value != ApprovedManifestSha256)
        {
            throw new DeterministicValidationException("Unsupported authorized package scope or altered approval binding.");
        }

        return new AuthorizedPackageScope(
            bytes.ToArray(),
            ContractJson.String(value, "authorization_id"),
            Canonicalization.Basename(ContractJson.String(source, "filename"), "requirements document"),
            ContractJson.Digest(ContractJson.Object(source, "sha256")),
            new EvidencePackageIdentity(ContractJson.String(package, "package_id"),
                ContractJson.String(package, "version"), ContractJson.Digest(ContractJson.Object(package, "nupkg_sha256"))),
            selected,
            selectedDigest,
            packageRows.Where(row => row.Basis?.RequiresPolicyApproval == true).Select(row => row.Id));
    }

    internal IReadOnlyList<RubricRequirement> Select(RubricContract rubric, string assessmentKind)
    {
        if (assessmentKind != "package" || rubric.RubricVersion != RubricLoader.CurrentVersion)
        {
            throw new DeterministicValidationException(
                "Authorized package scope cannot be applied to a component, unified assessment, or another rubric.");
        }

        return Requirements;
    }

    internal void Validate(ReadinessAssessment assessment, InputManifest input, EvidenceBundle evidence)
    {
        var rubric = RubricLoader.Load();
        var expectedIds = Requirements.Select(row => row.Id).ToArray();
        if (assessment.AssessmentKind != "package" ||
            assessment.SchemaVersion != AssessmentService.SchemaVersion ||
            assessment.RubricVersion != RubricLoader.CurrentVersion ||
            assessment.ScopeSchemaVersion != rubric.ScopeSchemaVersion ||
            assessment.RubricDigest != rubric.RubricDigest ||
            assessment.ScopeMapDigest != rubric.ScopeMapDigest ||
            assessment.Overlays.Count != 0 ||
            assessment.Identity.AssessmentKind != "package" ||
            assessment.Identity.ComponentId is not null ||
            assessment.PackageReference is not null ||
            assessment.Identity.Package != Package ||
            assessment.Identity.InputManifestDigest != InputManifestService.Digest(InputManifestService.Serialize(input)) ||
            evidence.Assessment != assessment.Identity ||
            !assessment.SelectedIds.SequenceEqual(expectedIds, StringComparer.Ordinal) ||
            !assessment.Rows.Select(row => row.Id).SequenceEqual(expectedIds, StringComparer.Ordinal))
        {
            throw new DeterministicValidationException("Assessment and evidence do not represent the exact authorized package scope.");
        }

        if (assessment.Rows.Zip(Requirements).Any(pair =>
                pair.First.Requirement != pair.Second.Requirement ||
                pair.First.Scope != pair.Second.Scope ||
                pair.First.Area != pair.Second.Area))
        {
            throw new DeterministicValidationException("Authorized assessment has canonical requirement, ownership or area drift.");
        }

        var records = evidence.SourceLedgers.SelectMany(item => item.Ledger.Records).ToArray();
        var selected = evidence.Selection.Select(item => item.EvidenceId).ToHashSet(StringComparer.Ordinal);
        var used = assessment.Rows.SelectMany(row => row.EvidenceIds).ToHashSet(StringComparer.Ordinal);
        if (records.Length != selected.Count ||
            !records.Select(record => record.StableId).ToHashSet(StringComparer.Ordinal).SetEquals(selected) ||
            !used.SetEquals(selected))
        {
            throw new DeterministicValidationException(
                "Authorized scope requires a selected-only evidence companion. Keep complete historical ledgers and unselected records internal.");
        }

        RejectDisclosure(Encoding.UTF8.GetString(AssessmentService.Serialize(assessment)));
        RejectDisclosure(Encoding.UTF8.GetString(InputManifestService.Serialize(input)));
        RejectDisclosure(Encoding.UTF8.GetString(CanonicalEvidenceJson.SerializeBundle(evidence)));
    }

    internal void RejectDisclosure(string text)
    {
        var decoded = WebUtility.HtmlDecode(text)
            .Replace('\u2010', '-').Replace('\u2011', '-').Replace('\u2013', '-');
        if (_excludedIds.IsMatch(decoded) ||
            decoded.Contains("versioned extension", StringComparison.OrdinalIgnoreCase) ||
            Regex.IsMatch(decoded,
                @"\b(?:60|121)\s*[- ]\s*(?:canonical\s+)?(?:package\s+)?(?:rows?|checks?|requirements?|findings?)\b|\b12\s*[- ]\s*(?:excluded\s+)?extensions?\b",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase))
        {
            throw new DeterministicValidationException("Internal extension material cannot appear in authorized partner output.");
        }
    }
}
