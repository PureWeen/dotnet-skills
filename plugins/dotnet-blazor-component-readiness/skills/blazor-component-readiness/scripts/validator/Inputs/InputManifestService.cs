using System.Text.Json;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Validation;

namespace BlazorComponentReadiness.Validator.Inputs;

public static class InputManifestService
{
    public const int SchemaVersion = 1;

    public static InputManifest Discover(string root, string nupkgPath, ReadOnlyMemory<byte> candidateBytes)
    {
        var packageRelativePath = GetRelativePath(root, nupkgPath, "nupkg");
        var inspected = NupkgInspector.Inspect(
            SafePath.ResolveUnderRoot(root, packageRelativePath, requireExisting: true, requireFile: true));
        using var document = StrictJson.Parse(
            candidateBytes,
            ResourceLimits.SerializedArtifactBytes,
            "input discovery candidates");
        var candidate = document.RootElement;
        ContractJson.RequireProperties(
            candidate,
            "schema_version",
            "acquisition",
            "source",
            "documentation",
            "package_sources",
            "owner_inputs",
            "components",
            "exclusions");
        if (ContractJson.Int32(candidate, "schema_version") != SchemaVersion)
        {
            throw new DeterministicValidationException("Input discovery candidate schema_version must be 1.");
        }

        var acquisition = ContractJson.String(candidate, "acquisition");
        if (acquisition is not ("published" or "release-candidate"))
        {
            throw new DeterministicValidationException(
                "acquisition must be 'published' or 'release-candidate'.");
        }

        var source = ParseCandidateSource(ContractJson.Object(candidate, "source"));
        var documentation = ContractJson.Array(candidate, "documentation")
            .EnumerateArray()
            .Select(item => CreateDocument(root, item))
            .OrderBy(item => item.Url, StringComparer.Ordinal)
            .ToArray();
        var packageSources = ContractJson.Array(candidate, "package_sources")
            .EnumerateArray()
            .Select(item => CreatePackageSource(root, item))
            .OrderBy(item => item.Kind, StringComparer.Ordinal)
            .ThenBy(item => item.Locator, StringComparer.Ordinal)
            .ToArray();
        var ownerInputs = ContractJson.Array(candidate, "owner_inputs")
            .EnumerateArray()
            .Select(item => CreateOwnerInput(root, item))
            .OrderBy(item => item.Basename, StringComparer.Ordinal)
            .ToArray();
        ValidateOwnerCeilings(ownerInputs);
        var components = ContractJson.Array(candidate, "components")
            .EnumerateArray()
            .Select(ParseCandidateComponent)
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ToArray();
        var exclusions = ContractJson.Array(candidate, "exclusions")
            .EnumerateArray()
            .Select(ParseExclusion)
            .OrderBy(item => item.Subject, StringComparer.Ordinal)
            .ThenBy(item => item.Rationale, StringComparer.Ordinal)
            .ToArray();

        var manifest = new InputManifest(
            SchemaVersion,
            "draft",
            acquisition,
            new InputPackage(
                Canonicalization.PackageId(inspected.Id),
                NuGetVersionNormalizer.Normalize(inspected.Version),
                new Sha256Digest("sha256", inspected.NupkgSha256),
                packageRelativePath),
            source,
            RequireUnique(documentation, item => item.Url, "documentation URL"),
            RequireUnique(packageSources, item => $"{item.Kind}\0{item.Locator}", "package source"),
            RequireUnique(ownerInputs, item => item.Basename, "owner input basename"),
            RequireUnique(components, item => item.Id, "component ID"),
            exclusions);
        Validate(manifest, root, requireConfirmed: false);
        return manifest;
    }

    public static InputManifest Confirm(InputManifest draft, string root)
    {
        Validate(draft, root, requireConfirmed: false);
        if (draft.State != "draft")
        {
            throw new DeterministicValidationException("Only a draft input manifest can be confirmed.");
        }

        var confirmed = draft with { State = "confirmed" };
        Validate(confirmed, root, requireConfirmed: true);
        return confirmed;
    }

    public static void Validate(InputManifest manifest, string root, bool requireConfirmed)
    {
        if (manifest.SchemaVersion != SchemaVersion ||
            manifest.State is not ("draft" or "confirmed") ||
            requireConfirmed && manifest.State != "confirmed" ||
            manifest.Acquisition is not ("published" or "release-candidate"))
        {
            throw new DeterministicValidationException("Input manifest schema, state, or acquisition is invalid.");
        }

        var packagePath = SafePath.ResolveUnderRoot(
            root,
            manifest.Package.NupkgPath,
            requireExisting: true,
            requireFile: true);
        var inspected = NupkgInspector.Inspect(packagePath);
        var expectedPackage = new InputPackage(
            Canonicalization.PackageId(inspected.Id),
            NuGetVersionNormalizer.Normalize(inspected.Version),
            new Sha256Digest("sha256", inspected.NupkgSha256),
            Canonicalization.RelativePath(manifest.Package.NupkgPath, "nupkg_path"));
        if (manifest.Package != expectedPackage)
        {
            throw new DeterministicValidationException(
                "Input manifest package identity or digest does not match the exact inspected nupkg.");
        }

        ValidateSource(manifest.Source);
        ValidateUniqueAndSorted(manifest.Documentation, item => item.Url, "documentation");
        foreach (var document in manifest.Documentation)
        {
            var canonical = new InputDocument(
                Canonicalization.HttpsUri(document.Url, requirePath: false),
                Canonicalization.RelativePath(document.ContentPath, "documentation content_path"),
                document.ContentDigest);
            if (canonical != document)
            {
                throw new DeterministicValidationException("Documentation input is not canonical.");
            }

            ValidateLocalDigest(root, document.ContentPath, document.ContentDigest, "documentation content");
        }

        ValidateUniqueAndSorted(
            manifest.PackageSources,
            item => $"{item.Kind}\0{item.Locator}",
            "package sources");
        foreach (var source in manifest.PackageSources)
        {
            if (source.Kind is not ("package-readme" or "package-metadata") ||
                Canonicalization.RelativePath(source.ContentPath, "package source content_path") != source.ContentPath ||
                ContractJson.NormalizeText(source.Locator, "package source locator", 512) != source.Locator)
            {
                throw new DeterministicValidationException("Package source is not canonical.");
            }

            ValidateLocalDigest(root, source.ContentPath, source.ContentDigest, "package source content");
        }

        ValidateUniqueAndSorted(manifest.OwnerInputs, item => item.Basename, "owner inputs");
        ValidateOwnerCeilings(manifest.OwnerInputs);
        foreach (var owner in manifest.OwnerInputs)
        {
            if (Canonicalization.Basename(owner.Basename, "owner input basename") != owner.Basename ||
                owner.Provenance is not ("owner-supplied-internal-evidence" or "owner-supplied-public-evidence"))
            {
                throw new DeterministicValidationException("Owner input basename or provenance is invalid.");
            }

            var path = SafePath.ResolveUnderRoot(root, owner.Basename, requireExisting: true, requireFile: true);
            BoundedIO.EnsureFileLength(path, ResourceLimits.SupplementalInputAggregateBytes, "owner input");
            if (new FileInfo(path).Length != owner.Size)
            {
                throw new DeterministicValidationException(
                    $"Owner input '{owner.Basename}' has a stale byte size.");
            }

            ValidateLocalDigest(root, owner.Basename, owner.ContentDigest, "owner input");
        }

        ValidateUniqueAndSorted(manifest.Components, item => item.Id, "components");
        if (manifest.Components.Count == 0)
        {
            throw new DeterministicValidationException("Input manifest requires a confirmed component inventory.");
        }

        foreach (var component in manifest.Components)
        {
            if (Canonicalization.ComponentId(component.Id) != component.Id ||
                ContractJson.NormalizeText(component.DisplayName, "component display name", 256) != component.DisplayName ||
                component.RenderModes.Count == 0)
            {
                throw new DeterministicValidationException("Component inventory entry is invalid.");
            }

            var normalizedModes = component.RenderModes.Select(Canonicalization.RenderMode)
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
            if (!normalizedModes.SequenceEqual(component.RenderModes, StringComparer.Ordinal))
            {
                throw new DeterministicValidationException("Component render modes are not canonical, unique, and sorted.");
            }
        }

        var exclusions = manifest.Exclusions
            .OrderBy(item => item.Subject, StringComparer.Ordinal)
            .ThenBy(item => item.Rationale, StringComparer.Ordinal)
            .ToArray();
        if (!exclusions.SequenceEqual(manifest.Exclusions))
        {
            throw new DeterministicValidationException("Exclusions are not in canonical order.");
        }

        foreach (var exclusion in manifest.Exclusions)
        {
            _ = ContractJson.NormalizeText(exclusion.Subject, "exclusion subject", 256);
            _ = ContractJson.NormalizeText(exclusion.Rationale, "exclusion rationale", 2048);
        }
    }

    public static byte[] Serialize(InputManifest manifest)
    {
        var bytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", manifest.SchemaVersion);
            writer.WriteString("state", manifest.State);
            writer.WriteString("acquisition", manifest.Acquisition);
            writer.WritePropertyName("package");
            writer.WriteStartObject();
            writer.WriteString("package_id", manifest.Package.PackageId);
            writer.WriteString("version", manifest.Package.Version);
            ContractJson.WriteDigest(writer, "nupkg_sha256", manifest.Package.NupkgDigest);
            writer.WriteString("nupkg_path", manifest.Package.NupkgPath);
            writer.WriteEndObject();
            writer.WritePropertyName("source");
            writer.WriteStartObject();
            writer.WriteString("availability", manifest.Source.Availability);
            WriteNullable(writer, "repository_uri", manifest.Source.RepositoryUri);
            WriteNullable(writer, "commit", manifest.Source.Commit);
            WriteNullable(writer, "mapping", manifest.Source.Mapping);
            WriteNullable(writer, "confidence", manifest.Source.Confidence);
            writer.WriteEndObject();
            writer.WritePropertyName("documentation");
            writer.WriteStartArray();
            foreach (var document in manifest.Documentation)
            {
                writer.WriteStartObject();
                writer.WriteString("url", document.Url);
                writer.WriteString("content_path", document.ContentPath);
                ContractJson.WriteDigest(writer, "content_sha256", document.ContentDigest);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WritePropertyName("package_sources");
            writer.WriteStartArray();
            foreach (var source in manifest.PackageSources)
            {
                writer.WriteStartObject();
                writer.WriteString("kind", source.Kind);
                writer.WriteString("locator", source.Locator);
                writer.WriteString("content_path", source.ContentPath);
                ContractJson.WriteDigest(writer, "content_sha256", source.ContentDigest);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WritePropertyName("owner_inputs");
            writer.WriteStartArray();
            foreach (var owner in manifest.OwnerInputs)
            {
                writer.WriteStartObject();
                writer.WriteString("basename", owner.Basename);
                writer.WriteString("provenance", owner.Provenance);
                ContractJson.WriteDigest(writer, "content_sha256", owner.ContentDigest);
                writer.WriteNumber("size", owner.Size);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WritePropertyName("components");
            writer.WriteStartArray();
            foreach (var component in manifest.Components)
            {
                writer.WriteStartObject();
                writer.WriteString("id", component.Id);
                writer.WriteString("display_name", component.DisplayName);
                writer.WritePropertyName("render_modes");
                writer.WriteStartArray();
                foreach (var mode in component.RenderModes)
                {
                    writer.WriteStringValue(mode);
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WritePropertyName("exclusions");
            writer.WriteStartArray();
            foreach (var exclusion in manifest.Exclusions)
            {
                writer.WriteStartObject();
                writer.WriteString("subject", exclusion.Subject);
                writer.WriteString("rationale", exclusion.Rationale);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        });
        BoundedIO.EnsureLength(bytes.Length, ResourceLimits.SerializedArtifactBytes, "input manifest");
        return bytes;
    }

    public static InputManifest Parse(ReadOnlyMemory<byte> bytes)
    {
        using var document = StrictJson.Parse(bytes, ResourceLimits.SerializedArtifactBytes, "input manifest");
        var root = document.RootElement;
        ContractJson.RequireProperties(
            root,
            "schema_version",
            "state",
            "acquisition",
            "package",
            "source",
            "documentation",
            "package_sources",
            "owner_inputs",
            "components",
            "exclusions");
        var manifest = new InputManifest(
            ContractJson.Int32(root, "schema_version"),
            ContractJson.String(root, "state"),
            ContractJson.String(root, "acquisition"),
            ParsePackage(ContractJson.Object(root, "package")),
            ParseSource(ContractJson.Object(root, "source")),
            ContractJson.Array(root, "documentation").EnumerateArray().Select(ParseDocument).ToArray(),
            ContractJson.Array(root, "package_sources").EnumerateArray().Select(ParsePackageSource).ToArray(),
            ContractJson.Array(root, "owner_inputs").EnumerateArray().Select(ParseOwnerInput).ToArray(),
            ContractJson.Array(root, "components").EnumerateArray().Select(ParseComponent).ToArray(),
            ContractJson.Array(root, "exclusions").EnumerateArray().Select(ParseExclusion).ToArray());
        ContractJson.RequireCanonical(bytes.Span, Serialize(manifest), "input manifest");
        return manifest;
    }

    public static Sha256Digest Digest(ReadOnlySpan<byte> confirmedBytes) =>
        ContractJson.RawDigest(confirmedBytes);

    private static InputSource ParseCandidateSource(JsonElement element)
    {
        ContractJson.RequireProperties(
            element,
            "availability",
            "repository_uri",
            "commit",
            "mapping",
            "confidence");
        var availability = ContractJson.String(element, "availability");
        var repositoryUri = ContractJson.NullableString(element, "repository_uri");
        var commit = ContractJson.NullableString(element, "commit");
        var mapping = ContractJson.NullableString(element, "mapping");
        var confidence = ContractJson.NullableString(element, "confidence");
        var source = new InputSource(
            availability,
            repositoryUri is null ? null : Canonicalization.HttpsUri(repositoryUri, requirePath: true),
            commit is null ? null : Canonicalization.Commit(commit),
            mapping is null ? null : ContractJson.NormalizeText(mapping, "source mapping", 1024),
            confidence?.ToLowerInvariant());
        ValidateSource(source);
        return source;
    }

    private static void ValidateSource(InputSource source)
    {
        switch (source.Availability)
        {
            case "source-available":
                if (source.RepositoryUri is null || source.Commit is null ||
                    source.Mapping is null || source.Confidence is not ("low" or "medium" or "high") ||
                    Canonicalization.HttpsUri(source.RepositoryUri, requirePath: true) != source.RepositoryUri ||
                    Canonicalization.Commit(source.Commit) != source.Commit)
                {
                    throw new DeterministicValidationException(
                        "source-available requires canonical repository URI, exact commit, mapping, and confidence.");
                }

                _ = ContractJson.NormalizeText(source.Mapping, "source mapping", 1024);
                break;
            case "closed-source":
                if (source.RepositoryUri is not null || source.Commit is not null ||
                    source.Mapping is not null || source.Confidence is not null)
                {
                    throw new DeterministicValidationException(
                        "closed-source must not fabricate repository mapping fields.");
                }

                break;
            case "unresolved":
                if (source.Commit is not null || source.Mapping is not null || source.Confidence is not null ||
                    source.RepositoryUri is not null &&
                    Canonicalization.HttpsUri(source.RepositoryUri, requirePath: true) != source.RepositoryUri)
                {
                    throw new DeterministicValidationException(
                        "unresolved source may contain only a canonical attempted repository URI.");
                }

                break;
            default:
                throw new DeterministicValidationException($"Unknown source availability '{source.Availability}'.");
        }
    }

    private static InputDocument CreateDocument(string root, JsonElement element)
    {
        ContractJson.RequireProperties(element, "url", "content_path");
        var path = Canonicalization.RelativePath(
            ContractJson.String(element, "content_path"),
            "documentation content_path");
        return new InputDocument(
            Canonicalization.HttpsUri(ContractJson.String(element, "url"), requirePath: false),
            path,
            LocalDigest(root, path, "documentation content"));
    }

    private static InputPackageSource CreatePackageSource(string root, JsonElement element)
    {
        ContractJson.RequireProperties(element, "kind", "locator", "content_path");
        var kind = ContractJson.String(element, "kind");
        if (kind is not ("package-readme" or "package-metadata"))
        {
            throw new DeterministicValidationException($"Unknown package source kind '{kind}'.");
        }

        var path = Canonicalization.RelativePath(
            ContractJson.String(element, "content_path"),
            "package source content_path");
        return new InputPackageSource(
            kind,
            ContractJson.NormalizeText(ContractJson.String(element, "locator"), "package source locator", 512),
            path,
            LocalDigest(root, path, "package source content"));
    }

    private static OwnerInput CreateOwnerInput(string root, JsonElement element)
    {
        ContractJson.RequireProperties(element, "path", "provenance");
        var basename = Canonicalization.Basename(ContractJson.String(element, "path"), "owner input path");
        var provenance = ContractJson.String(element, "provenance");
        if (provenance is not ("owner-supplied-internal-evidence" or "owner-supplied-public-evidence"))
        {
            throw new DeterministicValidationException($"Unknown owner input provenance '{provenance}'.");
        }

        var path = SafePath.ResolveUnderRoot(root, basename, requireExisting: true, requireFile: true);
        BoundedIO.EnsureFileLength(path, ResourceLimits.SupplementalInputAggregateBytes, "owner input");
        return new OwnerInput(
            basename,
            provenance,
            ContractJson.RawDigest(BoundedIO.ReadAllBytes(
                path,
                ResourceLimits.SupplementalInputAggregateBytes,
                "owner input")),
            new FileInfo(path).Length);
    }

    private static InputComponent ParseCandidateComponent(JsonElement element)
    {
        ContractJson.RequireProperties(element, "id", "display_name", "render_modes");
        var modes = ContractJson.StringArray(element, "render_modes")
            .Select(Canonicalization.RenderMode)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (modes.Length == 0)
        {
            throw new DeterministicValidationException("A component requires at least one claimed render mode.");
        }

        return new InputComponent(
            Canonicalization.ComponentId(ContractJson.String(element, "id")),
            ContractJson.NormalizeText(ContractJson.String(element, "display_name"), "component display name", 256),
            modes);
    }

    private static InputExclusion ParseExclusion(JsonElement element)
    {
        ContractJson.RequireProperties(element, "subject", "rationale");
        return new InputExclusion(
            ContractJson.NormalizeText(ContractJson.String(element, "subject"), "exclusion subject", 256),
            ContractJson.NormalizeText(ContractJson.String(element, "rationale"), "exclusion rationale", 2048));
    }

    private static InputPackage ParsePackage(JsonElement element)
    {
        ContractJson.RequireProperties(element, "package_id", "version", "nupkg_sha256", "nupkg_path");
        return new InputPackage(
            ContractJson.String(element, "package_id"),
            ContractJson.String(element, "version"),
            ContractJson.Digest(ContractJson.Object(element, "nupkg_sha256")),
            ContractJson.String(element, "nupkg_path"));
    }

    private static InputSource ParseSource(JsonElement element)
    {
        ContractJson.RequireProperties(
            element,
            "availability",
            "repository_uri",
            "commit",
            "mapping",
            "confidence");
        return new InputSource(
            ContractJson.String(element, "availability"),
            ContractJson.NullableString(element, "repository_uri"),
            ContractJson.NullableString(element, "commit"),
            ContractJson.NullableString(element, "mapping"),
            ContractJson.NullableString(element, "confidence"));
    }

    private static InputDocument ParseDocument(JsonElement element)
    {
        ContractJson.RequireProperties(element, "url", "content_path", "content_sha256");
        return new InputDocument(
            ContractJson.String(element, "url"),
            ContractJson.String(element, "content_path"),
            ContractJson.Digest(ContractJson.Object(element, "content_sha256")));
    }

    private static InputPackageSource ParsePackageSource(JsonElement element)
    {
        ContractJson.RequireProperties(element, "kind", "locator", "content_path", "content_sha256");
        return new InputPackageSource(
            ContractJson.String(element, "kind"),
            ContractJson.String(element, "locator"),
            ContractJson.String(element, "content_path"),
            ContractJson.Digest(ContractJson.Object(element, "content_sha256")));
    }

    private static OwnerInput ParseOwnerInput(JsonElement element)
    {
        ContractJson.RequireProperties(element, "basename", "provenance", "content_sha256", "size");
        return new OwnerInput(
            ContractJson.String(element, "basename"),
            ContractJson.String(element, "provenance"),
            ContractJson.Digest(ContractJson.Object(element, "content_sha256")),
            ContractJson.Int64(element, "size"));
    }

    private static InputComponent ParseComponent(JsonElement element)
    {
        ContractJson.RequireProperties(element, "id", "display_name", "render_modes");
        return new InputComponent(
            ContractJson.String(element, "id"),
            ContractJson.String(element, "display_name"),
            ContractJson.StringArray(element, "render_modes"));
    }

    private static string GetRelativePath(string root, string path, string resource)
    {
        var fullRoot = Path.GetFullPath(root);
        var fullPath = Path.GetFullPath(path);
        var relative = Path.GetRelativePath(fullRoot, fullPath);
        var canonical = Canonicalization.RelativePath(relative, $"{resource} path");
        _ = SafePath.ResolveUnderRoot(fullRoot, canonical, requireExisting: true, requireFile: true);
        return canonical;
    }

    private static Sha256Digest LocalDigest(string root, string relativePath, string resource)
    {
        var path = SafePath.ResolveUnderRoot(root, relativePath, requireExisting: true, requireFile: true);
        return ContractJson.RawDigest(BoundedIO.ReadAllBytes(
            path,
            ResourceLimits.SupplementalInputAggregateBytes,
            resource));
    }

    private static void ValidateLocalDigest(
        string root,
        string relativePath,
        Sha256Digest expected,
        string resource)
    {
        EvidenceIdentity.ValidateDigest(expected, $"{resource}_sha256");
        if (LocalDigest(root, relativePath, resource) != expected)
        {
            throw new DeterministicValidationException($"{resource} has a stale local digest.");
        }
    }

    private static void ValidateOwnerCeilings(IReadOnlyList<OwnerInput> ownerInputs)
    {
        if (ownerInputs.Count > ResourceLimits.SupplementalInputCount)
        {
            throw new DeterministicValidationException(
                $"Owner inputs exceed the {ResourceLimits.SupplementalInputCount}-file ceiling.");
        }

        long total = 0;
        foreach (var owner in ownerInputs)
        {
            total = checked(total + owner.Size);
            BoundedIO.EnsureLength(
                total,
                ResourceLimits.SupplementalInputAggregateBytes,
                "owner input aggregate");
        }
    }

    private static T[] RequireUnique<T>(T[] values, Func<T, string> key, string name)
    {
        if (values.Select(key).Distinct(StringComparer.Ordinal).Count() != values.Length)
        {
            throw new DeterministicValidationException($"{name} values must be unique.");
        }

        return values;
    }

    private static void ValidateUniqueAndSorted<T>(
        IReadOnlyList<T> values,
        Func<T, string> key,
        string name)
    {
        var keys = values.Select(key).ToArray();
        if (keys.Distinct(StringComparer.Ordinal).Count() != keys.Length ||
            !keys.SequenceEqual(keys.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new DeterministicValidationException($"{name} must be unique and canonically sorted.");
        }
    }

    private static void WriteNullable(Utf8JsonWriter writer, string property, string? value)
    {
        if (value is null)
        {
            writer.WriteNull(property);
        }
        else
        {
            writer.WriteString(property, value);
        }
    }
}
