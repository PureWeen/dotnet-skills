using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace BlazorPackageResolver;

internal sealed record InventoryChecksum(string Algorithm, string Value);
internal sealed record InventoryComponent(string SpdxId, string Id, string Version, string Purl,
    string Ecosystem = "nuget", InventoryChecksum[]? Checksums = null)
{
    public string Key => Id + "/" + Version;
    internal string QualifiedKey => Ecosystem + ":" + Key;
}
internal sealed record InventoryEdge(string From, string To);
internal sealed record ReleaseInventory(string Profile, string RootId, string RootVersion,
    string RootSha256, string SbomSha256, string DocumentNamespace, string ProductSpdxId,
    string RootSpdxId, InventoryComponent[] Dependencies, InventoryEdge[] Relationships,
    string[] Diagnostics);
internal sealed record InventoryAdmission(string Disposition, string Code, string Detail,
    string StructuralAdmission, string DesignationAdmission, ReleaseInventory? Inventory);

internal static class Spdx22InventoryAdmission
{
    internal const int SbomLimit = 1024 * 1024;
    internal const string Profile = "spdx22-release-nuget-npm-union/1.0.0";
    internal const int ComponentLimit = 128;
    // Keep the entire historical NuGet id/version key order, including prefix-related IDs.
    internal static InventoryComponent[] Ordered(IEnumerable<InventoryComponent> values) =>
        values.OrderBy(c => c.Ecosystem == "nuget" ? 0 : 1)
            .ThenBy(c => c.Key, StringComparer.Ordinal).ToArray();
    internal const string DesignationBasis = "caller-authoritative-release-inventory/1";
    internal const string LegacyScope =
        "The supplied LP-03 assessment uses legacy schema 1; re-admit a schema-2 release-wide SBOM packet.";
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private sealed class Failure(string kind, string code, string detail) : Exception(detail)
    {
        internal string Kind => kind;
        internal string Code => code;
    }

    internal static InventoryAdmission Admit(IReadOnlyDictionary<string, CheckedInput> inputs)
    {
        var structural = "not-tested";
        var designation = "not-tested";
        try
        {
            Check(inputs.TryGetValue("package", out var package), "missing", "missing-package", "The exact root package is missing.");
            Check(inputs.TryGetValue("assessment", out var assessment), "missing", "scope-missing",
                "The exact root and release-wide SBOM assessment binding is missing.");
            using var scopeDoc = Parse(assessment!.Content, 65536, 8);
            var scope = scopeDoc.RootElement;
            if (scope.TryGetProperty("schema_version", out var schema) && schema.TryGetInt32(out var number) && number == 1)
                throw new Failure("invalid", "input-invalid", LegacyScope);
            Fields(scope, "schema_version root inventory_scope sbom_sha256 designation");
            Check(scope.GetProperty("schema_version").TryGetInt32(out number) && number == 2,
                "invalid", "input-invalid", "Unsupported assessment schema.");
            var root = scope.GetProperty("root");
            Identity(root);
            Check(package!.Content.Length is > 0 and <= 8 * 1024 * 1024, "invalid", "input-invalid", "Root archive byte limit.");
            var actual = Lp03PackageEvidence.Read(package.Content, null);
            Check(actual is not null, "invalid", "input-invalid", "Root archive is outside the safe package profile.");
            Check(Text(root, "id") == actual!.Id && Text(root, "version") == actual.Version &&
                Text(root, "sha256") == package.Identity.Sha256, "conflict", "binding-conflict", "Assessment root does not match exact package bytes.");
            Check(inputs.TryGetValue("sbom", out var sbom), "missing", "evidence-missing",
                "The retained raw release SBOM is missing.");
            Check(scope.GetProperty("sbom_sha256").ValueKind == JsonValueKind.String &&
                Text(scope, "sbom_sha256") == sbom!.Identity.Sha256, "conflict", "binding-conflict", "Raw SBOM digest does not match the assessment.");
            using var document = Parse(sbom!.Content, SbomLimit, 16);
            var inventory = Structure(document.RootElement, actual.Id, actual.Version,
                package.Identity.Sha256, sbom.Identity.Sha256, package.Content);
            structural = "admitted";
            designation = "missing";
            var designated = scope.GetProperty("designation");
            Check(designated.ValueKind != JsonValueKind.Null, "unsupported", "closure-unresolved",
                "Caller authoritative release-wide inventory designation is missing.");
            Fields(designated, "basis scope root sbom_sha256");
            designation = "unsupported";
            Check(Text(scope, "inventory_scope") == "release-wide" &&
                Text(designated, "basis") == DesignationBasis &&
                Text(designated, "scope") == "release-wide", "unsupported", "closure-unresolved",
                "The designation is unknown, sampled, partial or not release-wide.");
            Identity(designated.GetProperty("root"));
            designation = "conflict";
            Check(new[] { "id", "version", "sha256" }.All(key =>
                Text(designated.GetProperty("root"), key) == Text(root, key)) &&
                Text(designated, "sbom_sha256") == sbom.Identity.Sha256,
                "conflict", "binding-conflict", "Caller designation does not bind this exact root and raw SBOM.");
            Check(JsonSerializer.SerializeToUtf8Bytes(inventory).Length <= 240 * 1024,
                "invalid", "input-invalid", "Inventory exceeds the bounded handoff output profile.");
            return new("admitted", "inventory-admitted",
                "Structure admitted; caller designation supplies authoritative release-wide scope, not independent publication or completeness proof.",
                structural, "designated", inventory);
        }
        catch (Failure error)
        {
            return new(error.Kind, error.Code, error.Message, structural, designation, null);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or
            DecoderFallbackException or InvalidDataException or ArgumentException or FormatException or OverflowException)
        {
            return new("invalid", "input-invalid", "Malformed, ambiguous or out-of-bounds inventory evidence.",
                structural, designation, null);
        }
    }

    private static ReleaseInventory Structure(JsonElement doc, string rootId, string rootVersion,
        string packageSha, string sbomSha, ReadOnlyMemory<byte> package)
    {
        Check(doc.ValueKind == JsonValueKind.Object, "invalid", "input-invalid", "SBOM must be a JSON object.");
        Check(doc.TryGetProperty("spdxVersion", out var version) && version.ValueKind == JsonValueKind.String &&
            version.GetString() == "SPDX-2.2", "unsupported", "closure-unresolved", "Only the retained SPDX-2.2 JSON profile is supported.");
        Fields(doc, "externalDocumentRefs spdxVersion dataLicense SPDXID name documentNamespace creationInfo documentDescribes packages relationships files");
        Check(Text(doc, "SPDXID") == "SPDXRef-DOCUMENT" && Text(doc, "dataLicense") == "CC0-1.0",
            "unsupported", "closure-unresolved", "Unsupported SPDX document identity/data license.");
        var ns = Text(doc, "documentNamespace", 2048);
        Check(Uri.TryCreate(ns, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" &&
            uri.Host.Length > 0 && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
            uri.IsDefaultPort && !ns.Any(char.IsWhiteSpace),
            "unsupported", "closure-unresolved", "Unsupported document namespace.");
        var creation = doc.GetProperty("creationInfo");
        Fields(creation, "created creators");
        Text(creation, "created");
        var creators = Array(creation.GetProperty("creators"), 16);
        Check(creators.Length > 0, "unsupported", "closure-unresolved", "Missing creation information.");
        foreach (var creator in creators) Scalar(creator, 1024);
        Text(doc, "name", 1024);
        Check(Array(doc.GetProperty("externalDocumentRefs"), 0).Length == 0,
            "unsupported", "closure-unresolved", "External SPDX documents are unsupported.");
        var described = Array(doc.GetProperty("documentDescribes"), 1);
        Check(described.Length == 1, "unsupported", "closure-unresolved", "Exactly one release product must be described.");
        var productId = ElementId(Scalar(described[0], 256));
        var packages = Array(doc.GetProperty("packages"), ComponentLimit + 2);
        var files = Array(doc.GetProperty("files"), 64);
        var elements = new HashSet<string>(StringComparer.Ordinal) { "SPDXRef-DOCUMENT" };
        var fileMap = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var file in files)
        {
            Fields(file, "fileName SPDXID checksums licenseConcluded licenseInfoInFiles copyrightText");
            var id = ElementId(Text(file, "SPDXID"));
            Check(elements.Add(id) && fileMap.TryAdd(id, file), "unsupported", "closure-unresolved", "Duplicate SPDX element.");
            Text(file, "fileName", 1024);
            Text(file, "licenseConcluded", 4096);
            Text(file, "copyrightText", 4096);
            foreach (var license in Array(file.GetProperty("licenseInfoInFiles"), 64)) Scalar(license, 4096);
            foreach (var checksum in Array(file.GetProperty("checksums"), 8))
            {
                Fields(checksum, "algorithm checksumValue");
                var algorithm = Text(checksum, "algorithm");
                var value = Text(checksum, "checksumValue");
                Check(algorithm is "SHA256" or "SHA1" && Regex.IsMatch(value,
                    algorithm == "SHA256" ? @"\A[a-f0-9]{64}\z" : @"\A[a-f0-9]{40}\z", RegexOptions.CultureInvariant),
                    "unsupported", "closure-unresolved", "Unsupported file checksum.");
            }
        }
        var nodes = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        var components = new Dictionary<string, InventoryComponent>(StringComparer.Ordinal);
        JsonElement? product = null;
        var productAsRoot = false;
        foreach (var item in packages)
        {
            Fields(item, "name SPDXID downloadLocation filesAnalyzed licenseConcluded licenseDeclared copyrightText versionInfo externalRefs supplier",
                "hasFiles packageVerificationCode licenseInfoFromFiles checksums");
            var id = ElementId(Text(item, "SPDXID"));
            Check(elements.Add(id) && nodes.TryAdd(id, item), "unsupported", "closure-unresolved", "Duplicate SPDX package ID.");
            Check(item.GetProperty("filesAnalyzed").ValueKind is JsonValueKind.True or JsonValueKind.False,
                "invalid", "input-invalid", "filesAnalyzed must be boolean.");
            foreach (var field in new[] { "downloadLocation", "licenseConcluded", "licenseDeclared", "copyrightText", "supplier" })
                Text(item, field, 4096);
            if (item.TryGetProperty("licenseInfoFromFiles", out var fromFiles))
                foreach (var license in Array(fromFiles, 64)) Scalar(license, 4096);
            if (item.TryGetProperty("packageVerificationCode", out var verification))
            {
                Fields(verification, "packageVerificationCodeValue", "packageVerificationCodeExcludedFiles");
                Check(Regex.IsMatch(Text(verification, "packageVerificationCodeValue"), @"\A[a-f0-9]{40}\z",
                    RegexOptions.CultureInvariant), "unsupported", "closure-unresolved", "Unsupported verification code.");
                if (verification.TryGetProperty("packageVerificationCodeExcludedFiles", out var excluded))
                    foreach (var file in Array(excluded, 64)) Scalar(file, 1024);
            }
            var refs = Array(item.GetProperty("externalRefs"), 8);
            Check(refs.Length == 1, "unsupported", "closure-unresolved", "One unambiguous package purl is required.");
            Fields(refs[0], "referenceCategory referenceType referenceLocator");
            Check(Text(refs[0], "referenceCategory") == "PACKAGE-MANAGER" && Text(refs[0], "referenceType") == "purl",
                "unsupported", "closure-unresolved", "Unsupported package reference.");
            var purl = Text(refs[0], "referenceLocator", 1024);
            var name = Text(item, "name").ToLowerInvariant();
            var v = Text(item, "versionInfo");
            if (id == productId)
            {
                var match = Regex.Match(purl, @"\Apkg:swid/([A-Za-z0-9._%-]+)/(github\.com|spdx\.org)/([A-Za-z0-9.-]+)@(v?[0-9.]+)\?tag_id=([a-fA-F0-9-]{36})\z", RegexOptions.CultureInvariant);
                Check(match.Success, "unsupported", "closure-unresolved", "Unsupported described product representation.");
                var supplier = Uri.UnescapeDataString(match.Groups[1].Value);
                Check(supplier.All(c => c is >= ' ' and <= '~' && c is not ('/' or '\\' or '%' or ':' or '?' or '#')) &&
                    Guid.TryParseExact(match.Groups[5].Value, "D", out _),
                    "unsupported", "closure-unresolved", "Unsupported SWID supplier or tag identity.");
                Check(name == rootId && (v.StartsWith('v') ? v[1..] : v) == rootVersion &&
                    match.Groups[3].Value.ToLowerInvariant() == rootId &&
                    (match.Groups[4].Value.StartsWith('v') ? match.Groups[4].Value[1..] : match.Groups[4].Value) == rootVersion,
                    "conflict", "binding-conflict", "Described product identifies another root release.");
                productAsRoot = match.Groups[2].Value == "spdx.org";
                product = item;
            }
            else
            {
                var match = Regex.Match(purl, @"\Apkg:nuget/([A-Za-z0-9.-]+)@([0-9.]+)\z", RegexOptions.CultureInvariant);
                string ecosystem;
                if (purl.StartsWith("pkg:npm/", StringComparison.Ordinal))
                {
                    Check(NpmPackageIdentity.TryParsePurl(purl, out var npmName, out var npmVersion),
                        "unsupported", "closure-unresolved", "Unsupported exact npm identity.");
                    Check(Text(item, "name") == npmName && v == npmVersion,
                        "conflict", "binding-conflict", "npm purl/name/version disagree.");
                    name = npmName;
                    ecosystem = "npm";
                }
                else
                {
                    Check(match.Success && NuGetPackageIdentity.ValidId(name) && NuGetPackageIdentity.ValidVersion(v),
                        "unsupported", "closure-unresolved", "Unsupported exact NuGet identity: " + name);
                    Check(match.Groups[1].Value.ToLowerInvariant() == name && match.Groups[2].Value == v,
                        "conflict", "binding-conflict", "NuGet purl/name/version disagree.");
                    ecosystem = "nuget";
                }
                var checksums = new List<InventoryChecksum>();
                if (item.TryGetProperty("checksums", out var declaredChecksums))
                    foreach (var checksum in Array(declaredChecksums, 8))
                    {
                        Fields(checksum, "algorithm checksumValue");
                        var algorithm = Text(checksum, "algorithm");
                        var value = Text(checksum, "checksumValue");
                        var length = algorithm switch { "SHA256" => 64, "SHA512" => 128, "SHA1" => 40, _ => 0 };
                        Check(length > 0 && value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') &&
                            checksums.All(c => c.Algorithm != algorithm), "unsupported", "closure-unresolved", "Unsupported/duplicate archive checksum.");
                        checksums.Add(new(algorithm, value));
                    }
                var component = new InventoryComponent(id, name, v, purl, ecosystem, checksums.ToArray());
                Check(components.TryAdd(component.QualifiedKey, component), "unsupported", "closure-unresolved", "Duplicate canonical component: " + component.QualifiedKey);
            }
            if (item.TryGetProperty("hasFiles", out var hasFiles))
                foreach (var reference in Array(hasFiles, 64))
                    Check(fileMap.ContainsKey(Scalar(reference, 256)), "unsupported", "closure-unresolved", "Unresolved hasFiles reference.");
        }
        Check(!components.Values.Any(c => c.Ecosystem == "nuget" && c.Id == rootId && c.Version != rootVersion),
            "conflict", "binding-conflict", "Wrong or ambiguous NuGet root version.");
        var rootKey = "nuget:" + rootId + "/" + rootVersion;
        Check(product is not null, "unsupported", "closure-unresolved", "Missing described product.");
        InventoryComponent root;
        if (productAsRoot)
        {
            Check(!components.ContainsKey(rootKey), "conflict", "binding-conflict", "Product-as-root conflicts with a separate NuGet root.");
            Check(product!.Value.TryGetProperty("hasFiles", out var rootFiles) &&
                rootFiles.EnumerateArray().Count(reference => fileMap.TryGetValue(reference.GetString()!, out var file) &&
                    string.Equals(Text(file, "fileName", 1024).StartsWith("./", StringComparison.Ordinal) ?
                        Text(file, "fileName", 1024)[2..] : Text(file, "fileName", 1024), rootId + "." + rootVersion + ".nupkg",
                        StringComparison.OrdinalIgnoreCase)) == 1,
                "unsupported", "closure-unresolved", "Product-as-root requires one exact root archive file association.");
            root = new(productId, rootId, rootVersion, "");
        }
        else
        {
            Check(components.TryGetValue(rootKey, out _), "unsupported", "closure-unresolved", "Missing described product or exact NuGet root.");
            root = components[rootKey];
        }
        var edges = new List<InventoryEdge>();
        var unique = new HashSet<string>(StringComparer.Ordinal);
        var describes = 0;
        foreach (var relation in Array(doc.GetProperty("relationships"), 512))
        {
            Fields(relation, "relationshipType relatedSpdxElement spdxElementId");
            var kind = Text(relation, "relationshipType");
            var from = Text(relation, "spdxElementId");
            var to = Text(relation, "relatedSpdxElement");
            Check(unique.Add(kind + ":" + from + ":" + to), "unsupported", "closure-unresolved", "Duplicate relationship.");
            if (kind == "DESCRIBES")
            {
                Check(from == "SPDXRef-DOCUMENT" && to == productId, "unsupported", "closure-unresolved", "Conflicting DESCRIBES relationship.");
                describes++;
            }
            else
            {
                Check(kind == "DEPENDS_ON" && from != to && nodes.ContainsKey(from) && nodes.ContainsKey(to),
                    "unsupported", "closure-unresolved", "Unsupported or unresolved dependency relationship.");
                edges.Add(new(from, to));
            }
        }
        Check(describes == 1 && (productAsRoot || edges.Contains(new(productId, root.SpdxId))),
            "unsupported", "closure-unresolved", "Missing product-to-root association.");
        var reached = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>([productId]);
        while (pending.TryPop(out var id))
            if (reached.Add(id))
                foreach (var edge in edges.Where(e => e.From == id)) pending.Push(edge.To);
        Check(reached.SetEquals(nodes.Keys), "unsupported", "closure-unresolved", "Orphan or incomplete package inventory.");
        if (!productAsRoot) components.Remove(rootKey);
        Check(components.Count <= ComponentLimit, "unsupported", "closure-unresolved", "Dependency component cap.");
        CheckRootDependencies(package, components.Values.Where(c => c.Ecosystem == "nuget").Select(c => c.Id).ToHashSet(StringComparer.Ordinal));
        var diagnostics = new List<string>();
        foreach (var file in files)
        {
            var fileName = Text(file, "fileName", 1024);
            var releaseFile = fileName.StartsWith("./", StringComparison.Ordinal) ? fileName[2..] : fileName;
            if (!string.Equals(releaseFile, rootId + "." + rootVersion + ".nupkg", StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var checksum in file.GetProperty("checksums").EnumerateArray())
                if (Text(checksum, "algorithm") == "SHA256" && Text(checksum, "checksumValue") != packageSha)
                    diagnostics.Add("Published file checksum differs from assessed root bytes: " + Text(file, "fileName", 1024) +
                        "; published " + Text(checksum, "checksumValue") + "; assessed " + packageSha + ". PI-10 is separately assessed.");
        }
        return new(Profile, rootId, rootVersion, packageSha, sbomSha, ns, productId, root.SpdxId,
            Ordered(components.Values),
            edges.OrderBy(e => e.From, StringComparer.Ordinal).ThenBy(e => e.To, StringComparer.Ordinal).ToArray(), diagnostics.ToArray());
    }

    private static void CheckRootDependencies(ReadOnlyMemory<byte> package, HashSet<string> ids)
    {
        var metadata = NuGetNuspecReader.Read(package).Metadata!;
        var ns = metadata.Name.Namespace;
        var sets = metadata.Elements().Where(e => e.Name.LocalName == "dependencies").ToArray();
        Check(sets.Length <= 1 && sets.All(e => e.Name.Namespace == ns),
            "unsupported", "closure-unresolved", "Ambiguous root dependency container.");
        Check(!metadata.Descendants().Any(e => e.Name.LocalName is "frameworkReference" or "frameworkReferences"),
            "unsupported", "closure-unresolved", "Unsupported root platform dependency declaration.");
        var count = 0;
        foreach (var set in sets)
        {
            Check(!set.HasAttributes && string.IsNullOrWhiteSpace(string.Concat(set.Nodes().OfType<XText>().Select(t => t.Value))),
                "unsupported", "closure-unresolved", "Ambiguous root dependency declarations.");
            var grouped = set.Elements().Any(e => e.Name.LocalName == "group");
            var groups = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in set.Elements())
            {
                Check(item.Name.Namespace == ns && item.Name.LocalName == (grouped ? "group" : "dependency"),
                    "unsupported", "closure-unresolved", "Malformed root dependency group.");
                var dependencies = grouped ? item.Elements().ToArray() : [item];
                if (grouped)
                {
                    Check(item.Attributes().All(a => a.Name == "targetFramework") &&
                        groups.Add((string?)item.Attribute("targetFramework") ?? "") &&
                        string.IsNullOrWhiteSpace(string.Concat(item.Nodes().OfType<XText>().Select(t => t.Value))),
                        "unsupported", "closure-unresolved", "Ambiguous root dependency group.");
                }
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var dependency in dependencies)
                {
                    var declared = (string?)dependency.Attribute("id");
                    var id = declared?.ToLowerInvariant();
                    Check(++count <= 1024 && dependency.Name == ns + "dependency" && !dependency.HasElements &&
                        string.IsNullOrWhiteSpace(dependency.Value) && id is not null &&
                        NuGetPackageIdentity.ValidId(id) &&
                        dependency.Attributes().All(a => a.Name.NamespaceName.Length == 0 &&
                            a.Name.LocalName is "id" or "version" or "include" or "exclude") &&
                        (grouped ? seen : groups).Add(id), "unsupported", "closure-unresolved", "Malformed or ambiguous root dependency identity.");
                    foreach (var attribute in dependency.Attributes().Where(a => a.Name.LocalName != "id"))
                    {
                        var supported = attribute.Name.LocalName == "version"
                            ? SupportedDependencyVersion(attribute.Value)
                            : SupportedDependencyAssets(attribute.Value);
                        Check(supported, "unsupported", "closure-unresolved",
                            "Unsupported or malformed root dependency " + attribute.Name.LocalName + " declaration.");
                    }
                    Check(ids.Contains(id!), "unsupported", "closure-unresolved", "Known root direct dependency omitted: " + id);
                }
            }
        }
    }

    private static bool SupportedDependencyVersion(string value)
    {
        // Same bounded literals as helper discovery; this checks syntax, never a selected version.
        if (value.Length > 19) return false;
        var literal = value.Length >= 2 && value[0] == '[' && value[^1] == ']'
            ? value[1..^1] : value;
        return NuGetPackageIdentity.ValidVersion(literal);
    }

    private static bool SupportedDependencyAssets(string value)
    {
        if (value.Length is 0 or > 256) return false;
        var flags = value.Split(',', StringSplitOptions.TrimEntries);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var flag in flags)
        {
            if (!seen.Add(flag) || flag.ToLowerInvariant() is not
                ("runtime" or "compile" or "build" or "native" or "contentfiles" or
                 "analyzers" or "buildtransitive" or "all" or "none")) return false;
        }
        return flags.Length == 1 || (!seen.Contains("all") && !seen.Contains("none"));
    }

    private static JsonDocument Parse(ReadOnlyMemory<byte> bytes, int limit, int depth)
    {
        Check(bytes.Length is > 0 && bytes.Length <= limit && !bytes.Span.StartsWith(new byte[] { 239, 187, 191 }),
            "invalid", "input-invalid", "JSON byte limit/BOM.");
        var doc = JsonDocument.Parse(Utf8.GetString(bytes.Span), new() { MaxDepth = depth });
        try
        {
            var count = 0;
            void Visit(JsonElement value)
            {
                Check(++count <= 32768, "invalid", "input-invalid", "JSON value cap.");
                if (value.ValueKind == JsonValueKind.Object)
                {
                    var names = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var property in value.EnumerateObject())
                    {
                        Check(++count <= 32768 && names.Add(property.Name) && Utf8.GetByteCount(property.Name) <= 16384,
                            "invalid", "input-invalid", "Duplicate/oversized JSON property.");
                        Visit(property.Value);
                    }
                }
                else if (value.ValueKind == JsonValueKind.Array)
                    foreach (var child in value.EnumerateArray()) Visit(child);
                else if (value.ValueKind == JsonValueKind.String)
                    Check(Utf8.GetByteCount(value.GetString()!) <= 16384, "invalid", "input-invalid", "JSON string cap.");
            }
            Visit(doc.RootElement);
            return doc;
        }
        catch { doc.Dispose(); throw; }
    }
    private static void Identity(JsonElement root)
    {
        Fields(root, "id version sha256");
        Check(NuGetPackageIdentity.ValidId(Text(root, "id")) && NuGetPackageIdentity.ValidVersion(Text(root, "version")) &&
            Regex.IsMatch(Text(root, "sha256"), @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant),
            "invalid", "input-invalid", "Unsupported exact identity.");
    }
    private static JsonElement[] Array(JsonElement value, int maximum)
    {
        Check(value.ValueKind == JsonValueKind.Array && value.GetArrayLength() <= maximum,
            "unsupported", "closure-unresolved", "Unsupported array or inventory cap.");
        return value.EnumerateArray().ToArray();
    }
    private static string Text(JsonElement parent, string key, int maximum = 256) => Scalar(parent.GetProperty(key), maximum);
    private static string ElementId(string value)
    {
        Check(Regex.IsMatch(value, @"\ASPDXRef-[A-Za-z0-9.-]+\z", RegexOptions.CultureInvariant) &&
            value != "SPDXRef-DOCUMENT", "unsupported", "closure-unresolved", "Unsupported SPDX element identity.");
        return value;
    }
    private static string Scalar(JsonElement value, int maximum)
    {
        Check(value.ValueKind == JsonValueKind.String, "invalid", "input-invalid", "String field required.");
        var text = value.GetString()!;
        Check(text.Length is > 0 && text.Length <= maximum && text.All(c => c is >= ' ' and <= '~'),
            "unsupported", "closure-unresolved", "Unsupported reference text.");
        return text;
    }
    private static void Fields(JsonElement value, string required, string optional = "")
    {
        Check(value.ValueKind == JsonValueKind.Object, "invalid", "input-invalid", "Object required.");
        var must = required.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var allowed = must.Concat(optional.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToHashSet(StringComparer.Ordinal);
        Check(must.All(k => value.TryGetProperty(k, out _)) && value.EnumerateObject().All(p => allowed.Contains(p.Name)),
            "invalid", "input-invalid", "Missing or unknown profile fields.");
    }
    private static void Check(bool condition, string kind, string code, string detail)
    {
        if (!condition) throw new Failure(kind, code, detail);
    }
}
