using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BlazorPackageResolver;

public sealed record BundledWebAsset(string Path, long Length, string Sha256);
public sealed record BundledWebAssetsEvidence(string Profile, IReadOnlyList<BundledWebAsset> Assets,
    IReadOnlyList<string> UnsupportedCandidates, string InventorySha256)
{
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("profile", Profile);
        writer.WritePropertyName("assets");
        writer.WriteStartArray();
        foreach (var asset in Assets)
        {
            writer.WriteStartObject();
            writer.WriteString("path", asset.Path);
            writer.WriteNumber("length", asset.Length);
            writer.WriteString("sha256", asset.Sha256);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WritePropertyName("unsupported_candidates");
        writer.WriteStartArray();
        foreach (var path in UnsupportedCandidates) writer.WriteStringValue(path);
        writer.WriteEndArray();
        writer.WriteString("inventory_sha256", InventorySha256);
        writer.WriteEndObject();
    }
}

internal static class Lp04PackageEvidence
{
    internal const string Profile = "bundled-web-assets/1";
    internal static readonly string[] Suffixes = [".js", ".mjs", ".cjs", ".css", ".map"];
    private const long ExpandedLimit = 64 * 1024 * 1024;
    internal static string AsciiLower(string value) =>
        string.Concat(value.Select(ch => ch is >= 'A' and <= 'Z' ? (char)(ch + 32) : ch));
    internal static string? Suffix(string path) =>
        Suffixes.FirstOrDefault(suffix => AsciiLower(path).EndsWith(suffix, StringComparison.Ordinal));
    internal static bool Supported(string path)
    {
        var segments = AsciiLower(path).Split('/');
        return segments.Length >= 2 && segments[0] is "staticwebassets" or "wwwroot" ||
            segments.Length >= 5 && segments[0] == "contentfiles" && segments[3] == "wwwroot";
    }
    internal static bool Unsupported(string path)
    {
        var lower = AsciiLower(path);
        return Suffix(path) is not null && !Supported(path) ||
            (lower.EndsWith(".gz", StringComparison.Ordinal) || lower.EndsWith(".br", StringComparison.Ordinal)) &&
                Suffix(path[..^3]) is not null;
    }

    internal static string InventoryDigest(IEnumerable<BundledWebAsset> assets)
    {
        var canonical = new StringBuilder(Profile + "\n");
        foreach (var asset in assets)
            canonical.Append(asset.Path).Append('\t')
                .Append(asset.Length.ToString(CultureInfo.InvariantCulture)).Append('\t')
                .Append(asset.Sha256).Append('\n');
        return Catalog.Digest(Encoding.UTF8.GetBytes(canonical.ToString()));
    }

    internal static string Summary(BundledWebAssetsEvidence inventory)
    {
        var counts = string.Join(", ", Suffixes.Select(suffix =>
            suffix + "=" + inventory.Assets.Count(asset => Suffix(asset.Path) == suffix).ToString(CultureInfo.InvariantCulture)));
        return $"{inventory.Profile}: {inventory.Assets.Count.ToString(CultureInfo.InvariantCulture)} assets ({counts}), " +
            $"{inventory.Assets.Sum(asset => asset.Length).ToString(CultureInfo.InvariantCulture)} bytes; " +
            $"inventory SHA-256 {inventory.InventorySha256}.";
    }

    internal static BundledWebAssetsEvidence? Read(ReadOnlyMemory<byte> content, Action? beforeStreaming = null)
    {
        if (content.Length == 0 || content.Length > 8 * 1024 * 1024 ||
            !NuGetNuspecReader.HasBoundedDirectory(content.Span, out var count)) return null;
        try
        {
            using var stream = new MemoryStream(content.ToArray(), writable: false);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, false, Lp01ArchiveIntegrity.Cp437);
            var entries = archive.Entries;
            // Preflight every declared expanded length and asset count before any entry is streamed.
            if (entries.Count != count || entries.Sum(entry => entry.Length) > ExpandedLimit ||
                entries.Count(entry => !entry.FullName.EndsWith('/') &&
                    Suffix(entry.FullName) is not null && Supported(entry.FullName)) > 512 ||
                entries.Any(entry => entry.FullName.EndsWith('/') && entry.Length != 0 ||
                    ((entry.ExternalAttributes >> 16) & 0xf000) is 0xa000 ||
                    entry.FullName != "[Content_Types].xml" &&
                    !Lp04NoticeCoverageResolver.SafePath(entry.FullName.EndsWith('/') ? entry.FullName[..^1] : entry.FullName)))
                return null;
            beforeStreaming?.Invoke();
            if (!Lp01ArchiveIntegrity.Validate(content.Span, entries)) return null;
            var nuspecs = entries.Where(entry => !entry.FullName.Contains('/') &&
                entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (nuspecs.Length != 1 || nuspecs[0].Length > 1024 * 1024) return null;
            using (var source = nuspecs[0].Open())
            using (var xml = new MemoryStream())
            {
                source.CopyTo(xml);
                if (!Lp01LicensePolicyResolver.SupportedXmlEncoding(xml.ToArray())) return null;
            }
            if (NuGetNuspecReader.Read(content).Metadata is not { } metadata) return null;
            string? Single(string name)
            {
                var fields = metadata.Elements().Where(element => element.Name.LocalName == name).ToArray();
                return fields.Length == 1 && fields[0].Name.Namespace == metadata.Name.Namespace &&
                    !fields[0].HasElements ? fields[0].Value : null;
            }
            var id = Single("id");
            var version = Single("version");
            if (id is null || id.Any(ch => ch > 127) || version is null ||
                !Lp03DependencyLicensesResolver.ValidId(id.ToLowerInvariant()) ||
                !Lp03DependencyLicensesResolver.ValidVersion(version)) return null;
            var assets = new List<BundledWebAsset>();
            foreach (var entry in entries.Where(entry => !entry.FullName.EndsWith('/') &&
                         Suffix(entry.FullName) is not null && Supported(entry.FullName))
                         .OrderBy(entry => entry.FullName, StringComparer.Ordinal))
            {
                using var source = entry.Open();
                var digest = Convert.ToHexStringLower(SHA256.HashData(source));
                assets.Add(new(entry.FullName, entry.Length, digest));
            }
            var unsupported = entries.Where(entry => !entry.FullName.EndsWith('/') && Unsupported(entry.FullName))
                .Select(entry => entry.FullName).Order(StringComparer.Ordinal).ToArray();
            return new(Profile, assets, unsupported, InventoryDigest(assets));
        }
        catch (Exception error) when (error is InvalidDataException or IOException or
            NotSupportedException or DecoderFallbackException or System.Xml.XmlException or ArgumentException or OverflowException)
        {
            return null;
        }
    }
}
