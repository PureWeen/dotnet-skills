using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BlazorPackageResolver;

internal sealed record NpmPackage(string Id, string Version, string? License);

internal static class NpmPackageEvidence
{
    internal const int ArchiveLimit = 8 * 1024 * 1024;
    internal const int ExpandedLimit = 64 * 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static Dictionary<string, string> ReadDesignation(ReadOnlyMemory<byte> bytes,
        ReleaseInventory inventory)
    {
        using var doc = Parse(bytes, 65536, 8);
        var root = doc.RootElement;
        Fields(root, "schema_version", "basis", "root_sha256", "sbom_sha256", "archives");
        if (!root.GetProperty("schema_version").TryGetInt32(out var schema) || schema != 1 ||
            root.GetProperty("basis").GetString() != "caller-designated-exact-npm-archives/1" ||
            root.GetProperty("root_sha256").GetString() != inventory.RootSha256 ||
            root.GetProperty("sbom_sha256").GetString() != inventory.SbomSha256)
            throw new InvalidDataException("npm archive designation does not bind this root/raw SBOM.");
        var archives = root.GetProperty("archives");
        if (archives.ValueKind != JsonValueKind.Array || archives.GetArrayLength() > 128)
            throw new InvalidDataException("npm archive designation count.");
        var members = inventory.Dependencies.Where(c => c.Ecosystem == "npm")
            .Select(c => c.Key).ToHashSet(StringComparer.Ordinal);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in archives.EnumerateArray())
        {
            Fields(item, "purl", "path", "sha256");
            if (!NpmPackageIdentity.TryParsePurl(item.GetProperty("purl").GetString()!, out var name, out var version) ||
                !Lp02PublicSourceResolver.SafePath(item.GetProperty("path").GetString()) ||
                item.GetProperty("sha256").GetString() is not { } digest ||
                !Regex.IsMatch(digest, @"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant) ||
                !members.Contains(name + "/" + version) || !result.TryAdd(name + "/" + version, digest))
                throw new InvalidDataException("Unknown, duplicate or unsafe npm archive designation.");
        }
        return result;
    }

    internal static NpmPackage? Read(ReadOnlyMemory<byte> content)
    {
        try
        {
            if (content.Length is 0 or > ArchiveLimit) return null;
            var tar = Expand(content.ToArray());
            var headers = Headers(tar);
            if (headers.Length == 0) return null;
            var archiveRoot = headers[0].Name.Split('/')[0];
            using var expanded = new MemoryStream(tar, writable: false);
            using var reader = new TarReader(expanded);
            byte[]? packageJson = null;
            foreach (var header in headers)
            {
                var entry = reader.GetNextEntry(false);
                if (entry is null || entry.Name != header.Name || entry.Length != header.Length ||
                    (entry.EntryType == TarEntryType.Directory) != header.Directory ||
                    entry.EntryType is not (TarEntryType.Directory or TarEntryType.RegularFile or TarEntryType.V7RegularFile))
                    return null;
                if (entry.Name == archiveRoot + "/package.json")
                {
                    if (header.Directory || header.Length > 1024 * 1024 || packageJson is not null) return null;
                    packageJson = new byte[(int)header.Length];
                    (entry.DataStream ?? Stream.Null).ReadExactly(packageJson);
                }
            }
            if (reader.GetNextEntry(false) is not null || packageJson is null) return null;
            using var json = Parse(packageJson, 1024 * 1024, 16);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.String ||
                !NpmPackageIdentity.ValidName(name.GetString()!) || !NpmPackageIdentity.ValidVersion(version.GetString()!))
                return null;
            if (archiveRoot != "package" && archiveRoot != name.GetString()!.Split('/')[^1])
                return null;
            var license = root.TryGetProperty("license", out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() : null;
            return new(name.GetString()!, version.GetString()!, license);
        }
        catch (Exception error) when (error is InvalidDataException or IOException or JsonException or
            DecoderFallbackException or InvalidOperationException or ArgumentException or OverflowException)
        { return null; }
    }

    internal static string Classify(NpmPackage package, Lp01LicensePolicyResolver.Policy policy)
    {
        if (package.License is not { Length: > 0 and <= 4096 } license) return "missing-license";
        try { return Lp01LicensePolicyResolver.Classify(Lp01SpdxExpression.Parse(license), policy); }
        catch (SpdxLimitException) { return "expression-limit"; }
        catch (SpdxSyntaxException) { return "invalid-expression"; }
    }

    internal static bool ChecksumsMatch(ReadOnlySpan<byte> bytes, InventoryChecksum[]? checksums)
    {
        foreach (var checksum in checksums ?? [])
        {
            var actual = checksum.Algorithm switch
            {
                "SHA256" => SHA256.HashData(bytes),
                "SHA512" => SHA512.HashData(bytes),
                "SHA1" => SHA1.HashData(bytes),
                _ => []
            };
            if (checksum.Value != Convert.ToHexStringLower(actual)) return false;
        }
        return true;
    }

    private static byte[] Expand(byte[] bytes)
    {
        // Bound all decompressed TAR bytes, including metadata/padding, before TarReader.
        // A single-byte input prevents inflater read-ahead from concealing trailing gzip data.
        if (bytes.Length < 18 || !bytes.AsSpan(0, 4).SequenceEqual(new byte[] { 31, 139, 8, 0 }))
            throw new InvalidDataException("Only a single plain-header gzip member is supported.");
        using var compressed = new MemoryStream(bytes, writable: false);
        compressed.Position = 10;
        using var input = new SingleByteStream(compressed);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress, leaveOpen: true);
        using var output = new MemoryStream();
        var buffer = new byte[16384];
        uint crc = uint.MaxValue;
        int count;
        while ((count = deflate.Read(buffer)) != 0)
        {
            if (output.Length + count > ExpandedLimit) throw new InvalidDataException("npm expanded byte cap.");
            foreach (var value in buffer.AsSpan(0, count))
            {
                crc ^= value;
                for (var bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0u);
            }
            output.Write(buffer, 0, count);
        }
        if (compressed.Position + 8 != bytes.Length ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)compressed.Position, 4)) != ~crc ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)compressed.Position + 4, 4)) != output.Length)
            throw new InvalidDataException("Corrupt, concatenated or trailing gzip data.");
        return output.ToArray();
    }

    private sealed class SingleByteStream(Stream source) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => source.Read(buffer, offset, Math.Min(1, count));
        public override int Read(Span<byte> buffer) => source.Read(buffer[..Math.Min(1, buffer.Length)]);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed record Header(string Name, long Length, bool Directory);

    private static Header[] Headers(byte[] tar)
    {
        var result = new List<Header>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        string? archiveRoot = null;
        var cursor = 0;
        while (cursor <= tar.Length - 512)
        {
            var head = tar.AsSpan(cursor, 512);
            if (head.IndexOfAnyExcept((byte)0) < 0)
            {
                if (tar.Length - cursor < 1024 || tar.AsSpan(cursor).IndexOfAnyExcept((byte)0) >= 0)
                    throw new InvalidDataException("Incomplete/ambiguous TAR terminator.");
                return result.ToArray();
            }
            if (result.Count == 4096) throw new InvalidDataException("npm TAR entry cap.");
            var checksum = Octal(head.Slice(148, 8));
            long actual = 0;
            for (var i = 0; i < 512; i++) actual += i is >= 148 and < 156 ? 32 : head[i];
            if (checksum != actual) throw new InvalidDataException("TAR header checksum.");
            var type = head[156];
            if (type is not (0 or (byte)'0' or (byte)'5'))
                throw new InvalidDataException("npm TAR metadata, links, devices and sparse entries are unsupported.");
            string prefix;
            if (head[475] == 0 && head.Slice(257, 6).SequenceEqual("ustar\0"u8) &&
                head.Slice(263, 2).SequenceEqual("00"u8))
            {
                // node-tar stores octal atime/ctime after its short USTAR prefix.
                prefix = Text(head.Slice(345, 131));
                _ = Octal(head.Slice(476, 12));
                _ = Octal(head.Slice(488, 12));
            }
            else prefix = Text(head.Slice(345, 155));
            var name = Text(head[..100]);
            if (prefix.Length != 0) name = prefix + "/" + name;
            var normalized = name.EndsWith('/') ? name[..^1] : name;
            if (name.Length > 512 || !SafeMember(normalized) ||
                !names.Add(Lp01CaseFold.Fold(normalized)))
                throw new InvalidDataException("Unsafe/aliased npm TAR path.");
            var length = Octal(head.Slice(124, 12));
            var directory = type == (byte)'5';
            if (length > ExpandedLimit || directory && length != 0 || !directory && name.EndsWith('/'))
                throw new InvalidDataException("npm TAR member size/type.");
            var separator = normalized.IndexOf('/');
            var memberRoot = separator < 0 ? normalized : normalized[..separator];
            archiveRoot ??= memberRoot;
            if (memberRoot != archiveRoot || separator < 0 && !directory)
                throw new InvalidDataException("npm TAR must have one directory root.");
            result.Add(new(name, length, directory));
            cursor = checked(cursor + 512 + (int)((length + 511) / 512 * 512));
            if (cursor > tar.Length) throw new InvalidDataException("Truncated npm TAR member.");
        }
        throw new InvalidDataException("Missing npm TAR terminator.");
    }

    private static bool SafeMember(string path) =>
        Regex.IsMatch(path, @"\A[A-Za-z0-9_.@+ -]+(?:/[A-Za-z0-9_.@+ -]+)*\z", RegexOptions.CultureInvariant) &&
        path.Split('/').All(p => p is not ("." or "..") && p == p.Trim() && !p.EndsWith('.') &&
            !Regex.IsMatch(p.Split('.')[0], @"\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    private static string Text(ReadOnlySpan<byte> value)
    {
        var zero = value.IndexOf((byte)0);
        if (zero >= 0)
        {
            if (value[zero..].IndexOfAnyExcept((byte)0) >= 0) throw new InvalidDataException("Ambiguous TAR name field.");
            value = value[..zero];
        }
        if (value.ContainsAnyExceptInRange((byte)32, (byte)126)) throw new InvalidDataException("Non-ASCII TAR field.");
        return Encoding.ASCII.GetString(value);
    }

    private static long Octal(ReadOnlySpan<byte> value)
    {
        long result = 0;
        var text = Encoding.ASCII.GetString(value).Trim('\0', ' ');
        if (text.Length == 0) return 0;
        foreach (var c in text)
        {
            if (c is < '0' or > '7') throw new InvalidDataException("Non-octal TAR field.");
            result = checked(result * 8 + c - '0');
        }
        return result;
    }

    private static JsonDocument Parse(ReadOnlyMemory<byte> bytes, int limit, int depth)
    {
        if (bytes.Length > limit) throw new InvalidDataException("npm JSON byte cap.");
        _ = Utf8.GetCharCount(bytes.Span);
        var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = depth });
        var count = 0;
        void Visit(JsonElement value)
        {
            if (++count > 32768) throw new InvalidDataException("npm JSON value cap.");
            if (value.ValueKind == JsonValueKind.Object)
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject())
                {
                    if (++count > 32768 || !seen.Add(property.Name) || Utf8.GetByteCount(property.Name) > 16384)
                        throw new InvalidDataException("Duplicate/oversized npm JSON property.");
                    Visit(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
                foreach (var item in value.EnumerateArray()) Visit(item);
            else if (value.ValueKind == JsonValueKind.String && Utf8.GetByteCount(value.GetString()!) > 16384)
                throw new InvalidDataException("npm JSON string cap.");
        }
        try { Visit(doc.RootElement); return doc; }
        catch { doc.Dispose(); throw; }
    }

    private static void Fields(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != fields.Length ||
            fields.Any(field => !value.TryGetProperty(field, out _)))
            throw new InvalidDataException("Unsupported npm archive designation fields.");
    }
}
