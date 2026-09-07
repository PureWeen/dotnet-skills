using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using BlazorComponentReadiness.Validator.Validation;

namespace BlazorComponentReadiness.Validator.IO;

/// <summary>
/// Verifies selected files against a retained source archive without invoking Git or extracting it.
/// </summary>
public static class SourceArchiveCaptureService
{
    /// <summary>
    /// Captures selected source files and writes a new deterministic receipt beneath <paramref name="root"/>.
    /// </summary>
    public static byte[] Capture(
        string root,
        string archivePath,
        string sourceRoot,
        string? archivePrefix,
        string archiveFormat,
        string repositoryUri,
        string sourceCommit,
        string sourceMapping,
        string sourceConfidence,
        string acquisitionLocator,
        IReadOnlyList<string> selectedSourcePaths,
        string? expectedArchiveSha256,
        string outputPath)
    {
        var fullRoot = EnsureRoot(root);
        var (archiveRelativePath, fullArchivePath) = ResolveFile(fullRoot, archivePath, "archive");
        var (sourceRootRelativePath, _) = ResolveDirectory(
            fullRoot,
            sourceRoot,
            "source root");
        var outputRelativePath = ResolveOutput(fullRoot, outputPath);
        if (outputRelativePath.StartsWith(sourceRootRelativePath + "/", StringComparison.OrdinalIgnoreCase))
        {
            throw new DeterministicValidationException(
                "The source capture receipt must be outside the extracted source directory.");
        }

        var format = NormalizeFormat(archiveFormat, fullArchivePath);
        var prefix = NormalizeArchivePrefix(archivePrefix);
        var selected = NormalizeSelectedSourcePaths(selectedSourcePaths);
        var source = NormalizeSource(
            repositoryUri,
            sourceCommit,
            sourceMapping,
            sourceConfidence,
            acquisitionLocator);

        var archiveBytes = BoundedIO.ReadAllBytes(
            fullArchivePath,
            ResourceLimits.SourceArchiveBytes,
            "source archive");
        var archiveSha256 = Convert.ToHexStringLower(SHA256.HashData(archiveBytes));
        if (expectedArchiveSha256 is not null &&
            !string.Equals(
                NormalizeSha256(expectedArchiveSha256, "expected archive SHA-256"),
                archiveSha256,
                StringComparison.Ordinal))
        {
            throw new DeterministicValidationException(
                "The retained source archive does not match the expected SHA-256.");
        }

        var selectedEntries = selected.ToDictionary(
            path => ArchivePath(prefix, path),
            path => path,
            StringComparer.Ordinal);
        var captured = format switch
        {
            "tar.gz" => ReadTarGzip(archiveBytes, selectedEntries),
            "zip" => ReadZip(archiveBytes, selectedEntries),
            _ => throw new DeterministicValidationException($"Unsupported source archive format '{format}'.")
        };

        var artifacts = selected
            .Select(sourcePath =>
            {
                var archiveEntry = ArchivePath(prefix, sourcePath);
                if (!captured.TryGetValue(archiveEntry, out var archiveContent))
                {
                    throw new DeterministicValidationException(
                        $"The source archive does not contain selected file '{archiveEntry}'.");
                }

                var contentPath = Canonicalization.RelativePath(
                    Path.Combine(sourceRootRelativePath, sourcePath).Replace('\\', '/'),
                    "source artifact content_path");
                var fullContentPath = SafePath.ResolveUnderRoot(
                    fullRoot,
                    contentPath,
                    requireExisting: true,
                    requireFile: true);
                var localContent = BoundedIO.ReadAllBytes(
                    fullContentPath,
                    ResourceLimits.SourceArchiveExpandedBytes,
                    "selected source file");
                if (!localContent.SequenceEqual(archiveContent.Bytes))
                {
                    throw new DeterministicValidationException(
                        $"Selected source file '{sourcePath}' does not match archive entry '{archiveEntry}'.");
                }

                var contentSha256 = Convert.ToHexStringLower(SHA256.HashData(localContent));
                if (!string.Equals(contentSha256, archiveContent.Sha256, StringComparison.Ordinal))
                {
                    throw new DeterministicValidationException(
                        $"Selected source file '{sourcePath}' has inconsistent archive and local digests.");
                }

                return new CapturedArtifact(sourcePath, contentPath, archiveEntry, contentSha256);
            })
            .ToArray();

        var receipt = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("capture_kind", "source-archive");
            writer.WriteString("archive_format", format);
            writer.WriteString("archive_path", archiveRelativePath);
            writer.WriteString("source_root", sourceRootRelativePath);
            writer.WriteString("archive_entry_prefix", prefix);
            writer.WritePropertyName("declared_source");
            writer.WriteStartObject();
            writer.WriteString("availability", "source-available");
            writer.WriteString("repository_uri", source.RepositoryUri);
            writer.WriteString("commit", source.Commit);
            writer.WriteString("mapping", source.Mapping);
            writer.WriteString("confidence", source.Confidence);
            writer.WriteString("acquisition_locator", source.AcquisitionLocator);
            writer.WriteEndObject();
            writer.WritePropertyName("archive");
            writer.WriteStartObject();
            writer.WriteString("path", archiveRelativePath);
            writer.WriteString("format", format);
            writer.WriteString("sha256", archiveSha256);
            writer.WriteNumber("size", archiveBytes.LongLength);
            writer.WriteEndObject();
            writer.WritePropertyName("source_artifacts");
            writer.WriteStartArray();
            foreach (var artifact in artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("source_path", artifact.SourcePath);
                writer.WriteString("content_path", artifact.ContentPath);
                writer.WriteString("archive_entry", artifact.ArchiveEntry);
                writer.WriteString("archive_content_sha256", artifact.ContentSha256);
                writer.WriteString("content_sha256", artifact.ContentSha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        });

        AtomicFile.WriteNew(
            fullRoot,
            outputRelativePath,
            receipt.Concat(Encoding.UTF8.GetBytes("\n")).ToArray());
        return receipt;
    }

    private static Dictionary<string, CapturedArchiveContent> ReadZip(
        byte[] archiveBytes,
        IReadOnlyDictionary<string, string> selectedEntries)
    {
        try
        {
            using var stream = new MemoryStream(archiveBytes, writable: false);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);
            var names = new HashSet<string>(StringComparer.Ordinal);
            var result = new Dictionary<string, CapturedArchiveContent>(StringComparer.Ordinal);
            long expandedBytes = 0;
            var entryCount = 0;
            foreach (var entry in archive.Entries)
            {
                if (++entryCount > ResourceLimits.SourceArchiveEntryCount)
                {
                    throw new ResourceLimitException(
                        "source archive entries",
                        ResourceLimits.SourceArchiveEntryCount,
                        entryCount);
                }

                SafePath.ValidateArchiveEntry(entry.FullName, IsZipSymbolicLink(entry));
                if (!names.Add(CanonicalArchiveName(entry.FullName)))
                {
                    throw new DeterministicValidationException(
                        $"The source archive contains duplicate entry '{entry.FullName}'.");
                }

                if (entry.FullName.EndsWith('/', StringComparison.Ordinal))
                {
                    continue;
                }

                BoundedIO.EnsureLength(
                    entry.Length,
                    ResourceLimits.SourceArchiveExpandedBytes,
                    "source archive entry");
                using var entryStream = entry.Open();
                var selected = selectedEntries.ContainsKey(entry.FullName);
                var content = ReadEntry(entryStream, selected, ref expandedBytes);
                if (selected)
                {
                    result.Add(
                        entry.FullName,
                        new CapturedArchiveContent(
                            content,
                            Convert.ToHexStringLower(SHA256.HashData(content))));
                }
            }

            return result;
        }
        catch (InvalidDataException exception)
        {
            throw new DeterministicValidationException(
                "The source archive is not a valid ZIP archive.",
                exception);
        }
    }

    private static Dictionary<string, CapturedArchiveContent> ReadTarGzip(
        byte[] archiveBytes,
        IReadOnlyDictionary<string, string> selectedEntries)
    {
        try
        {
            using var compressed = new MemoryStream(archiveBytes, writable: false);
            using var gzip = new GZipStream(compressed, CompressionMode.Decompress, leaveOpen: false);
            // Bound metadata and padding too, before the TAR reader consumes them.
            long decompressedBytes = 0;
            using var expanded = new MemoryStream(ReadEntry(gzip, retain: true, ref decompressedBytes), writable: false);
            using var reader = new TarReader(expanded, leaveOpen: false);
            var names = new HashSet<string>(StringComparer.Ordinal);
            var result = new Dictionary<string, CapturedArchiveContent>(StringComparer.Ordinal);
            long expandedBytes = 0;
            var entryCount = 0;
            TarEntry? entry;
            while ((entry = reader.GetNextEntry(false)) is not null)
            {
                if (++entryCount > ResourceLimits.SourceArchiveEntryCount)
                {
                    throw new ResourceLimitException(
                        "source archive entries",
                        ResourceLimits.SourceArchiveEntryCount,
                        entryCount);
                }

                if (entry.EntryType == TarEntryType.GlobalExtendedAttributes)
                {
                    continue;
                }

                var isDirectory = entry.EntryType == TarEntryType.Directory;
                if (entry.EntryType is not (TarEntryType.Directory or TarEntryType.RegularFile or TarEntryType.V7RegularFile))
                {
                    throw new DeterministicValidationException(
                        $"The source archive entry '{entry.Name}' is not a regular file or directory.");
                }

                SafePath.ValidateArchiveEntry(entry.Name, isSymbolicLink: false);
                if (!names.Add(CanonicalArchiveName(entry.Name)))
                {
                    throw new DeterministicValidationException(
                        $"The source archive contains duplicate entry '{entry.Name}'.");
                }

                if (isDirectory)
                {
                    continue;
                }

                if (entry.DataStream is null && entry.Length != 0)
                {
                    throw new DeterministicValidationException(
                        $"The source archive file entry '{entry.Name}' has no data stream.");
                }

                var selected = selectedEntries.ContainsKey(entry.Name);
                var content = ReadEntry(entry.DataStream ?? Stream.Null, selected, ref expandedBytes);
                if (selected)
                {
                    result.Add(
                        entry.Name,
                        new CapturedArchiveContent(
                            content,
                            Convert.ToHexStringLower(SHA256.HashData(content))));
                }
            }

            return result;
        }
        catch (InvalidDataException exception)
        {
            throw new DeterministicValidationException(
                "The source archive is not a valid gzip-compressed TAR archive.",
                exception);
        }
    }

    private static byte[] ReadEntry(Stream input, bool retain, ref long expandedBytes)
    {
        using var retained = retain ? new MemoryStream() : null;
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            expandedBytes = checked(expandedBytes + read);
            BoundedIO.EnsureLength(
                expandedBytes,
                ResourceLimits.SourceArchiveExpandedBytes,
                "expanded source archive");
            retained?.Write(buffer, 0, read);
        }

        return retained?.ToArray() ?? [];
    }

    private static string EnsureRoot(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var fullRoot = Path.GetFullPath(root);
        if (!Directory.Exists(fullRoot) ||
            (File.GetAttributes(fullRoot) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) !=
            FileAttributes.Directory)
        {
            throw new DeterministicValidationException(
                "The source capture root must be an existing regular directory.");
        }

        return fullRoot;
    }

    private static (string RelativePath, string FullPath) ResolveFile(
        string root,
        string path,
        string resource)
    {
        var relative = RelativePath(root, path, resource);
        return (
            relative,
            SafePath.ResolveUnderRoot(root, relative, requireExisting: true, requireFile: true));
    }

    private static (string RelativePath, string FullPath) ResolveDirectory(
        string root,
        string path,
        string resource)
    {
        var relative = RelativePath(root, path, resource);
        var fullPath = SafePath.ResolveUnderRoot(root, relative, requireExisting: true);
        if (!Directory.Exists(fullPath) ||
            (File.GetAttributes(fullPath) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) !=
            FileAttributes.Directory)
        {
            throw new DeterministicValidationException(
                $"The {resource} must be an existing regular directory.");
        }

        return (relative, fullPath);
    }

    private static string ResolveOutput(string root, string path)
    {
        var relative = RelativePath(root, path, "output");
        _ = SafePath.ResolveUnderRoot(root, relative, requireExisting: false);
        return relative;
    }

    private static string RelativePath(string root, string path, string resource)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.IsPathRooted(path)
            ? Path.GetFullPath(path)
            : Path.GetFullPath(Path.Combine(root, path));
        var relative = Path.GetRelativePath(root, fullPath).Replace('\\', '/');
        return Canonicalization.RelativePath(relative, $"{resource} path");
    }

    private static string NormalizeFormat(string value, string archivePath)
    {
        var format = ContractJson.NormalizeText(value, "archive format", 16).ToLowerInvariant();
        if (format is "tgz")
        {
            format = "tar.gz";
        }

        if (format is not ("tar.gz" or "zip"))
        {
            throw new DeterministicValidationException(
                "archive format must be exactly 'tar.gz' or 'zip'.");
        }

        if (format == "tar.gz" &&
            !archivePath.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase) &&
            !archivePath.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase))
        {
            throw new DeterministicValidationException(
                "A tar.gz source archive must use a .tar.gz or .tgz retained path.");
        }

        if (format == "zip" && !archivePath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            throw new DeterministicValidationException(
                "A ZIP source archive must use a .zip retained path.");
        }

        return format;
    }

    private static string NormalizeArchivePrefix(string? value)
    {
        if (value is null)
        {
            return string.Empty;
        }

        var prefix = ContractJson.NormalizeText(value, "archive entry prefix", 1024);
        if (prefix.EndsWith('/', StringComparison.Ordinal))
        {
            prefix = prefix[..^1];
        }

        if (prefix.Length == 0)
        {
            throw new DeterministicValidationException(
                "archive entry prefix must be a nonempty safe relative path when supplied.");
        }

        _ = Canonicalization.RelativePath(prefix, "archive entry prefix");
        SafePath.ValidateArchiveEntry(prefix, isSymbolicLink: false);
        return prefix;
    }

    private static string[] NormalizeSelectedSourcePaths(IReadOnlyList<string> values)
    {
        if (values.Count is 0 or > ResourceLimits.SourceArchiveSelectionCount)
        {
            throw new DeterministicValidationException(
                $"source paths require between 1 and {ResourceLimits.SourceArchiveSelectionCount} entries.");
        }

        var result = values
            .Select(value => Canonicalization.RelativePath(value, "selected source path"))
            .ToArray();
        if (result.Distinct(StringComparer.Ordinal).Count() != result.Length)
        {
            throw new DeterministicValidationException(
                "Selected source paths must be unique.");
        }

        return result.Order(StringComparer.Ordinal).ToArray();
    }

    private static SourceDeclaration NormalizeSource(
        string repositoryUri,
        string sourceCommit,
        string sourceMapping,
        string sourceConfidence,
        string acquisitionLocator) =>
        new(
            Canonicalization.HttpsUri(repositoryUri, requirePath: true),
            Canonicalization.Commit(sourceCommit),
            ContractJson.NormalizeText(sourceMapping, "source mapping", 1024),
            NormalizeConfidence(sourceConfidence),
            Canonicalization.HttpsUri(acquisitionLocator, requirePath: true));

    private static string NormalizeConfidence(string value)
    {
        value = ContractJson.NormalizeText(value, "source confidence", 16).ToLowerInvariant();
        if (value is not ("low" or "medium" or "high"))
        {
            throw new DeterministicValidationException(
                "source confidence must be 'low', 'medium', or 'high'.");
        }

        return value;
    }

    private static string NormalizeSha256(string value, string name)
    {
        value = ContractJson.NormalizeText(value, name, 64).ToLowerInvariant();
        if (value.Length != 64 || value.Any(character =>
                character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new DeterministicValidationException($"{name} must be canonical lowercase SHA-256.");
        }

        return value;
    }

    private static string ArchivePath(string prefix, string sourcePath) =>
        prefix.Length == 0 ? sourcePath : $"{prefix}/{sourcePath}";

    private static string CanonicalArchiveName(string name) =>
        name.EndsWith('/', StringComparison.Ordinal) ? name[..^1] : name;

    private static bool IsZipSymbolicLink(ZipArchiveEntry entry) =>
        ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000;

    private sealed record SourceDeclaration(
        string RepositoryUri,
        string Commit,
        string Mapping,
        string Confidence,
        string AcquisitionLocator);

    private sealed record CapturedArchiveContent(byte[] Bytes, string Sha256);

    private sealed record CapturedArtifact(
        string SourcePath,
        string ContentPath,
        string ArchiveEntry,
        string ContentSha256);
}
