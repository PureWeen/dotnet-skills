using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using BlazorComponentReadiness.Validator.Contracts;

namespace BlazorComponentReadiness.Validator.IO;

public static class NupkgInspector
{
    private const int UnixFileTypeMask = 0xF000;
    private const int UnixSymbolicLink = 0xA000;
    private static readonly Regex PackageIdPattern = new(
        @"^[A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex PackageVersionPattern = new(
        @"^[0-9]+(?:\.[0-9]+){0,3}(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static PackageIdentity Inspect(string path)
    {
        SafePath.EnsureRegularFile(path);
        var bytes = BoundedIO.ReadAllBytes(path, ResourceLimits.NupkgBytes, "nupkg");
        var digest = Convert.ToHexStringLower(SHA256.HashData(bytes));

        try
        {
            using var packageStream = new MemoryStream(bytes, writable: false);
            using var archive = new ZipArchive(packageStream, ZipArchiveMode.Read, leaveOpen: false);
            foreach (var entry in archive.Entries)
            {
                SafePath.ValidateArchiveEntry(entry.FullName, IsSymbolicLink(entry));
            }

            var nuspecEntries = archive.Entries
                .Where(entry =>
                    !entry.FullName.Contains('/', StringComparison.Ordinal) &&
                    entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (nuspecEntries.Length != 1)
            {
                throw new DeterministicValidationException(
                    $"A package must contain exactly one root-level nuspec; found {nuspecEntries.Length}.");
            }

            var nuspec = nuspecEntries[0];
            BoundedIO.EnsureLength(nuspec.Length, ResourceLimits.NuspecBytes, "nuspec");
            using var nuspecStream = nuspec.Open();
            var nuspecBytes = BoundedIO.ReadAllBytes(nuspecStream, ResourceLimits.NuspecBytes, "nuspec");
            var (id, version) = ReadIdentity(nuspecBytes);
            return new PackageIdentity(id, version, digest, bytes.LongLength, nuspec.FullName);
        }
        catch (InvalidDataException exception)
        {
            throw new DeterministicValidationException("The nupkg is not a valid ZIP package.", exception);
        }
    }

    private static (string Id, string Version) ReadIdentity(byte[] nuspecBytes)
    {
        try
        {
            using var stream = new MemoryStream(nuspecBytes, writable: false);
            using var reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = ResourceLimits.NuspecBytes,
                IgnoreComments = false,
                IgnoreWhitespace = false
            });
            var document = XDocument.Load(reader, LoadOptions.None);
            var root = document.Root;
            if (root is null || root.Name.LocalName != "package")
            {
                throw new DeterministicValidationException("The nuspec root element must be 'package'.");
            }

            var metadata = SingleChild(root, "metadata");
            var id = SingleChild(metadata, "id").Value.Trim();
            var version = SingleChild(metadata, "version").Value.Trim();
            ValidateIdentityValue(id, "package ID", PackageIdPattern, maximumLength: 100);
            ValidateIdentityValue(version, "package version", PackageVersionPattern, maximumLength: 256);
            return (id, version);
        }
        catch (XmlException exception)
        {
            throw new DeterministicValidationException($"The nuspec is not safe, well-formed XML: {exception.Message}", exception);
        }
    }

    private static XElement SingleChild(XElement parent, string localName)
    {
        var matches = parent.Elements().Where(element => element.Name.LocalName == localName).ToArray();
        if (matches.Length != 1)
        {
            throw new DeterministicValidationException(
                $"The nuspec must contain exactly one '{localName}' element beneath '{parent.Name.LocalName}'.");
        }

        return matches[0];
    }

    private static void ValidateIdentityValue(string value, string name, Regex pattern, int maximumLength)
    {
        if (value.Length is 0 || value.Length > maximumLength || value.Any(char.IsControl) || !pattern.IsMatch(value))
        {
            throw new DeterministicValidationException($"The nuspec {name} is empty or invalid.");
        }
    }

    private static bool IsSymbolicLink(ZipArchiveEntry entry) =>
        ((entry.ExternalAttributes >> 16) & UnixFileTypeMask) == UnixSymbolicLink;
}
