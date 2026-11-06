using System.Text.RegularExpressions;

namespace BlazorPackageResolver;

internal static class NpmPackageIdentity
{
    internal static bool ValidName(string name) => name.Length <= 214 &&
        Regex.IsMatch(name, @"\A(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\z",
            RegexOptions.CultureInvariant);

    internal static bool ValidVersion(string version) => version.Length <= 128 &&
        Regex.IsMatch(version,
            @"\A(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})(?:-(?:(?:0|[1-9][0-9]*)|[0-9]*[A-Za-z-][A-Za-z0-9-]*)(?:\.(?:(?:0|[1-9][0-9]*)|[0-9]*[A-Za-z-][A-Za-z0-9-]*))*)?(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?\z",
            RegexOptions.CultureInvariant);

    internal static bool TryParsePurl(string? purl, out string name, out string version)
    {
        name = version = "";
        if (purl is not { Length: > 0 and <= 512 } || !purl.StartsWith("pkg:npm/", StringComparison.Ordinal)) return false;
        var value = purl[8..];
        if (value.StartsWith("%40", StringComparison.Ordinal)) value = "@" + value[3..];
        var separator = value.LastIndexOf('@');
        if (separator <= 0) return false;
        name = value[..separator];
        version = value[(separator + 1)..];
        return ValidName(name) && ValidVersion(version);
    }
}
