using System.Text.RegularExpressions;

namespace BlazorPackageResolver;

internal static class NuGetPackageIdentity
{
    private static readonly Regex Id = new(@"\A[a-z0-9][a-z0-9.-]{0,63}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Version = new(
        @"\A(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){2}\z", RegexOptions.CultureInvariant);
    internal static bool ValidId(string value) => Id.IsMatch(value);
    internal static bool ValidVersion(string value) => Version.IsMatch(value);
}
