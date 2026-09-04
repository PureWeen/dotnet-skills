using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using BlazorComponentReadiness.Validator.IO;

namespace BlazorComponentReadiness.Validator.Validation;

public static partial class Canonicalization
{
    [GeneratedRegex("^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex PackageIdPattern();

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex ComponentIdPattern();

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitPattern();

    public static string PackageId(string value)
    {
        value = ContractJson.NormalizeText(value, "package_id", 100).ToLowerInvariant();
        if (!PackageIdPattern().IsMatch(value))
        {
            throw new DeterministicValidationException("package_id has invalid canonical NuGet syntax.");
        }

        return value;
    }

    public static string ComponentId(string value)
    {
        value = ContractJson.NormalizeText(
                value.Trim().Normalize(NormalizationForm.FormC),
                "component_id",
                256)
            .Normalize(NormalizationForm.FormC)
            .ToLowerInvariant();
        var builder = new StringBuilder();
        var separator = false;
        foreach (var character in value)
        {
            if (char.IsAsciiLetterOrDigit(character))
            {
                if (separator && builder.Length > 0)
                {
                    builder.Append('-');
                }

                builder.Append(character);
                separator = false;
            }
            else
            {
                separator = true;
            }
        }

        var result = builder.ToString().Trim('-');
        if (!ComponentIdPattern().IsMatch(result))
        {
            throw new DeterministicValidationException(
                "component_id cannot be canonicalized to a bounded lowercase identifier.");
        }

        return result;
    }

    public static string RenderMode(string value)
    {
        value = ContractJson.NormalizeText(value, "render_mode", 64)
            .ToLowerInvariant()
            .Replace("_", "-", StringComparison.Ordinal)
            .Replace(" ", "-", StringComparison.Ordinal);
        return value switch
        {
            "static" or "ssr" or "static-ssr" => "static-ssr",
            "server" or "interactive-server" => "interactive-server",
            "wasm" or "webassembly" or "interactive-wasm" or "interactive-webassembly" =>
                "interactive-webassembly",
            "auto" or "interactive-auto" => "interactive-auto",
            "standalone-wasm" or "standalone-webassembly" => "standalone-webassembly",
            _ => throw new DeterministicValidationException($"Unsupported render mode '{value}'.")
        };
    }

    public static string HttpsUri(string value, bool requirePath)
    {
        value = ContractJson.NormalizeText(value, "URI", 2048);
        if (value.Contains('%') || value.Contains('?') || value.Contains('#') ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !uri.IsDefaultPort ||
            string.IsNullOrWhiteSpace(uri.IdnHost) ||
            uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6)
        {
            throw new DeterministicValidationException(
                "URI must be a host-neutral public HTTPS URI without credentials, ports, query, fragment, or encoding.");
        }

        var host = uri.IdnHost.ToLowerInvariant();
        if (host is "localhost" || !host.Contains('.', StringComparison.Ordinal) || host.EndsWith('.'))
        {
            throw new DeterministicValidationException("URI host must be a public DNS name.");
        }

        var path = uri.AbsolutePath;
        if (requirePath && path == "/")
        {
            throw new DeterministicValidationException("Repository URI requires a non-root path.");
        }

        if (path.Length > 1 && path.EndsWith('/'))
        {
            path = path.TrimEnd('/');
        }

        if (path.Contains("//", StringComparison.Ordinal) ||
            path.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(segment => segment is "." or ".."))
        {
            throw new DeterministicValidationException("URI path is not canonical.");
        }

        return $"https://{host}{path}";
    }

    public static string Commit(string value)
    {
        value = ContractJson.NormalizeText(value, "source commit", 40).ToLowerInvariant();
        if (!CommitPattern().IsMatch(value))
        {
            throw new DeterministicValidationException("Source commit must be exactly 40 lowercase hexadecimal characters.");
        }

        return value;
    }

    public static string RelativePath(string value, string name)
    {
        value = ContractJson.NormalizeText(value, name, 1024).Replace('\\', '/');
        if (Path.IsPathRooted(value) ||
            value.Contains(':', StringComparison.Ordinal) ||
            value.Split('/').Any(segment => segment.Length == 0 || segment is "." or ".."))
        {
            throw new DeterministicValidationException($"{name} must be a normalized relative path.");
        }

        return value;
    }

    public static string Basename(string value, string name)
    {
        value = ContractJson.NormalizeText(value, name, 256);
        if (value is "." or ".." ||
            value.Contains('/') ||
            value.Contains('\\') ||
            value.Contains(':'))
        {
            throw new DeterministicValidationException($"{name} must be a basename without a path.");
        }

        return value;
    }
}
