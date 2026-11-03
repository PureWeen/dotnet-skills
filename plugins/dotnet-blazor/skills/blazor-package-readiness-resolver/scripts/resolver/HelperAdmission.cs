using System.Security.Cryptography;
using System.Text.Json;

namespace BlazorPackageResolver;

// Admission trusts the helper's child-process environment, never a key carried in an input packet.
internal static class HelperAdmission
{
    internal const string KeyVariable = "BLAZOR_PROVENANCE_ADMISSION_KEY";

    internal static JsonDocument? Open(ReadOnlyMemory<byte> receipt)
    {
        try
        {
            var keyText = Environment.GetEnvironmentVariable(KeyVariable);
            if (keyText is null || keyText.Length != 64) return null;
            var key = Convert.FromHexString(keyText);
            using var envelope = JsonDocument.Parse(receipt);
            var payload = Convert.FromBase64String(envelope.RootElement.GetProperty("payload").GetString()!);
            var supplied = Convert.FromHexString(envelope.RootElement.GetProperty("hmac_sha256").GetString()!);
            if (!CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(key, payload), supplied))
                return null;
            return JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 32 });
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException or
            KeyNotFoundException or ArgumentException)
        {
            return null;
        }
    }
}
