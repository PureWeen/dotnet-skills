using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BlazorPackageResolver;

internal static class ProvenanceTestAdmission
{
    // Offline test double for the trusted acquisition/gh boundary; never a production verification key.
    private static readonly byte[] Key = SHA256.HashData("offline-test-helper-only"u8);

    internal static byte[] Sign(byte[] raw, byte[] source, string repository, string commit, bool acquired = true)
    {
        var doc = JsonNode.Parse(raw)!;
        if (acquired)
            doc["source_acquisition"] = JsonSerializer.SerializeToNode(new
            {
                producer = "lp02-anonymous-github/1.0.0",
                package_sha256 = doc["package_sha256"]!.GetValue<string>(),
                repository_url = repository,
                commit,
                archive_size = source.Length,
                retrieval_attempt = new
                {
                    url = "https://codeload.github.com/" + repository["https://github.com/".Length..] + "/zip/" + commit,
                    transport = "direct-https-no-credentials/1", result = "retrieved", http_status = 200
                },
                capture_receipt = new { role = "source-archive", sha256 = Catalog.Digest(source) }
            });
        var payload = Encoding.UTF8.GetBytes(doc.ToJsonString());
        Environment.SetEnvironmentVariable("BLAZOR_PROVENANCE_ADMISSION_KEY", Convert.ToHexString(Key));
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            payload = Convert.ToBase64String(payload),
            hmac_sha256 = Convert.ToHexString(HMACSHA256.HashData(Key, payload))
        });
    }

    internal static byte[] Payload(byte[] envelope) =>
        Convert.FromBase64String(JsonNode.Parse(envelope)!["payload"]!.GetValue<string>());
}
