using System.Text.Json;
using System.Text.RegularExpressions;

namespace BlazorPackageResolver;

public sealed record ResolveRequest(int SchemaVersion, List<RequestedCase> Cases);
public sealed record RequestedCase(string CaseId, string RowId, List<PinnedInput> Inputs);

/// <summary>Bounded admission without expected answers; row classification is unchanged.</summary>
public static class Requests
{
    private const int FileLimit = 64 * 1024 * 1024;
    private const int TotalLimit = 256 * 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
    };

    public static byte[] Run(string manifestPath, Registry registry)
    {
        var full = FullPath(manifestPath);
        var root = Path.GetDirectoryName(full)!;
        using var document = JsonDocument.Parse(Read(full, 1024 * 1024), new() { MaxDepth = 16 });
        Unique(document.RootElement);
        var request = document.Deserialize<ResolveRequest>(Options)
            ?? throw new InvalidDataException("Empty resolve request.");
        if (request.SchemaVersion != 1 || request.Cases is not { Count: > 0 and <= 256 })
            throw new InvalidDataException("Unsupported or oversized resolve request.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var results = new List<(string, CaseResult)>();
        long total = 0;
        foreach (var item in request.Cases)
        {
            if (item is null || item.CaseId is not { Length: > 0 and <= 256 } ||
                string.IsNullOrWhiteSpace(item.CaseId) || string.IsNullOrWhiteSpace(item.RowId) ||
                !ids.Add(item.CaseId) || item.Inputs is not { Count: <= 512 })
                throw new InvalidDataException("Invalid case identity or input count.");
            var inputs = new Dictionary<string, CheckedInput>(StringComparer.Ordinal);
            foreach (var pin in item.Inputs)
            {
                if (pin is null || pin.Role is not { Length: > 0 and <= 128 } || string.IsNullOrWhiteSpace(pin.Role) ||
                    inputs.ContainsKey(pin.Role) || !Relative(pin.Path) ||
                    !Regex.IsMatch(pin.Sha256 ?? "", "\\A[a-f0-9]{64}\\z", RegexOptions.CultureInvariant))
                    throw new InvalidDataException("Invalid input identity.");
                var path = root;
                foreach (var part in pin.Path.Split('/'))
                {
                    path = Path.Combine(path, part);
                    if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidDataException("Linked inputs are unsupported.");
                }
                var bytes = Read(path, (int)Math.Min(FileLimit, TotalLimit - total));
                total += bytes.Length;
                if (Catalog.Digest(bytes) != pin.Sha256)
                    throw new InvalidDataException("Input digest mismatch.");
                inputs.Add(pin.Role, new(pin, bytes));
            }
            results.Add((item.CaseId, registry.Dispatch(new(item.CaseId, item.RowId, item.Inputs, inputs))));
        }
        return Write(results);
    }

    public static byte[] Package(string packagePath, Registry registry)
    {
        packagePath = FullPath(packagePath);
        var name = Path.GetFileName(packagePath);
        if (!Relative(name) || !name.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase) ||
            (File.GetAttributes(packagePath) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Package needs a canonical regular .nupkg path.");
        var bytes = Read(packagePath, FileLimit);
        var pin = new PinnedInput("package", name, Catalog.Digest(bytes));
        var checkedInputs = new Dictionary<string, CheckedInput>(StringComparer.Ordinal)
            { ["package"] = new(pin, bytes) };
        var rows = Enumerable.Range(1, 10).Select(n => $"LP-{n:00}").Append("PI-01");
        return Write(rows.Select(row =>
            ("package-" + row.ToLowerInvariant(),
             registry.Dispatch(new("package-" + row.ToLowerInvariant(), row, [pin], checkedInputs)))));
    }

    private static bool Relative(string? value) => value is { Length: > 0 and <= 256 } &&
        Regex.IsMatch(value, "\\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\\z", RegexOptions.CultureInvariant) &&
        value.Split('/').All(part => part is not ("." or ".."));

    private static string FullPath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch (ArgumentException error) { throw new InvalidDataException("Invalid input path.", error); }
    }

    private static byte[] Read(string path, int maximum)
    {
        using var stream = File.OpenRead(path);
        if (maximum < 0 || stream.Length > maximum)
            throw new InvalidDataException("Input resource limit.");
        using var output = new MemoryStream();
        var buffer = new byte[16384];
        int count;
        while ((count = stream.Read(buffer)) != 0)
        {
            if (output.Length + count > maximum)
                throw new InvalidDataException("Input resource limit.");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    private static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate request field.");
                Unique(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) Unique(item);
    }

    private static byte[] Write(IEnumerable<(string Id, CaseResult Result)> results) =>
        Canonical.Write(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WritePropertyName("cases");
            writer.WriteStartArray();
            foreach (var (id, result) in results)
            {
                writer.WriteStartObject();
                writer.WriteString("case_id", id);
                writer.WritePropertyName("result");
                result.Write(writer);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        });
}
