using System.Text.Json;

namespace BlazorPackageResolver;

internal static class JsonStringValidation
{
    internal static bool IsWellFormed(JsonElement value)
    {
        try { return Visit(value); }
        catch (InvalidOperationException) { return false; }
    }

    private static bool Visit(JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in value.EnumerateObject())
                {
                    var name = property.Name;
                    if (!names.Add(name) || !WellFormedUtf16(name) || !Visit(property.Value)) return false;
                }
                return true;
            case JsonValueKind.Array:
                return value.EnumerateArray().All(Visit);
            case JsonValueKind.String:
                return WellFormedUtf16(value.GetString()!);
            default:
                return value.ValueKind is JsonValueKind.Number or JsonValueKind.True or
                    JsonValueKind.False or JsonValueKind.Null;
        }
    }

    private static bool WellFormedUtf16(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (!char.IsSurrogate(value[index])) continue;
            if (!char.IsHighSurrogate(value[index]) || index + 1 == value.Length ||
                !char.IsLowSurrogate(value[++index])) return false;
        }
        return true;
    }
}
