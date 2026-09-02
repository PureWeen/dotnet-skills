namespace BlazorComponentReadiness.Validator.IO;

public sealed record ImmutableInputSnapshot(
    string Path,
    string Resource,
    byte[] Bytes)
{
    public static ImmutableInputSnapshot Capture(string path, string resource) =>
        new(
            System.IO.Path.GetFullPath(path),
            resource,
            BoundedIO.ReadAllBytes(path, ResourceLimits.SerializedArtifactBytes, resource));

    public void EnsureUnchanged()
    {
        var actual = BoundedIO.ReadAllBytes(
            Path,
            ResourceLimits.SerializedArtifactBytes,
            Resource);
        if (!actual.AsSpan().SequenceEqual(Bytes))
        {
            throw new DeterministicValidationException(
                $"{Resource} changed while the report revision was being rendered.");
        }
    }
}
