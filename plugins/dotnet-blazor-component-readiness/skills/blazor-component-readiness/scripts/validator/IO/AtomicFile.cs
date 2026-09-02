namespace BlazorComponentReadiness.Validator.IO;

public static class AtomicFile
{
    public static void WriteNew(string root, string relativePath, byte[] content) =>
        WriteNew(root, relativePath, stream => stream.Write(content));

    public static void WriteNew(string root, string relativePath, Action<Stream> write)
    {
        var destination = PrepareDestination(root, relativePath);
        WriteThroughTemporary(destination, write, temporary => File.Move(temporary, destination, overwrite: false));
    }

    public static void Replace(string root, string relativePath, byte[] content) =>
        Replace(root, relativePath, stream => stream.Write(content));

    public static void Replace(string root, string relativePath, Action<Stream> write)
    {
        var destination = PrepareDestination(root, relativePath);
        WriteThroughTemporary(destination, write, temporary => File.Move(temporary, destination, overwrite: true));
    }

    private static string PrepareDestination(string root, string relativePath)
    {
        var destination = SafePath.ResolveUnderRoot(root, relativePath, requireExisting: false);
        var parent = Path.GetDirectoryName(destination)
            ?? throw new DeterministicValidationException("An atomic output must have a parent directory.");
        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException($"The atomic output parent does not exist: {parent}");
        }

        if (Directory.Exists(destination))
        {
            throw new DeterministicValidationException("An atomic file destination cannot be a directory.");
        }

        if (File.Exists(destination))
        {
            SafePath.EnsureRegularFile(destination);
        }

        return destination;
    }

    private static void WriteThroughTemporary(
        string destination,
        Action<Stream> write,
        Action<string> commit)
    {
        ArgumentNullException.ThrowIfNull(write);
        var directory = Path.GetDirectoryName(destination)!;
        var temporary = Path.Combine(
            directory,
            $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");

        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 64 * 1024,
                       FileOptions.WriteThrough))
            {
                write(stream);
                stream.Flush(flushToDisk: true);
            }

            commit(temporary);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
