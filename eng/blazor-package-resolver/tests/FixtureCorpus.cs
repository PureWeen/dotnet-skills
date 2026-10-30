using System.Diagnostics;
using System.Runtime.CompilerServices;

internal sealed class FixtureCorpus : IDisposable
{
    internal string Root { get; }
    internal static string Tests([CallerFilePath] string file = "") => Path.GetDirectoryName(file)!;
    internal static string Runtime => Path.GetFullPath(Path.Combine(Tests(), "..", "..", "..",
        "plugins", "dotnet-blazor", "skills", "blazor-package-readiness-resolver", "scripts", "resolver"));

    internal FixtureCorpus()
    {
        Root = Path.Combine(Path.GetTempPath(), "resolver-corpus-" + Guid.NewGuid().ToString("N"));
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("PYTHON") ?? "python")
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { Path.Combine(Tests(), "corpus.py"), "materialize", "--output", Root })
            start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Python did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120000))
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Corpus materialization timed out.");
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException("Corpus materialization failed: " +
                output.GetAwaiter().GetResult() + error.GetAwaiter().GetResult());
    }

    public void Dispose()
    {
        if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
    }
}
