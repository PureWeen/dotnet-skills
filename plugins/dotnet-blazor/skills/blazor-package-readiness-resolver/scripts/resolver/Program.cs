using BlazorPackageResolver;
using System.Text.Json;

try
{
    var catalog = Catalog.Load(Path.Combine(AppContext.BaseDirectory, "data"));
    var registry = Registry.Bootstrap(catalog);
    byte[] output = args switch
    {
        [] or ["coverage"] => registry.Coverage(catalog),
        ["replay", var manifest] => Replay.Run(manifest, registry),
        ["resolve", var request] => Requests.Run(request, registry),
        ["inspect", var request] => Requests.Inspect(request),
        ["admit-sbom", var request] => Requests.AdmitSbom(request),
        ["package", var package] => Requests.Package(package, registry),
        ["acquire-lp02", var package, var destination, var project, var implementation, var rationale] =>
            await Lp02SourceAcquisition.CaptureAsync(package, destination, project, implementation, rationale),
        _ => throw new CliUsageException()
    };
    using var stdout = Console.OpenStandardOutput();
    stdout.Write(output);
}
catch (InvalidDataException error)
{
    Console.Error.WriteLine(args is ["inspect", _]
        ? "Invalid resolver catalog or input contract: " + error.Message
        : "Invalid resolver catalog or replay contract.");
    Environment.ExitCode = 2;
}
catch (JsonException)
{
    Console.Error.WriteLine("Invalid JSON contract.");
    Environment.ExitCode = 2;
}
catch (IOException)
{
    Console.Error.WriteLine("Unable to read required catalog or case input.");
    Environment.ExitCode = 2;
}
catch (UnauthorizedAccessException)
{
    Console.Error.WriteLine("Unable to read required catalog or case input.");
    Environment.ExitCode = 2;
}
catch (CliUsageException)
{
    Console.Error.WriteLine("Usage: blazor-package-resolver [coverage | resolve <request.json> | inspect <inputs.json> | admit-sbom <inputs.json> | package <nupkg> | replay <cases.json> | acquire-lp02 <nupkg> <new-directory> <archive-project-path> <archive-implementation-path> <rationale>]");
    Environment.ExitCode = 2;
}

sealed class CliUsageException : Exception;
