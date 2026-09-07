using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;

namespace BlazorComponentReadiness.Validator.Cli;

public static class InputsCommand
{
    private const string Help =
        """
        Canonical input manifests

        Usage:
          readiness-validator inputs candidates <init|add-...> --help
          readiness-validator inputs discover --root <dir> --nupkg <path> --candidates <json> --output <draft>
          readiness-validator inputs confirm --root <dir> --draft <json> --output <confirmed>
          readiness-validator inputs validate --root <dir> --manifest <confirmed>
        """;

    public static int Run(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 0 || IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        return args[0] switch
        {
            "candidates" => InputCandidatesCommand.Run(args.Skip(1).ToArray(), output),
            "discover" => Discover(args.Skip(1).ToArray(), output),
            "confirm" => Confirm(args.Skip(1).ToArray(), output),
            "validate" => Validate(args.Skip(1).ToArray(), output),
            _ => throw new UsageException($"Unknown inputs command '{args[0]}'.")
        };
    }

    private static int Discover(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 1 && IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        var options = CommandOptions.Parse(args, "--root", "--nupkg", "--candidates", "--output");
        var root = Path.GetFullPath(options.Single("--root"));
        var candidates = BoundedIO.ReadAllBytes(
            options.Single("--candidates"),
            ResourceLimits.SerializedArtifactBytes,
            "input discovery candidates");
        var manifest = InputManifestService.Discover(root, options.Single("--nupkg"), candidates);
        WriteNew(options.Single("--output"), InputManifestService.Serialize(manifest));
        return ExitCodes.Success;
    }

    private static int Confirm(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 1 && IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        var options = CommandOptions.Parse(args, "--root", "--draft", "--output");
        var root = Path.GetFullPath(options.Single("--root"));
        var bytes = BoundedIO.ReadAllBytes(
            options.Single("--draft"),
            ResourceLimits.SerializedArtifactBytes,
            "draft input manifest");
        var confirmed = InputManifestService.Confirm(InputManifestService.ParseDraft(bytes, root), root);
        WriteNew(options.Single("--output"), InputManifestService.Serialize(confirmed));
        return ExitCodes.Success;
    }

    private static int Validate(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 1 && IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        var options = CommandOptions.Parse(args, "--root", "--manifest");
        var bytes = BoundedIO.ReadAllBytes(
            options.Single("--manifest"),
            ResourceLimits.SerializedArtifactBytes,
            "confirmed input manifest");
        var manifest = InputManifestService.Parse(bytes);
        InputManifestService.Validate(manifest, Path.GetFullPath(options.Single("--root")), requireConfirmed: true);
        return ExitCodes.Success;
    }

    private static void WriteNew(string path, byte[] bytes)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetDirectoryName(fullPath)
            ?? throw new UsageException("Output path requires a parent directory.");
        Directory.CreateDirectory(root);
        AtomicFile.WriteNew(root, Path.GetFileName(fullPath), bytes);
    }

    private static bool IsHelp(string value) => value is "--help" or "-h";
}
