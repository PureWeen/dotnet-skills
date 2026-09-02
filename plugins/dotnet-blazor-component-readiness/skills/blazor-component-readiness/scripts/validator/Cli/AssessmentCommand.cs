using BlazorComponentReadiness.Validator.Assessment;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;

namespace BlazorComponentReadiness.Validator.Cli;

public static class AssessmentCommand
{
    private const string Help =
        """
        Canonical readiness assessments

        Usage:
          readiness-validator assessment init --kind <unified|package|component> --root <dir> --input <confirmed> --output <json> [--component <id>] [--overlays <id,id>]
          readiness-validator assessment validate --root <dir> --input <confirmed> --assessment <json> --evidence <bundle>
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
            "init" => Initialize(args.Skip(1).ToArray(), output),
            "validate" => Validate(args.Skip(1).ToArray(), output),
            _ => throw new UsageException($"Unknown assessment command '{args[0]}'.")
        };
    }

    private static int Initialize(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 1 && IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        var options = CommandOptions.Parse(
            args,
            "--kind",
            "--root",
            "--input",
            "--output",
            "--component",
            "--overlays");
        var root = Path.GetFullPath(options.Single("--root"));
        var inputBytes = BoundedIO.ReadAllBytes(
            options.Single("--input"),
            ResourceLimits.SerializedArtifactBytes,
            "confirmed input manifest");
        var input = InputManifestService.Parse(inputBytes);
        var overlays = ParseOverlays(options.Optional("--overlays"));
        var assessment = AssessmentService.Initialize(
            options.Single("--kind"),
            root,
            input,
            inputBytes,
            options.Optional("--component"),
            overlays);
        WriteNew(options.Single("--output"), AssessmentService.Serialize(assessment));
        return ExitCodes.Success;
    }

    private static int Validate(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 1 && IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        var options = CommandOptions.Parse(args, "--root", "--input", "--assessment", "--evidence");
        var root = Path.GetFullPath(options.Single("--root"));
        var inputBytes = BoundedIO.ReadAllBytes(
            options.Single("--input"),
            ResourceLimits.SerializedArtifactBytes,
            "confirmed input manifest");
        var input = InputManifestService.Parse(inputBytes);
        InputManifestService.Validate(input, root, requireConfirmed: true);
        var assessmentBytes = BoundedIO.ReadAllBytes(
            options.Single("--assessment"),
            ResourceLimits.SerializedArtifactBytes,
            "assessment");
        var assessment = AssessmentService.Parse(assessmentBytes);
        var evidence = CanonicalEvidenceJson.ParseBundle(BoundedIO.ReadAllBytes(
            options.Single("--evidence"),
            ResourceLimits.SerializedArtifactBytes,
            "evidence bundle"));
        AssessmentService.Validate(assessment, assessmentBytes, input, inputBytes, evidence);
        return ExitCodes.Success;
    }

    private static IReadOnlyList<string> ParseOverlays(string? value)
    {
        if (value is null)
        {
            return [];
        }

        var overlays = value.Split(',', StringSplitOptions.None);
        if (overlays.Any(string.IsNullOrWhiteSpace))
        {
            throw new UsageException("--overlays must be a comma-separated list without empty values.");
        }

        return overlays;
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
