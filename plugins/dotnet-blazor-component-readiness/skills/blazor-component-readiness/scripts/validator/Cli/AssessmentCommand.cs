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
          readiness-validator assessment init --kind <unified|package|component> --root <dir> --input <confirmed> --output <json> [--component <id>] [--overlays <id,id>] [--package-revision <dir>] [--package-feedback <markdown>]
          readiness-validator assessment validate --root <dir> --input <confirmed> --assessment <json> --evidence <bundle> [--package-revision <dir>] [--package-feedback <markdown>]
          readiness-validator assessment revise --root <dir> --input <confirmed> --assessment <replacement-json> --evidence <replacement-bundle> --output <revisions-root> --predecessor <digest> --changed-ids <id,id> [--feedback <markdown>] [--package-revision <dir>] [--package-feedback <markdown>]
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
            "revise" => Revise(args.Skip(1).ToArray(), output),
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
            "--overlays",
            "--package-revision",
            "--package-feedback");
        var root = Path.GetFullPath(options.Single("--root"));
        var inputBytes = BoundedIO.ReadAllBytes(
            options.Single("--input"),
            ResourceLimits.SerializedArtifactBytes,
            "confirmed input manifest");
        var input = InputManifestService.Parse(inputBytes);
        var overlays = ParseOverlays(options.Optional("--overlays"));
        var kind = options.Single("--kind");
        var packageBinding = LoadPackageBinding(
            root,
            kind,
            options.Optional("--package-revision"),
            options.Optional("--package-feedback"));
        var assessment = AssessmentService.Initialize(
            kind,
            root,
            input,
            inputBytes,
            options.Optional("--component"),
            overlays,
            packageBinding);
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

        var options = CommandOptions.Parse(
            args,
            "--root",
            "--input",
            "--assessment",
            "--evidence",
            "--package-revision",
            "--package-feedback");
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
        var packageBinding = LoadPackageBinding(
            root,
            assessment.AssessmentKind,
            options.Optional("--package-revision"),
            options.Optional("--package-feedback"));
        AssessmentService.Validate(
            assessment,
            assessmentBytes,
            input,
            inputBytes,
            evidence,
            packageBinding);
        return ExitCodes.Success;
    }

    private static int Revise(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 1 && IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        if (!args.Contains("--predecessor", StringComparer.Ordinal) ||
            !args.Contains("--changed-ids", StringComparer.Ordinal))
        {
            throw new UsageException(
                "assessment revise requires --predecessor and --changed-ids.");
        }

        return ReportCommand.Render(args, output);
    }

    private static PackageRevisionBinding? LoadPackageBinding(
        string root,
        string kind,
        string? packageRevision,
        string? packageFeedback)
    {
        if (string.Equals(kind, "component", StringComparison.OrdinalIgnoreCase))
        {
            if (packageRevision is null)
            {
                throw new DeterministicValidationException(
                    "Component assessment requires --package-revision.");
            }

            var feedbackBytes = packageFeedback is null
                ? null
                : BoundedIO.ReadAllBytes(
                    packageFeedback,
                    ResourceLimits.SerializedArtifactBytes,
                    "package assessment feedback");
            return RevisionService.LoadPackageBinding(
                root,
                Path.GetFullPath(packageRevision),
                feedbackBytes);
        }

        if (packageRevision is not null || packageFeedback is not null)
        {
            throw new DeterministicValidationException(
                "Only component assessments may specify package revision artifacts.");
        }

        return null;
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
