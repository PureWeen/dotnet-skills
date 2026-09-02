using BlazorComponentReadiness.Validator.Assessment;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Rendering;

namespace BlazorComponentReadiness.Validator.Cli;

public static class ReportCommand
{
    internal static Action? BeforePublishForTests { get; set; }

    private const string Help =
        """
        Deterministic readiness reports

        Usage:
          readiness-validator report render --root <input-root> --input <confirmed> --assessment <json> --evidence <bundle> --output <revisions-root> [--predecessor <digest>]
          readiness-validator report verify --root <input-root> --revision <0001-directory>
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
            "render" => Render(args.Skip(1).ToArray(), output),
            "verify" => Verify(args.Skip(1).ToArray(), output),
            _ => throw new UsageException($"Unknown report command '{args[0]}'.")
        };
    }

    private static int Render(IReadOnlyList<string> args, TextWriter output)
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
            "--output",
            "--predecessor");
        if (options.Optional("--predecessor") is not null)
        {
            throw new DeterministicValidationException("Revision 0001 cannot declare a predecessor.");
        }

        var root = Path.GetFullPath(options.Single("--root"));
        var inputPath = Path.GetFullPath(options.Single("--input"));
        var assessmentPath = Path.GetFullPath(options.Single("--assessment"));
        var evidencePath = Path.GetFullPath(options.Single("--evidence"));
        var inputSnapshot = ImmutableInputSnapshot.Capture(inputPath, "confirmed input manifest");
        var assessmentSnapshot = ImmutableInputSnapshot.Capture(assessmentPath, "assessment");
        var evidenceSnapshot = ImmutableInputSnapshot.Capture(evidencePath, "evidence bundle");
        var inputBytes = inputSnapshot.Bytes;
        var assessmentBytes = assessmentSnapshot.Bytes;
        var evidenceBytes = evidenceSnapshot.Bytes;
        var input = InputManifestService.Parse(inputBytes);
        InputManifestService.Validate(input, root, requireConfirmed: true);
        var referencedSnapshots = CaptureReferencedInputs(input, root);
        InputManifestService.Validate(input, root, requireConfirmed: true);
        var assessment = AssessmentService.Parse(assessmentBytes);
        var evidence = CanonicalEvidenceJson.ParseBundle(evidenceBytes);
        AssessmentService.Validate(assessment, assessmentBytes, input, inputBytes, evidence);
        var reportBytes = ReportService.RenderMarkdown(assessment, input, evidence);
        var manifestBytes = ReportService.SerializeManifest(
            ReportService.CreateManifest(
                assessment,
                assessmentBytes,
                input,
                inputBytes,
                evidence,
                evidenceBytes,
                reportBytes));
        var outputRoot = Path.GetFullPath(options.Single("--output"));
        AtomicDirectory.WriteNew(outputRoot, "0001", staging =>
        {
            File.WriteAllBytes(Path.Combine(staging, "input-manifest.json"), inputBytes);
            File.WriteAllBytes(Path.Combine(staging, $"{assessment.AssessmentKind}.assessment.json"), assessmentBytes);
            File.WriteAllBytes(Path.Combine(staging, $"{assessment.AssessmentKind}.evidence.json"), evidenceBytes);
            File.WriteAllBytes(Path.Combine(staging, $"{assessment.AssessmentKind}.report.md"), reportBytes);
            File.WriteAllBytes(Path.Combine(staging, $"{assessment.AssessmentKind}.validation.json"), manifestBytes);
            BeforePublishForTests?.Invoke();
            InputManifestService.Validate(input, root, requireConfirmed: true);
            inputSnapshot.EnsureUnchanged();
            assessmentSnapshot.EnsureUnchanged();
            evidenceSnapshot.EnsureUnchanged();
            foreach (var snapshot in referencedSnapshots)
            {
                snapshot.EnsureUnchanged();
            }
        });
        return ExitCodes.Success;
    }

    private static int Verify(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 1 && IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        var options = CommandOptions.Parse(args, "--root", "--revision");
        var root = Path.GetFullPath(options.Single("--root"));
        var revision = Path.GetFullPath(options.Single("--revision"));
        if (Path.GetFileName(revision) != "0001")
        {
            throw new DeterministicValidationException("Commit 4 verifies only initial revision 0001.");
        }

        var validationFiles = Directory.GetFiles(revision, "*.validation.json", SearchOption.TopDirectoryOnly);
        if (validationFiles.Length != 1)
        {
            throw new DeterministicValidationException("Revision requires exactly one validation manifest.");
        }

        var kind = Path.GetFileName(validationFiles[0]).Split('.')[0];
        var inputBytes = Read(Path.Combine(revision, "input-manifest.json"), "input manifest snapshot");
        var assessmentBytes = Read(Path.Combine(revision, $"{kind}.assessment.json"), "assessment snapshot");
        var evidenceBytes = Read(Path.Combine(revision, $"{kind}.evidence.json"), "evidence snapshot");
        var reportBytes = Read(Path.Combine(revision, $"{kind}.report.md"), "report");
        var manifestBytes = Read(validationFiles[0], "validation manifest");
        var input = InputManifestService.Parse(inputBytes);
        InputManifestService.Validate(input, root, requireConfirmed: true);
        var assessment = AssessmentService.Parse(assessmentBytes);
        var evidence = CanonicalEvidenceJson.ParseBundle(evidenceBytes);
        AssessmentService.Validate(assessment, assessmentBytes, input, inputBytes, evidence);
        var expectedReport = ReportService.RenderMarkdown(assessment, input, evidence);
        if (!reportBytes.AsSpan().SequenceEqual(expectedReport))
        {
            throw new DeterministicValidationException(
                "Rendered report differs by one or more bytes or contains extra bytes.");
        }

        var actualManifest = ReportService.ParseManifest(manifestBytes);
        var expectedManifest = ReportService.CreateManifest(
            assessment,
            assessmentBytes,
            input,
            inputBytes,
            evidence,
            evidenceBytes,
            reportBytes);
        ReportService.ValidateManifest(actualManifest, expectedManifest);
        return ExitCodes.Success;
    }

    private static byte[] Read(string path, string resource) =>
        BoundedIO.ReadAllBytes(path, ResourceLimits.SerializedArtifactBytes, resource);

    private static IReadOnlyList<ImmutableInputSnapshot> CaptureReferencedInputs(
        InputManifest input,
        string root)
    {
        var snapshots = new List<ImmutableInputSnapshot>
        {
            ImmutableInputSnapshot.Capture(
                SafePath.ResolveUnderRoot(
                    root,
                    input.Package.NupkgPath,
                    requireExisting: true,
                    requireFile: true),
                ResourceLimits.NupkgBytes,
                "referenced nupkg")
        };
        snapshots.AddRange(input.Documentation.Select(document =>
            ImmutableInputSnapshot.Capture(
                SafePath.ResolveUnderRoot(
                    root,
                    document.ContentPath,
                    requireExisting: true,
                    requireFile: true),
                ResourceLimits.SupplementalInputAggregateBytes,
                $"referenced documentation '{document.ContentPath}'")));
        snapshots.AddRange(input.PackageSources.Select(source =>
            ImmutableInputSnapshot.Capture(
                SafePath.ResolveUnderRoot(
                    root,
                    source.ContentPath,
                    requireExisting: true,
                    requireFile: true),
                ResourceLimits.SupplementalInputAggregateBytes,
                $"referenced package source '{source.ContentPath}'")));
        snapshots.AddRange(input.OwnerInputs.Select(owner =>
            ImmutableInputSnapshot.Capture(
                SafePath.ResolveUnderRoot(
                    root,
                    owner.Basename,
                    requireExisting: true,
                    requireFile: true),
                ResourceLimits.SupplementalInputAggregateBytes,
                $"referenced owner input '{owner.Basename}'")));
        return snapshots
            .GroupBy(snapshot => snapshot.Path, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToArray();
    }

    private static bool IsHelp(string value) => value is "--help" or "-h";
}
