using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Rendering;

namespace BlazorComponentReadiness.Validator.Assessment;

public sealed record RevisionArtifacts(
    string Directory,
    string Kind,
    InputManifest Input,
    byte[] InputBytes,
    ReadinessAssessment Assessment,
    byte[] AssessmentBytes,
    EvidenceBundle Evidence,
    byte[] EvidenceBytes,
    byte[] ReportBytes,
    ValidationManifest Manifest,
    byte[] ManifestBytes);

public sealed record PackageRevisionBinding(
    InputManifest Input,
    ReadinessAssessment Assessment,
    ValidationManifest Manifest,
    PackageAssessmentReference Reference);

public static class RevisionService
{
    public static PackageRevisionBinding LoadPackageBinding(
        string root,
        string revisionDirectory,
        byte[]? feedbackBytes)
    {
        var revision = VerifyRevision(
            root,
            revisionDirectory,
            feedbackBytes,
            packageBinding: null,
            validateChain: true,
            allowMissingFeedback: false);
        if (revision.Kind != "package" ||
            revision.Assessment.CompletionState != "complete" ||
            revision.Manifest.CompletionState != "complete")
        {
            throw new DeterministicValidationException(
                "Package binding requires a complete validated package assessment revision.");
        }

        var reference = new PackageAssessmentReference(
            revision.Assessment.Identity.Package,
            revision.Manifest.InputManifestDigest,
            revision.Manifest.AssessmentDigest,
            revision.Manifest.ReportDigest,
            ContractJson.RawDigest(revision.ManifestBytes));
        return new PackageRevisionBinding(
            revision.Input,
            revision.Assessment,
            revision.Manifest,
            reference);
    }

    public static RevisionArtifacts VerifyRevision(
        string root,
        string revisionDirectory,
        byte[]? feedbackBytes,
        PackageRevisionBinding? packageBinding,
        bool validateChain,
        bool allowMissingFeedback = false)
    {
        var revision = Path.GetFullPath(revisionDirectory);
        var sequence = ParseSequence(revision);
        var validationFiles = Directory.GetFiles(
            revision,
            "*.validation.json",
            SearchOption.TopDirectoryOnly);
        if (validationFiles.Length != 1)
        {
            throw new DeterministicValidationException(
                "Revision requires exactly one validation manifest.");
        }

        var kind = Path.GetFileName(validationFiles[0]).Split('.')[0];
        if (kind is not ("unified" or "package" or "component"))
        {
            throw new DeterministicValidationException("Revision validation filename has an invalid assessment kind.");
        }

        var expectedFiles = new HashSet<string>(StringComparer.Ordinal)
        {
            "input-manifest.json",
            $"{kind}.assessment.json",
            $"{kind}.evidence.json",
            $"{kind}.report.md",
            $"{kind}.validation.json"
        };
        var actualFiles = Directory.GetFiles(revision, "*", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName)
            .ToHashSet(StringComparer.Ordinal);
        if (!actualFiles.SetEquals(expectedFiles) ||
            Directory.GetDirectories(revision, "*", SearchOption.TopDirectoryOnly).Length != 0)
        {
            throw new DeterministicValidationException(
                "Immutable revisions contain exactly the input, assessment, evidence, report, and validation artifacts.");
        }

        var inputBytes = Read(Path.Combine(revision, "input-manifest.json"), "input manifest snapshot");
        var assessmentBytes = Read(
            Path.Combine(revision, $"{kind}.assessment.json"),
            "assessment snapshot");
        var evidenceBytes = Read(
            Path.Combine(revision, $"{kind}.evidence.json"),
            "evidence snapshot");
        var reportBytes = Read(Path.Combine(revision, $"{kind}.report.md"), "report");
        var manifestBytes = Read(validationFiles[0], "validation manifest");
        var input = InputManifestService.Parse(inputBytes);
        InputManifestService.Validate(input, root, requireConfirmed: true);
        var assessment = AssessmentService.Parse(assessmentBytes);
        var evidence = CanonicalEvidenceJson.ParseBundle(evidenceBytes);
        var manifest = ReportService.ParseManifest(manifestBytes);
        AssessmentService.Validate(
            assessment,
            assessmentBytes,
            input,
            inputBytes,
            evidence,
            packageBinding);
        if (assessment.AssessmentKind != kind || manifest.AssessmentKind != kind)
        {
            throw new DeterministicValidationException(
                "Revision filenames, assessment kind, and validation manifest kind must match.");
        }

        AssessmentFeedback? feedback = null;
        if (manifest.FeedbackDigest is null)
        {
            if (feedbackBytes is not null)
            {
                throw new DeterministicValidationException(
                    "Revision does not bind an assessment feedback file.");
            }
        }
        else if (feedbackBytes is null)
        {
            if (!allowMissingFeedback)
            {
                throw new DeterministicValidationException(
                    "Revision verification requires the exact bound assessment feedback file.");
            }
        }
        else
        {
            feedback = FeedbackService.Parse(feedbackBytes, assessment);
            if (feedback.Digest != manifest.FeedbackDigest)
            {
                throw new DeterministicValidationException(
                    "Assessment feedback bytes differ from the validation-manifest digest.");
            }
        }

        if (ContractJson.RawDigest(reportBytes) != manifest.ReportDigest)
        {
            throw new DeterministicValidationException(
                "Rendered report bytes differ from the validation-manifest digest.");
        }

        if (manifest.FeedbackDigest is null || feedback is not null)
        {
            var expectedReport = ReportService.RenderMarkdown(assessment, input, evidence, feedback);
            if (!reportBytes.AsSpan().SequenceEqual(expectedReport))
            {
                throw new DeterministicValidationException(
                    "Rendered report differs by one or more bytes or contains extra bytes.");
            }
        }

        var expectedManifest = ReportService.CreateManifest(
            assessment,
            assessmentBytes,
            input,
            inputBytes,
            evidence,
            evidenceBytes,
            reportBytes,
            manifest.PredecessorManifestDigest,
            manifest.FeedbackDigest,
            manifest.DeclaredChangedIds);
        ReportService.ValidateManifest(manifest, expectedManifest);

        if (sequence == 1)
        {
            if (manifest.PredecessorManifestDigest is not null ||
                manifest.DeclaredChangedIds.Count != 0)
            {
                throw new DeterministicValidationException(
                    "Revision 0001 cannot declare a predecessor or changed requirement IDs.");
            }
        }
        else if (manifest.PredecessorManifestDigest is null)
        {
            throw new DeterministicValidationException(
                "Every revision after 0001 requires the immediate predecessor manifest digest.");
        }

        var artifacts = new RevisionArtifacts(
            revision,
            kind,
            input,
            inputBytes,
            assessment,
            assessmentBytes,
            evidence,
            evidenceBytes,
            reportBytes,
            manifest,
            manifestBytes);
        if (!validateChain || sequence == 1)
        {
            return artifacts;
        }

        var predecessorDirectory = Path.Combine(
            Path.GetDirectoryName(revision)!,
            (sequence - 1).ToString("D4", System.Globalization.CultureInfo.InvariantCulture));
        if (!Directory.Exists(predecessorDirectory))
        {
            throw new DeterministicValidationException(
                "Revision chain has a missing or skipped immediate predecessor.");
        }

        var predecessor = VerifyRevision(
            root,
            predecessorDirectory,
            feedbackBytes: null,
            packageBinding,
            validateChain: true,
            allowMissingFeedback: true);
        if (ContractJson.RawDigest(predecessor.ManifestBytes) != manifest.PredecessorManifestDigest)
        {
            throw new DeterministicValidationException(
                "Revision predecessor digest does not name the immediate preceding manifest.");
        }

        ValidateChainIdentity(predecessor, artifacts);
        if (manifest.DeclaredChangedIds.Count == 0)
        {
            if (!inputBytes.AsSpan().SequenceEqual(predecessor.InputBytes) ||
                !assessmentBytes.AsSpan().SequenceEqual(predecessor.AssessmentBytes) ||
                !evidenceBytes.AsSpan().SequenceEqual(predecessor.EvidenceBytes))
            {
                throw new DeterministicValidationException(
                    "Feedback-only revisions must preserve input, assessment, and evidence bytes exactly.");
            }
        }
        else
        {
            ValidateCorrection(predecessor, artifacts, manifest.DeclaredChangedIds);
        }

        return artifacts;
    }

    public static void ValidateCorrection(
        RevisionArtifacts predecessor,
        RevisionArtifacts replacement,
        IReadOnlyList<string> declaredChangedIds)
    {
        var declared = declaredChangedIds
            .Select(id => ContractJson.NormalizeText(id, "declared changed ID", 64))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (declared.Length == 0 ||
            !declared.SequenceEqual(declaredChangedIds, StringComparer.Ordinal) ||
            declared.Any(id => !replacement.Assessment.SelectedIds.Contains(id, StringComparer.Ordinal)))
        {
            throw new DeterministicValidationException(
                "Evidence-backed corrections require nonempty, selected, unique, canonically sorted changed IDs.");
        }

        ValidateChainIdentity(predecessor, replacement);
        if (!predecessor.InputBytes.AsSpan().SequenceEqual(replacement.InputBytes))
        {
            throw new DeterministicValidationException(
                "Assessment corrections cannot change confirmed input-manifest bytes.");
        }

        var actual = predecessor.Assessment.Rows.Zip(
                replacement.Assessment.Rows,
                (before, after) => new
                {
                    before.Id,
                    Changed = !AssessmentService.SerializeRow(before)
                        .AsSpan()
                        .SequenceEqual(AssessmentService.SerializeRow(after))
                })
            .Where(item => item.Changed)
            .Select(item => item.Id)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (actual.Length == 0 || !actual.SequenceEqual(declared, StringComparer.Ordinal))
        {
            throw new DeterministicValidationException(
                "Declared changed IDs must exactly equal the actual canonical assessment-row changes.");
        }

        var beforeRows = predecessor.Assessment.Rows.ToDictionary(row => row.Id, StringComparer.Ordinal);
        var afterRows = replacement.Assessment.Rows.ToDictionary(row => row.Id, StringComparer.Ordinal);
        foreach (var id in declared)
        {
            var before = beforeRows[id];
            var after = afterRows[id];
            if (before.Status != after.Status &&
                !after.EvidenceIds.Except(before.EvidenceIds, StringComparer.Ordinal).Any())
            {
                throw new DeterministicValidationException(
                    $"Status change for '{id}' requires added or changed evidence that explains the correction.");
            }
        }

        var beforeRecords = Records(predecessor.Evidence);
        var afterRecords = Records(replacement.Evidence);
        foreach (var selection in predecessor.Evidence.Selection)
        {
            if (!replacement.Evidence.Selection.Any(
                    item => item.EvidenceId == selection.EvidenceId) ||
                !afterRecords.TryGetValue(selection.EvidenceId, out var afterRecord) ||
                !SameRecord(beforeRecords[selection.EvidenceId], afterRecord))
            {
                throw new DeterministicValidationException(
                    "Assessment corrections cannot remove or mutate previously selected evidence.");
            }
        }
    }

    public static int ParseSequence(string revisionDirectory)
    {
        var name = Path.GetFileName(Path.TrimEndingDirectorySeparator(revisionDirectory));
        if (name.Length != 4 ||
            !int.TryParse(
                name,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var sequence) ||
            sequence < 1)
        {
            throw new DeterministicValidationException(
                "Revision directory names must be positive zero-padded four-digit sequences.");
        }

        return sequence;
    }

    private static void ValidateChainIdentity(
        RevisionArtifacts predecessor,
        RevisionArtifacts replacement)
    {
        var before = predecessor.Assessment;
        var after = replacement.Assessment;
        if (predecessor.Kind != replacement.Kind ||
            before.Identity != after.Identity ||
            before.RubricVersion != after.RubricVersion ||
            before.ScopeSchemaVersion != after.ScopeSchemaVersion ||
            before.RubricDigest != after.RubricDigest ||
            before.ScopeMapDigest != after.ScopeMapDigest ||
            !before.Overlays.SequenceEqual(after.Overlays) ||
            !before.SelectedIds.SequenceEqual(after.SelectedIds, StringComparer.Ordinal) ||
            before.PackageReference != after.PackageReference)
        {
            throw new DeterministicValidationException(
                "Revision chain assessment identity, package, rubric, scope, or overlays drifted.");
        }
    }

    private static Dictionary<string, EvidenceRecord> Records(EvidenceBundle bundle) =>
        bundle.SourceLedgers.SelectMany(source => source.Ledger.Records)
            .ToDictionary(record => record.StableId, StringComparer.Ordinal);

    private static bool SameRecord(EvidenceRecord before, EvidenceRecord after) =>
        before.StableId == after.StableId &&
        before.Claim == after.Claim &&
        before.Applicability == after.Applicability &&
        before.Provenance == after.Provenance &&
        before.Supersedes.SequenceEqual(after.Supersedes, StringComparer.Ordinal);

    private static byte[] Read(string path, string resource) =>
        BoundedIO.ReadAllBytes(path, ResourceLimits.SerializedArtifactBytes, resource);
}
