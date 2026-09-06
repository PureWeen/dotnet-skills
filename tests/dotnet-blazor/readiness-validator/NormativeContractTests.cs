using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BlazorComponentReadiness.Validator.Assessment;
using BlazorComponentReadiness.Validator.Cli;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Rendering;
using BlazorComponentReadiness.Validator.Validation;

internal static class NormativeContractTests
{
    public static void Run(string repositoryRoot, string pluginRoot)
    {
        var root = Path.Combine(
            Environment.GetEnvironmentVariable("READINESS_TEST_ARTIFACTS") ?? Path.Combine(repositoryRoot, "artifacts"),
            "readiness-normative-tests");
        Directory.CreateDirectory(root);
        var skillRoot = Path.Combine(pluginRoot, "skills", "blazor-component-readiness");
        var previous = Environment.GetEnvironmentVariable("READINESS_SKILL_ROOT");
        Environment.SetEnvironmentVariable("READINESS_SKILL_ROOT", skillRoot);
        try
        {
            TestInventoryAndBasis(skillRoot);
            TestCrosswalkTampering(root, skillRoot);
            var fixture = AssessmentTests.CreateInputFixture(root);
            TestConditionalInventory(fixture);
            TestSharedSecurityEvidence(fixture);
            TestLegacyFeedback(fixture);
            TestQuietCurrentCli(fixture);
        }
        finally
        {
            Environment.SetEnvironmentVariable("READINESS_SKILL_ROOT", previous);
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestInventoryAndBasis(string skillRoot)
    {
        var rubric = RubricLoader.Load();
        Assert(rubric.RubricVersion == "2.0.0", "new initialization defaults to normative v2");
        Assert(rubric.CoreRequirements.Count == 121, "121 canonical rows");
        var package = RubricLoader.Select(rubric, "package", []);
        var component = RubricLoader.Select(rubric, "component", []);
        Assert(package.Count == 60 && component.Count == 61, "60/61 ownership partition");
        var expectedIds = new[] {
            ("LP", 10), ("PI", 12), ("SEC", 13), ("A11Y", 12), ("BEQ", 24),
            ("TA", 7), ("PERF", 10), ("CI", 11), ("SUP", 10), ("SCF", 6), ("AI", 6)
        }.SelectMany(group => Enumerable.Range(1, group.Item2).Select(n => $"{group.Item1}-{n:00}")).ToArray();
        Assert(rubric.CoreRequirements.Select(row => row.Id).SequenceEqual(expectedIds), "canonical IDs and order");
        Assert(package.Concat(component).Select(row => row.Id).Distinct().Count() == 121, "exactly once across split");
        Assert(rubric.Overlays.Count == 0, "conditional rows are not optional overlays");
        Assert(rubric.Extensions is [{ Id: "TA-08", Basis.RequiresPolicyApproval: true }], "TA-08 outside canonical inventory");
        Assert(rubric.CoreRequirements.All(row => row.Basis is { Quotation.Length: > 20 }), "all121 exact quotation bindings");
        Assert(rubric.CoreRequirements.All(row => row.Basis!.SemanticScope == row.Scope), "one scope axis for all canonical rows");
        Assert(rubric.CoreRequirements.Count(row => row.Basis?.ConditionalFamily is not null) == 12, "12 explicit conditional IDs");
        var rows = rubric.CoreRequirements.ToDictionary(row => row.Id);
        Assert(rows["SUP-10"].Requirement == "Microsoft may stop promoting a partner library if it no longer adheres to these requirements.",
            "SUP-10 Microsoft removal discretion, not vendor suspension");
        foreach (var id in new[] { "SEC-01", "SEC-02", "SEC-03" })
        {
            Assert(rows[id].Scope == "repository-wide" &&
                rows[id].Basis is { SemanticScope: "repository-wide", SharedActionKey: "library-security-review" },
                "library threat evidence belongs to the package with one shared action");
        }

        foreach (var (id, term) in new[] {
            ("A11Y-03", "Accessibility Insights"), ("A11Y-03", "FastPass"),
            ("A11Y-04", "Assessment"), ("A11Y-05", "NVDA, JAWS, or Windows Narrator"),
            ("BEQ-09", "BL0007"), ("BEQ-15", "JSDisconnectedException"),
            ("BEQ-17", ".razor.js"), ("BEQ-20", ".razor.css"),
            ("BEQ-21", "no new"), ("BEQ-24", "one minor version"),
            ("TA-01", "IsTrimmable"), ("TA-05", "AOT"), ("LP-10", "Every packaged binary")
        })
        {
            Assert(rows[id].Requirement.Contains(term, StringComparison.Ordinal), $"named obligation {id}: {term}");
        }

        foreach (var id in new[] { "PI-04", "PI-10", "PI-11", "PI-12", "CI-01", "CI-02", "CI-03",
            "CI-04", "CI-05", "CI-06", "CI-07", "CI-08", "CI-09", "CI-10", "PERF-07", "PERF-08", "PERF-09", "PERF-10", "SUP-05" })
        {
            Assert(rows[id].Basis is { Classification: "versioned extension", RequiresPolicyApproval: true, ExtensionBasis.Length: > 20 },
                $"{id} retains canonical slot without becoming a DOCX defect");
        }

        Assert(rubric.CrosswalkDigest?.Value == "15fab7fb82f9ad30fb7a57d3f915afb9e93f281d0e5845ab17a95eb87cb79470",
            "frozen crosswalk digest");
        var checklist = File.ReadAllText(Path.Combine(skillRoot, "references", "checklist.md"));
        var listedIds = Regex.Matches(checklist, @"(?m)^\| ([A-Z0-9]+-\d{2}) \|")
            .Select(match => match.Groups[1].Value);
        Assert(listedIds.SequenceEqual(expectedIds), "human checklist exact121 inventory");
        var legacy = RubricLoader.Load("1.3.0");
        Assert(legacy.RubricDigest.Value == "6a36fc581af3a2710fec3a70a484c7dc751cdf2c248dcd98e49ce4bb9cf8c49f",
            "legacy raw bytes unchanged");
        Assert(legacy.CoreRequirements.Count == 110 && legacy.CoreRequirements.All(row => row.Basis is null),
            "legacy meanings do not inherit normative metadata");
        Assert(legacy.CoreRequirements.Single(row => row.Id == "SUP-10").Requirement.Contains("suspend a release"),
            "legacy SUP-10 remains frozen, not rewritten retroactively");
        Assert(RubricLoader.Select(legacy, "unified", ["scaffolder"]).Count == 116, "legacy selected-overlay behavior");
        Reject(() => RubricLoader.Load("9.9.9"), "unknown rubric version");
        Reject(() => RubricLoader.Select(rubric, "unified", ["scaffolder"]), "new overlay selection cannot alter inventory");
    }

    private static void TestCrosswalkTampering(string root, string skillRoot)
    {
        var copy = Path.Combine(root, "tampered-skill");
        Directory.CreateDirectory(Path.Combine(copy, "references"));
        File.WriteAllText(Path.Combine(copy, "SKILL.md"), "# Test skill root");
        foreach (var name in new[] { "rubric.json", "rubric.v1.3.0.json", "docx-crosswalk.json" })
        {
            File.Copy(Path.Combine(skillRoot, "references", name), Path.Combine(copy, "references", name));
        }

        Environment.SetEnvironmentVariable("READINESS_SKILL_ROOT", copy);
        try
        {
            var crosswalk = Path.Combine(copy, "references", "docx-crosswalk.json");
            File.AppendAllText(crosswalk, "\n");
            Reject(() => RubricLoader.Load(), "even whitespace changes crosswalk digest");
            Assert(RubricLoader.Load("1.3.0").CoreRequirements.Count == 110, "legacy verification independent of normative crosswalk");
            File.Copy(Path.Combine(skillRoot, "references", "docx-crosswalk.json"), crosswalk, overwrite: true);
            var rubric = Path.Combine(copy, "references", "rubric.json");
            File.WriteAllText(rubric, File.ReadAllText(rubric).Replace("versioned extension", "direct obligation", StringComparison.Ordinal));
            Reject(() => RubricLoader.Load(), "extension relabeling rejected");
        }
        finally
        {
            Environment.SetEnvironmentVariable("READINESS_SKILL_ROOT", skillRoot);
        }
    }

    private static void TestConditionalInventory(AssessmentTests.Fixture fixture)
    {
        foreach (var kind in new[] { "unified", "package" })
        {
            var initialized = AssessmentService.Initialize(kind, fixture.Root, fixture.Confirmed,
                fixture.ConfirmedBytes, kind == "unified" ? "fancy-tree" : null, []);
            Assert(initialized.Rows.Count == (kind == "package" ? 60 : 121), "current init includes all conditional rows");
            var assessment = CompleteNotTested(initialized, scaffolderInScope: false);
            var evidence = RetainedEvidence(assessment);
            Validate(fixture, assessment, evidence);
            var conditionalIds = initialized.Rows.Where(IsConditional).Select(row => row.Id).ToHashSet();
            Assert(assessment.Rows.Where(IsConditional).All(row => row.Status == "not applicable" &&
                row.NotApplicableRationale is { Length: > 12 }), "library-only conditional NAs remain explicit");
            var missing = assessment with {
                Rows = assessment.Rows.Where(row => !conditionalIds.Contains(row.Id)).ToArray(),
                SelectedIds = assessment.SelectedIds.Where(id => !conditionalIds.Contains(id)).ToArray()
            };
            Reject(() => Validate(fixture, missing, evidence), "omission cannot count as completion");
            var noRationale = assessment with {
                Rows = assessment.Rows.Select(row => IsConditional(row) ? row with { NotApplicableRationale = null } : row).ToArray()
            };
            Reject(() => Validate(fixture, noRationale, evidence), "each conditional NA requires rationale");
            var unassessed = assessment with {
                Rows = assessment.Rows.Select(row => IsConditional(row)
                    ? row with { Status = null, NotApplicableRationale = null } : row).ToArray()
            };
            Reject(() => Validate(fixture, unassessed, evidence), "conditional placeholders cannot claim complete");
            var inScope = CompleteNotTested(initialized, scaffolderInScope: true);
            Validate(fixture, inScope, evidence);
            Assert(inScope.Rows.Where(row => row.Id.StartsWith("SCF-")).All(row => row.Status == "not tested"),
                "in-scope scaffolders assessed explicitly rather than excluded");
            Reject(() => Validate(fixture, assessment with { SchemaVersion = 1 }, evidence),
                "new normative contract cannot downgrade evidence protocols");
            var bytes = AssessmentService.Serialize(assessment);
            Assert(bytes.SequenceEqual(AssessmentService.Serialize(AssessmentService.Parse(bytes))), "strict current serialization roundtrip");
        }
    }

    private static void TestSharedSecurityEvidence(AssessmentTests.Fixture fixture)
    {
        var package = CompleteNotTested(AssessmentService.Initialize("package", fixture.Root, fixture.Confirmed,
            fixture.ConfirmedBytes, null, []), false);
        var evidence = RetainedEvidence(package);
        Validate(fixture, package, evidence);
        var assessmentBytes = AssessmentService.Serialize(package);
        var report = ReportService.RenderMarkdown(package, fixture.Confirmed, evidence);
        var manifest = ReportService.CreateManifest(package, assessmentBytes, fixture.Confirmed, fixture.ConfirmedBytes,
            evidence, CanonicalEvidenceJson.SerializeBundle(evidence), report, null, null, []);
        var reference = new PackageAssessmentReference(package.Identity.Package, manifest.InputManifestDigest,
            manifest.AssessmentDigest, manifest.ReportDigest, ContractJson.RawDigest(ReportService.SerializeManifest(manifest)));
        var binding = new PackageRevisionBinding(fixture.Confirmed, package, manifest, reference);
        var component = CompleteNotTested(AssessmentService.Initialize("component", fixture.Root, fixture.Confirmed,
            fixture.ConfirmedBytes, "fancy-tree", [], binding), false);
        Validate(fixture, component, RetainedEvidence(component), binding);
        Assert(component.Rows.Count == 61 &&
            component.Rows.All(row => row.Id is not ("SEC-01" or "SEC-02" or "SEC-03")),
            "component assessment has no duplicate or pointer rows for package security");
        Assert(new[] { "SEC-10", "SEC-11", "SEC-12", "SEC-13" }
            .All(id => component.Rows.Any(row => row.Id == id)), "render-mode and component behavior security stays component-owned");
        var record = new EvidenceRecordDraft(
            "One exact-package library security-review packet supports the three library-wide conclusions.",
            new EvidenceApplicability("repository-wide", null),
            new EvidenceProvenance(EvidenceIdentity.ReproducedRuntimeObservation, "probe://security/library-review",
                "Bounded shared package security packet review.", "2026-09-04T12:00:00Z",
                new Sha256Digest("sha256", new string('c', 64)), "commitment-only"), []);
        var ledger = EvidenceLedgerBuilder.BuildRepositoryLedger(
            new RepositoryLedgerSubject("package", package.Identity.Package, package.Identity.InputManifestDigest, null), [record]);
        var bundle = EvidenceLedgerBuilder.BuildBundle(package.Identity, [ledger], [ledger.Records[0].StableId]);
        var sharedPacketAssessment = package with {
            Rows = package.Rows.Select(row => row.Id is "SEC-01" or "SEC-02" or "SEC-03" ? row with {
                Status = "gap", Observation = "The shared exact-package security packet records a library-level documentation gap.",
                EvidenceIds = [ledger.Records[0].StableId]
            } : row with { EvidenceIds = [] }).ToArray()
        };
        sharedPacketAssessment = sharedPacketAssessment with {
            SummaryGroups = PackageSummaries(sharedPacketAssessment.RubricVersion, sharedPacketAssessment.Rows)
        };
        Validate(fixture, sharedPacketAssessment, bundle);
        Assert(sharedPacketAssessment.Rows.Count(row => row.EvidenceIds.Contains(ledger.Records[0].StableId)) == 3,
            "one library packet supports all three conclusions without duplicated evidence");
        Assert(RubricLoader.Load().CoreRequirements.Where(row => row.Id is "SEC-01" or "SEC-02" or "SEC-03")
            .Select(row => row.Basis!.SharedActionKey).Distinct().Single() == "library-security-review",
            "three package conclusions share one action, not three component threat requests");
    }

    private static void TestQuietCurrentCli(AssessmentTests.Fixture fixture)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var path = Path.Combine(fixture.Root, "current.assessment.json");
        Assert(CliApplication.Run(["assessment", "init", "--kind", "package", "--root", fixture.Root,
            "--input", fixture.ConfirmedPath, "--output", path], output, error) == ExitCodes.Success,
            $"current CLI initializes: {error}");
        Assert(output.ToString().Length == 0 && error.ToString().Length == 0, "current CLI remains quiet");
        var initialized = AssessmentService.Parse(File.ReadAllBytes(path));
        Assert(initialized.Rows.Count == 60, "CLI defaults to normative package inventory");
        var completed = CompleteNotTested(initialized, false);
        File.WriteAllBytes(path, AssessmentService.Serialize(completed));
        var evidencePath = Path.Combine(fixture.Root, "current.evidence.json");
        File.WriteAllBytes(evidencePath, CanonicalEvidenceJson.SerializeBundle(RetainedEvidence(completed)));
        var revisions = Path.Combine(fixture.Root, "current-revisions");
        Assert(CliApplication.Run(["report", "render", "--root", fixture.Root, "--input", fixture.ConfirmedPath,
            "--assessment", path, "--evidence", evidencePath, "--output", revisions], output, error) == ExitCodes.Success,
            $"current immutable revision renders: {error}");
        Assert(CliApplication.Run(["report", "verify", "--root", fixture.Root, "--revision", Path.Combine(revisions, "0001")],
            output, error) == ExitCodes.Success, $"current immutable revision verifies: {error}");
        Assert(output.ToString().Length == 0 && error.ToString().Length == 0, "current render/verify remain quiet");
    }

    private static void TestLegacyFeedback(AssessmentTests.Fixture fixture)
    {
        var legacy = CompleteNotTested(AssessmentService.Initialize("package", fixture.Root,
            fixture.Confirmed, fixture.ConfirmedBytes, null, [], rubricVersion: RubricLoader.LegacyVersion), false);
        var bytes = AssessmentService.Serialize(legacy);
        Validate(fixture, legacy, RetainedEvidence(legacy));
        var feedbackBytes = Encoding.UTF8.GetBytes(
            "# Assessment feedback\n\n| Requirement IDs | Feedback |\n|---|---|\n" +
            "| `TA-08` | Keep historical TA-08 feedback byte-for-byte. |\n");
        var feedback = FeedbackService.Parse(feedbackBytes, legacy);
        Assert(feedback.Entries.Single().RawPayload == " Keep historical TA-08 feedback byte-for-byte. ",
            "legacy feedback payload preserved exactly");
        Assert(feedback.Digest == ContractJson.RawDigest(feedbackBytes), "legacy raw feedback hash preserved");
        _ = RubricLoader.Load();
        Assert(bytes.SequenceEqual(AssessmentService.Serialize(AssessmentService.Parse(bytes))),
            "loading current rubric never rewrites legacy assessment bytes");
        var current = AssessmentService.Initialize("package", fixture.Root, fixture.Confirmed,
            fixture.ConfirmedBytes, null, []);
        Reject(() => FeedbackService.Parse(feedbackBytes, current),
            "legacy supplementary feedback cannot silently attach to a different canonical contract");
    }

    private static bool IsConditional(AssessmentRow row) => row.Id.StartsWith("SCF-") || row.Id.StartsWith("AI-");

    private static ReadinessAssessment CompleteNotTested(ReadinessAssessment assessment, bool scaffolderInScope)
    {
        var evidenceId = RetainedEvidence(assessment).Selection.Single().EvidenceId;
        var evidenceRow = assessment.AssessmentKind == "component" ? "SEC-10" : "LP-01";
        var rows = assessment.Rows.Select(row =>
            IsConditional(row) && !(scaffolderInScope && row.Id.StartsWith("SCF-"))
                ? row with { Status = "not applicable", NotApplicableRationale =
                    row.Id.StartsWith("SCF-") ? "Scope decision: this deliverable contains no promoted scaffolder; repository templates are not in scope."
                        : "Scope decision: this library deliverable contains no partner AI skill." }
                : row with { Status = "not tested", AssessmentFollowUp = "Run a bounded validation against the exact released package.",
                    EvidenceIds = row.Id == evidenceRow ? [evidenceId] : [] }).ToArray();
        return assessment with {
            Rows = rows, CompletionState = "complete",
            SummaryGroups = assessment.AssessmentKind != "package" ? [] : PackageSummaries(assessment.RubricVersion, rows)
        };
    }

    private static IReadOnlyList<AssessmentSummaryGroup> PackageSummaries(string rubricVersion, IReadOnlyList<AssessmentRow> rows) =>
        RubricLoader.Load(rubricVersion).Statuses
            .Where(status => rows.Any(row => row.Status == status))
            .Select(status => new AssessmentSummaryGroup(status,
                $"These rows retain the explicit assessment conclusion '{status}'.",
                rows.Where(row => row.Status == status).Select(row => row.Id).ToArray(),
                rows.Where(row => row.Status == status).SelectMany(row => row.EvidenceIds).Distinct().Order().ToArray())).ToArray();

    private static EvidenceBundle RetainedEvidence(ReadinessAssessment assessment) => AssessmentTests.BuildEvidence(assessment.Identity);
    private static void Validate(AssessmentTests.Fixture fixture, ReadinessAssessment assessment,
        EvidenceBundle evidence, PackageRevisionBinding? binding = null) =>
        AssessmentService.Validate(fixture.Root, assessment, AssessmentService.Serialize(assessment),
            fixture.Confirmed, fixture.ConfirmedBytes, evidence, binding);

    private static void Reject(Action action, string name)
    {
        try { action(); }
        catch (DeterministicValidationException) { return; }
        throw new InvalidOperationException($"Expected deterministic rejection: {name}");
    }

    private static void Assert(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException(name);
    }
}
