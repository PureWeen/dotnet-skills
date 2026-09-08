using System.Text;
using System.Text.Json.Nodes;
using BlazorComponentReadiness.Validator.Assessment;
using BlazorComponentReadiness.Validator.Cli;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Rendering;
using BlazorComponentReadiness.Validator.Validation;

internal static class AuthorizedScopeTests
{
    private static readonly string[] Excluded =
        ["PI-04", "PI-10", "PI-11", "PI-12", "SUP-04", "SUP-05", "CI-01", "CI-05", "CI-06", "CI-07", "CI-08", "TA-07"];

    public static void Run(string repositoryRoot, string pluginRoot)
    {
        var previous = Environment.GetEnvironmentVariable("READINESS_SKILL_ROOT");
        Environment.SetEnvironmentVariable("READINESS_SKILL_ROOT",
            Path.Combine(pluginRoot, "skills", "blazor-component-readiness"));
        var root = Path.Combine(
            Environment.GetEnvironmentVariable("READINESS_TEST_ARTIFACTS") ?? Path.Combine(repositoryRoot, "artifacts"),
            "readiness-authorized-scope-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var bytes = File.ReadAllBytes(Path.Combine(repositoryRoot, "tests", "dotnet-blazor",
                "readiness-validator", "fixtures", AuthorizedPackageScope.Filename));
            var scope = AuthorizedPackageScope.Parse(bytes);
            TestManifest(bytes, scope);
            var input = CreateInput(scope, bytes, documentSize: 1);
            var (assessment, evidence) = CreateAssessment(scope, input);
            scope.Validate(assessment, input, evidence);
            TestBindings(scope, input, assessment, evidence);
            TestDisclosure(scope);
            TestMalformedIntake(root, input, bytes);
            Reject(() => ReportService.RenderMarkdown(assessment, input, evidence),
                "renderer cannot bypass retained scope by omitting root");

            var retainedRoot = Environment.GetEnvironmentVariable("READINESS_RECOVERY_FIXTURE_ROOT");
            if (retainedRoot is not null)
            {
                var docx = Environment.GetEnvironmentVariable("READINESS_RECOVERY_DOCX") ??
                    throw new InvalidOperationException("Exact recovery replay requires READINESS_RECOVERY_DOCX.");
                TestRetainedReplay(root, retainedRoot, docx, scope, bytes);
                Console.WriteLine("Authorized scope: exact retained package/DOCX replay, receipts, reader, mutations and historical freeze passed.");
            }
            else
            {
                Console.WriteLine("Authorized scope: contract tests passed; exact retained recovery replay was not requested.");
            }
        }
        finally
        {
            ReportCommand.BeforePublishForTests = null;
            ReaderCommand.BeforePublishForTests = null;
            Environment.SetEnvironmentVariable("READINESS_SKILL_ROOT", previous);
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestManifest(byte[] bytes, AuthorizedPackageScope scope)
    {
        Assert(scope.Requirements.Count == 48 && scope.Requirements.All(row =>
            row.Scope == "repository-wide" && row.Basis is { RequiresPolicyApproval: false }),
            "exact approved grounded inventory");
        Assert(scope.ManifestDigest == ContractJson.RawDigest(bytes), "independently pinned manifest bytes");
        Assert(scope.SelectedSetDigest.Value == "942a4c28425cc4a34269f1c564422d5cc87c389717f3f881ada38c3fd7c1feb0",
            "canonical ordered selected-set digest");
        foreach (var invalid in new[] { "", " ", "{}", "[]", "{", Encoding.UTF8.GetString(bytes) + "\n" })
        {
            Reject(() => AuthorizedPackageScope.Parse(Encoding.UTF8.GetBytes(invalid)), "empty/malformed/noncanonical manifest");
        }

        void Mutate(string name, Action<JsonObject> change)
        {
            var value = JsonNode.Parse(bytes)!.AsObject();
            change(value);
            Reject(() => AuthorizedPackageScope.Parse(Encoding.UTF8.GetBytes(value.ToJsonString())), name);
        }

        Mutate("47 rows with internally recomputed count/digest", value =>
        {
            value["selected_ids"]!.AsArray().RemoveAt(0);
            RehashSelection(value);
        });
        foreach (var id in Excluded.Concat(["BEQ-01", "TA-08", "UNKNOWN-01", "LP-02"]))
        {
            Mutate("49 rows: extra " + id, value =>
            {
                value["selected_ids"]!.AsArray().Add(id);
                RehashSelection(value);
            });
            Mutate("48 rows: substituted " + id, value =>
            {
                value["selected_ids"]![0] = id;
                RehashSelection(value);
            });
        }

        Mutate("noncanonical order", value =>
        {
            value["selected_ids"]![0] = "LP-02";
            value["selected_ids"]![1] = "LP-01";
            RehashSelection(value);
        });
        Mutate("count mismatch", value => value["row_count"] = 47);
        Mutate("selected digest mismatch", value => value["selected_set_sha256"]!["value"] = new string('0', 64));
        Mutate("unapproved authorization", value => value["authorization_id"] = "self-approved");
        Mutate("scope reference drift", value => value["scope_correction"]!["sha256"]!["value"] = new string('0', 64));
        Mutate("recovery reference drift", value => value["recovery_authorization"]!["sha256"]!["value"] = new string('0', 64));
        Mutate("document filename drift", value => value["requirement_source"]!["filename"] = "other.docx");
        Mutate("document digest drift", value => value["requirement_source"]!["sha256"]!["value"] = new string('0', 64));
        Mutate("package digest drift", value => value["package"]!["nupkg_sha256"]!["value"] = new string('0', 64));
        Mutate("package ID drift", value => value["package"]!["package_id"] = "other.package");
        Mutate("package version drift", value => value["package"]!["version"] = "9.0.0");
        Mutate("unsupported manifest version", value => value["schema_version"] = 2);
        Mutate("unsupported kind", value => value["kind"] = "arbitrary-selection");
        var duplicateProperty = Encoding.UTF8.GetString(bytes).Replace("\"row_count\":48",
            "\"row_count\":48,\"row_count\":48", StringComparison.Ordinal);
        Reject(() => AuthorizedPackageScope.Parse(Encoding.UTF8.GetBytes(duplicateProperty)), "duplicate JSON property");
        Reject(() => scope.Select(RubricLoader.Load(), "component"), "component scope");
        Reject(() => scope.Select(RubricLoader.Load(), "unified"), "unified scope");
        Reject(() => scope.Select(RubricLoader.Load("1.3.0"), "package"), "wrong rubric scope");
        Assert(RubricLoader.Select(RubricLoader.Load(), "package", []).Count == 60, "ordinary selection remains full");
        Assert(RubricLoader.Select(RubricLoader.Load(), "component", []).Count == 61, "ordinary component remains full");
    }

    private static void RehashSelection(JsonObject value)
    {
        var ids = value["selected_ids"]!.AsArray();
        value["row_count"] = ids.Count;
        value["selected_set_sha256"]!["value"] = ContractJson.RawDigest(Encoding.UTF8.GetBytes(ids.ToJsonString())).Value;
    }

    private static InputManifest CreateInput(AuthorizedPackageScope scope, byte[] scopeBytes, long documentSize) =>
        new(InputManifestService.SchemaVersion, "confirmed", "published",
            new(scope.Package.PackageId, scope.Package.Version, scope.Package.NupkgDigest,
                "package.nupkg", "package.nupkg", "local-file"),
            new("unresolved", null, null, null, null),
            [new("package", "package.nupkg", "local-file", "succeeded",
                "Structural regression replay of retained package bytes, not a new package assessment.")],
            [], [], [],
            new[] {
                new InputEvidenceArtifact(AuthorizedPackageScope.Filename, AuthorizedPackageScope.Kind,
                    scope.ManifestDigest, scopeBytes.LongLength),
                new InputEvidenceArtifact(scope.DocumentFilename, "frozen-requirements-document",
                    scope.DocumentDigest, documentSize)
            }.OrderBy(item => item.Basename, StringComparer.Ordinal).ToArray(),
            [], [], []);

    private static (ReadinessAssessment Assessment, EvidenceBundle Evidence) CreateAssessment(
        AuthorizedPackageScope scope, InputManifest input, EvidenceRecordDraft? draft = null)
    {
        var rubric = RubricLoader.Load();
        var identity = new ExactAssessmentIdentity("package", scope.Package,
            InputManifestService.Digest(InputManifestService.Serialize(input)), null);
        draft ??= new(
            "Structural regression fixture only; exact retained byte binding is not a readiness finding.",
            new("repository-wide", null),
            new(EvidenceIdentity.PackageArtifactMetadata, NupkgInspector.WholePackageEvidenceLocator,
                "Structural fixture binds the retained archive; no product investigation is asserted.",
                "2026-09-08T05:26:31Z", scope.Package.NupkgDigest, "commitment-only"), []);
        var ledger = EvidenceLedgerBuilder.BuildRepositoryLedger(
            new("package", identity.Package, identity.InputManifestDigest, null), [draft]);
        var evidence = EvidenceLedgerBuilder.BuildBundle(identity, [ledger], [ledger.Records[0].StableId]);
        var rows = scope.Requirements.Select((row, index) => new AssessmentRow(
            row.Id, row.Requirement, row.Scope, row.Area, "not tested",
            "Structural regression fixture only; not an accepted product finding.",
            index == 0 ? [ledger.Records[0].StableId] : [], null,
            "Substantive investigation is intentionally outside this structural test fixture.", null)).ToArray();
        var assessment = new ReadinessAssessment(AssessmentService.SchemaVersion, "package", identity,
            rubric.RubricVersion, rubric.ScopeSchemaVersion, rubric.RubricDigest, rubric.ScopeMapDigest,
            [], rows.Select(row => row.Id).ToArray(), null, rows, [],
            [new("not tested", "This structural fixture does not establish package readiness.",
                rows.Select(row => row.Id).ToArray(), [ledger.Records[0].StableId])], "complete");
        return (assessment, evidence);
    }

    private static void TestBindings(
        AuthorizedPackageScope scope, InputManifest input, ReadinessAssessment assessment, EvidenceBundle evidence)
    {
        Reject(() => scope.Validate(assessment with { Rows = assessment.Rows.Skip(1).ToArray() }, input, evidence), "missing row");
        Reject(() => scope.Validate(assessment with { Rows = [.. assessment.Rows, assessment.Rows[0]] }, input, evidence), "extra row");
        Reject(() => scope.Validate(assessment with { SelectedIds = assessment.SelectedIds.Skip(1).ToArray() }, input, evidence), "missing selected ID");
        Reject(() => scope.Validate(assessment with { ScopeMapDigest = new("sha256", new string('0', 64)) }, input, evidence), "scope map drift");
        Reject(() => scope.Validate(assessment with
        {
            Rows = assessment.Rows.Select((row, index) => index == 0 ? row with { Requirement = "Changed canonical wording." } : row).ToArray()
        }, input, evidence), "canonical requirement drift");
        var changedIdentity = assessment.Identity with { InputManifestDigest = new("sha256", new string('0', 64)) };
        Reject(() => scope.Validate(assessment with { Identity = changedIdentity }, input, evidence), "assessment input binding drift");
        Reject(() => scope.Validate(assessment, input, evidence with { Assessment = changedIdentity }), "evidence scope binding drift");
        Reject(() => EvidenceLedgerValidator.ValidateCompatibility(changedIdentity, evidence.SourceLedgers[0].Ledger),
            "changed evidence subject invalidates reuse");
        var changedInput = input with { Exclusions = [new("Fixture boundary", "A different identity cannot claim unchanged reuse.")] };
        var rebound = CreateAssessment(scope, changedInput);
        Assert(rebound.Evidence.Selection[0].EvidenceId != evidence.Selection[0].EvidenceId, "input identity changes EV1 identity");
        Reject(() => scope.Validate(assessment, changedInput, evidence), "changed retained input invalidates reuse");
        var record = evidence.SourceLedgers[0].Ledger.Records[0];
        var extraDraft = new EvidenceRecordDraft("Historical unselected record must remain internal.",
            record.Applicability, record.Provenance, []);
        var expanded = EvidenceLedgerBuilder.BuildRepositoryLedger(
            evidence.SourceLedgers[0].Ledger.RepositorySubject!,
            [new(record.Claim, record.Applicability, record.Provenance, record.Supersedes), extraDraft]);
        var expandedBundle = EvidenceLedgerBuilder.BuildBundle(assessment.Identity, [expanded], [record.StableId]);
        Reject(() => scope.Validate(assessment, input, expandedBundle), "unselected historical ledger records cannot escape");
    }

    private static void TestDisclosure(AuthorizedPackageScope scope)
    {
        foreach (var id in Excluded)
        {
            foreach (var value in new[] { id, id.ToLowerInvariant(), id.Replace("-", "&#45;", StringComparison.Ordinal),
                id.Replace("-", "\u2011", StringComparison.Ordinal) })
            {
                scope.RejectDisclosure("A scoped observation without an extension identifier.");
                Reject(() => scope.RejectDisclosure("Summary / evidence / appendix: " + value + " verified."),
                    "extension disclosure: " + value);
            }
        }

        Reject(() => scope.RejectDisclosure("All 60 package checks are complete."), "broader count claim");
        Reject(() => scope.RejectDisclosure("Versioned extension conclusions."), "extension prose");
    }

    private static void TestMalformedIntake(string root, InputManifest input, byte[] scopeBytes)
    {
        var path = Path.Combine(root, AuthorizedPackageScope.Filename);
        File.WriteAllBytes(path, []);
        Reject(() => AuthorizedPackageScope.Load(root, input), "explicit empty file cannot fall back");
        File.WriteAllBytes(path, scopeBytes);
        Reject(() => AuthorizedPackageScope.Load(root, input), "missing frozen DOCX",
            Path.Combine(root, "blazor-partner-components-requirements.docx"));
        Reject(() => AuthorizedPackageScope.Load(root, input with
        {
            EvidenceInputs = input.EvidenceInputs.Select(item => item.Kind == AuthorizedPackageScope.Kind
                ? item with { Kind = AuthorizedPackageScope.Kind + "-unsupported" } : item).ToArray()
        }), "unsupported retained manifest kind");
        Reject(() => AuthorizedPackageScope.Load(root, input with
        {
            EvidenceInputs = [.. input.EvidenceInputs, input.EvidenceInputs.Single(item => item.Kind == AuthorizedPackageScope.Kind)]
        }), "duplicate retained scope");
        Assert(AuthorizedPackageScope.Load(null, input with { EvidenceInputs = [] }) is null, "no scope preserves ordinary path");
    }

    private static void TestRetainedReplay(
        string root, string retainedRoot, string docxPath, AuthorizedPackageScope scope, byte[] scopeBytes)
    {
        VerifyHistory(retainedRoot);
        File.Copy(Path.Combine(retainedRoot, "controller", "retained-attempt-28", "retained", "acquisition",
            "package", "IgniteUI.Blazor.Lite.0.1.2-alpha.3.nupkg"), Path.Combine(root, "package.nupkg"));
        File.Copy(docxPath, Path.Combine(root, scope.DocumentFilename));
        File.WriteAllBytes(Path.Combine(root, AuthorizedPackageScope.Filename), scopeBytes);
        var input = CreateInput(scope, scopeBytes, new FileInfo(docxPath).Length);
        var inputBytes = InputManifestService.Serialize(input);
        InputManifestService.Validate(input, root, requireConfirmed: true);
        var initialized = AssessmentService.Initialize("package", root, input, inputBytes, null, []);
        Assert(initialized.Rows.Count == 48, "ordinary init consumes retained authorized scope");
        var (assessment, evidence) = CreateAssessment(scope, input);
        var inputPath = Path.Combine(root, "scoped.input.json");
        var assessmentPath = Path.Combine(root, "scoped.assessment.json");
        var evidencePath = Path.Combine(root, "scoped.evidence.json");
        File.WriteAllBytes(inputPath, inputBytes);
        File.WriteAllBytes(assessmentPath, AssessmentService.Serialize(assessment));
        File.WriteAllBytes(evidencePath, CanonicalEvidenceJson.SerializeBundle(evidence));
        string[] validate = ["assessment", "validate", "--root", root, "--input", inputPath,
            "--assessment", assessmentPath, "--evidence", evidencePath];
        string[] render = ["report", "render", "--root", root, "--input", inputPath,
            "--assessment", assessmentPath, "--evidence", evidencePath, "--output", Path.Combine(root, "revisions")];
        ExpectCli(validate, 0);
        ExpectCli(render, 0);
        var revisionPath = Path.Combine(root, "revisions", "0001");
        var revision = RevisionService.VerifyRevision(root, revisionPath, null, null, validateChain: true);
        string[] verify = ["report", "verify", "--root", root, "--revision", revisionPath];
        ExpectCli(verify, 0);
        Reject(() => RevisionService.LoadPackageBinding(root, revisionPath, null), "scoped report is not a full-package component prerequisite");
        string[] reader = ["reader", "render", "--root", root, "--revision", revisionPath, "--output", Path.Combine(root, "reader")];
        ExpectCli(reader, 0);
        reader[1] = "verify";
        ExpectCli(reader, 0);
        var mappedIds = JsonNode.Parse(File.ReadAllBytes(Path.Combine(root, "reader", "mapping.json")))!
            ["groups"]!.AsArray().SelectMany(group => group!["checks"]!.AsArray())
            .Select(row => row!["id"]!.GetValue<string>()).ToArray();
        Assert(mappedIds.Length == 48 && mappedIds.Distinct(StringComparer.Ordinal).Count() == 48 &&
            mappedIds.ToHashSet(StringComparer.Ordinal).SetEquals(assessment.SelectedIds),
            "reader contains exactly the authorized rows without omissions or duplicates");
        var tableIds = Encoding.UTF8.GetString(revision.ReportBytes).Split('\n')
            .Where(line => line.StartsWith("| `", StringComparison.Ordinal))
            .Select(line => line.Split('`')[1]).ToArray();
        Assert(tableIds.SequenceEqual(assessment.SelectedIds, StringComparer.Ordinal), "raw report has exact canonical 48-row table");
        Assert(Encoding.UTF8.GetString(revision.ReportBytes).Contains("- `not tested`: 48", StringComparison.Ordinal),
            "status totals are computed from the authorized rows");
        var outputFiles = Directory.GetFiles(Path.Combine(root, "reader"), "*", SearchOption.AllDirectories);
        Assert(outputFiles.All(path => !path.EndsWith(".bin", StringComparison.Ordinal)), "raw evidence is not exported");
        Assert(File.ReadAllBytes(Path.Combine(root, "reader", "technical", AuthorizedPackageScope.Filename))
            .SequenceEqual(scopeBytes), "reader carries exact manifest bytes");
        foreach (var path in outputFiles)
        {
            scope.RejectDisclosure(File.ReadAllText(path));
        }

        foreach (var rowCount in new[] { 47, 49 })
        {
            var invalid = assessment with
            {
                Rows = rowCount == 47 ? assessment.Rows.Skip(1).ToArray() : [.. assessment.Rows, assessment.Rows[0]]
            };
            MutateFile(assessmentPath, AssessmentService.Serialize(invalid), () => ExpectCli(validate, 1));
        }

        MutateFile(Path.Combine(root, AuthorizedPackageScope.Filename), Encoding.UTF8.GetBytes("{}"),
            () => ExpectCli(verify, 1));
        MutateFile(Path.Combine(root, scope.DocumentFilename), [0], () => ExpectCli(verify, 1));
        var wrongReceipt = revision.Manifest with { InputManifestDigest = new("sha256", new string('0', 64)) };
        MutateFile(Path.Combine(revisionPath, "package.validation.json"), ReportService.SerializeManifest(wrongReceipt),
            () => ExpectCli(verify, 1));
        Reject(() => ReaderService.Build(root, revision with { Manifest = wrongReceipt }, null, null), "reader rejects receipt scope drift");

        var reportPath = Path.Combine(revisionPath, "package.report.md");
        foreach (var changedReport in new[]
        {
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(revision.ReportBytes).Replace(
                scope.SelectedSetDigest.Value, new string('0', 64), StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(revision.ReportBytes) + "\n## Appendix\nPI-04: verified\n"),
            Encoding.UTF8.GetBytes(string.Join('\n', Encoding.UTF8.GetString(revision.ReportBytes).Split('\n')
                .Where(line => !line.StartsWith("| `LP-01` |", StringComparison.Ordinal))))
        })
        {
            Reject(() => ReportService.CreateManifest(assessment, revision.AssessmentBytes, input, inputBytes,
                evidence, revision.EvidenceBytes, changedReport, root: root), "receipt refuses altered report");
            var rehashed = revision.Manifest with { ReportDigest = ContractJson.RawDigest(changedReport) };
            MutateFile(reportPath, changedReport, () =>
                MutateFile(Path.Combine(revisionPath, "package.validation.json"), ReportService.SerializeManifest(rehashed),
                    () => ExpectCli(verify, 1)));
        }

        MutateFile(Path.Combine(root, "reader", "technical", AuthorizedPackageScope.Filename), Encoding.UTF8.GetBytes("{}"),
            () => ExpectCli(reader, 1));
        MutateFile(Path.Combine(root, "reader", "reader.validation.json"), Encoding.UTF8.GetBytes("{}"),
            () => ExpectCli(reader, 1));
        var changed = assessment with
        {
            Rows = assessment.Rows.Select((row, index) => index == 0
                ? row with { Observation = "A changed observation must not be presented as unchanged accepted content." } : row).ToArray()
        };
        MutateFile(assessmentPath, AssessmentService.Serialize(changed), () =>
            ExpectCli([.. render, "--predecessor", ContractJson.RawDigest(revision.ManifestBytes).Value], 1));
        MutateFile(assessmentPath, AssessmentService.Serialize(changed), () =>
            ExpectCli([.. render, "--predecessor", ContractJson.RawDigest(revision.ManifestBytes).Value, "--changed-ids", "LP-01"], 1));
        Assert(!Directory.Exists(Path.Combine(root, "revisions", "0002")), "failed unchanged-reuse attempt publishes no revision");
        var missingFeedback = revision.Manifest with { FeedbackDigest = new("sha256", new string('a', 64)) };
        MutateFile(Path.Combine(revisionPath, "package.validation.json"), ReportService.SerializeManifest(missingFeedback),
            () => Reject(() => RevisionService.VerifyRevision(root, revisionPath, null, null,
                validateChain: true, allowMissingFeedback: true), "authorized scope cannot skip rendering through missing-feedback fallback"));
        TestPublicationMutation(root, scopeBytes, render, revisionPath);
        TestRawHistoryProjection(root, scope, scopeBytes, input);
        VerifyHistory(retainedRoot);
        if (Environment.GetEnvironmentVariable("READINESS_RECOVERY_REPLAY_OUTPUT") is { } replayOutput)
        {
            RetainReplay(root, replayOutput, scope.DocumentFilename);
        }
    }

    private static void RetainReplay(string root, string output, string documentFilename)
    {
        var fullOutput = Path.GetFullPath(output);
        var parent = Path.GetDirectoryName(fullOutput)!;
        AtomicDirectory.WriteNew(parent, Path.GetFileName(fullOutput), staging =>
        {
            foreach (var name in new[] { "package.nupkg", documentFilename, AuthorizedPackageScope.Filename })
            {
                File.Copy(Path.Combine(root, name), Path.Combine(staging, name));
            }

            foreach (var directory in new[] { "revisions", "reader" })
            {
                foreach (var file in Directory.GetFiles(Path.Combine(root, directory), "*", SearchOption.AllDirectories))
                {
                    var destination = Path.Combine(staging, Path.GetRelativePath(root, file));
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    File.Copy(file, destination);
                }
            }

            File.WriteAllText(Path.Combine(staging, "qualification.txt"),
                "Structural regression fixture only. This is not the accepted partner assessment or substantive investigation evidence.\n");
        });
        ExpectCli(["report", "verify", "--root", fullOutput, "--revision", Path.Combine(fullOutput, "revisions", "0001")], 0);
        ExpectCli(["reader", "verify", "--root", fullOutput, "--revision", Path.Combine(fullOutput, "revisions", "0001"),
            "--output", Path.Combine(fullOutput, "reader")], 0);
        Console.WriteLine("Independently revalidated structural replay retained at: " + fullOutput);
    }

    private static void TestPublicationMutation(string root, byte[] scopeBytes, string[] render, string revisionPath)
    {
        var scopePath = Path.Combine(root, AuthorizedPackageScope.Filename);
        var raceRender = (string[])render.Clone();
        raceRender[^1] = Path.Combine(root, "race-revisions");
        try
        {
            ReportCommand.BeforePublishForTests = () => File.WriteAllText(scopePath, "{}");
            ExpectCli(raceRender, 1);
            Assert(!Directory.Exists(Path.Combine(root, "race-revisions", "0001")), "scope mutation publishes no report");
        }
        finally
        {
            ReportCommand.BeforePublishForTests = null;
            File.WriteAllBytes(scopePath, scopeBytes);
        }

        try
        {
            ReaderCommand.BeforePublishForTests = () => File.WriteAllText(scopePath, "{}");
            ExpectCli(["reader", "render", "--root", root, "--revision", revisionPath, "--output", Path.Combine(root, "race-reader")], 1);
            Assert(!Directory.Exists(Path.Combine(root, "race-reader")), "scope mutation publishes no reader");
        }
        finally
        {
            ReaderCommand.BeforePublishForTests = null;
            File.WriteAllBytes(scopePath, scopeBytes);
        }
    }

    private static void TestRawHistoryProjection(string root, AuthorizedPackageScope scope, byte[] scopeBytes, InputManifest input)
    {
        var history = Encoding.UTF8.GetBytes("PI-04: verified. Internal historical status and evidence must not be exported.");
        File.WriteAllBytes(Path.Combine(root, "retained-history.txt"), history);
        input = input with
        {
            EvidenceInputs = input.EvidenceInputs.Append(new InputEvidenceArtifact("retained-history.txt", "retained-test-history",
                ContractJson.RawDigest(history), history.LongLength)).OrderBy(item => item.Basename, StringComparer.Ordinal).ToArray()
        };
        var draft = new EvidenceRecordDraft("Synthetic selected record with internal raw history; not a product finding.",
            new("repository-wide", null),
            new(EvidenceIdentity.ReviewerGeneratedAnalysis, "retained-history.txt", "Synthetic disclosure regression only.",
                "2026-09-08T05:26:31Z", ContractJson.RawDigest(history), "commitment-only"), []);
        var (assessment, evidence) = CreateAssessment(scope, input, draft);
        var inputBytes = InputManifestService.Serialize(input);
        var assessmentBytes = AssessmentService.Serialize(assessment);
        var evidenceBytes = CanonicalEvidenceJson.SerializeBundle(evidence);
        AssessmentService.Validate(root, assessment, assessmentBytes, input, inputBytes, evidence);
        var report = ReportService.RenderMarkdown(assessment, input, evidence, root: root);
        var manifest = ReportService.CreateManifest(assessment, assessmentBytes, input, inputBytes, evidence, evidenceBytes, report, root: root);
        var revision = new RevisionArtifacts("", "package", input, inputBytes, assessment, assessmentBytes,
            evidence, evidenceBytes, report, manifest, ReportService.SerializeManifest(manifest));
        var files = ReaderService.Build(root, revision, null, null);
        Assert(files.All(file => !file.Value.AsSpan().SequenceEqual(history)), "internal raw bytes are not copied");
        Assert(files[$"technical/{AuthorizedPackageScope.Filename}"].SequenceEqual(scopeBytes), "scope retained in safe projection");
        foreach (var file in files)
        {
            scope.RejectDisclosure(Encoding.UTF8.GetString(file.Value));
        }
    }

    private static void VerifyHistory(string retainedRoot)
    {
        var blockedBytes = File.ReadAllBytes(Path.Combine(retainedRoot, "milestone-a-blocked.json"));
        Assert(ContractJson.RawDigest(blockedBytes).Value == "a9c1b8af77e3a5bdace9912b5da07ef19100602ce4cc54327b7db6b003998d05",
            "historical handoff bytes unchanged");
        Assert(JsonNode.Parse(blockedBytes)!["decision"]!.GetValue<string>() == "blocked", "historical decision remains blocked");
        var frozen = File.ReadAllBytes(Path.Combine(retainedRoot, "milestone-a-internal-freeze.json"));
        Assert(ContractJson.RawDigest(frozen).Value == "f1b2b05f4345dfb34aa65c1ad9a9dfe676a83849738a927441dd691d62e2e1a8",
            "historical freeze unchanged");
        foreach (var entry in JsonNode.Parse(frozen)!["files"]!.AsArray())
        {
            var path = SafePath.ResolveUnderRoot(retainedRoot, entry!["path"]!.GetValue<string>(), true, true);
            Assert(new FileInfo(path).Length == entry["size"]!.GetValue<long>() &&
                ContractJson.RawDigest(File.ReadAllBytes(path)).Value == entry["sha256"]!.GetValue<string>(),
                "historical artifact unchanged: " + entry["path"]);
        }
    }

    private static void MutateFile(string path, byte[] replacement, Action action)
    {
        var original = File.ReadAllBytes(path);
        try
        {
            File.WriteAllBytes(path, replacement);
            action();
        }
        finally
        {
            File.WriteAllBytes(path, original);
        }
    }

    private static void ExpectCli(string[] arguments, int expected)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var actual = CliApplication.Run(arguments, output, error);
        Assert(actual == expected, $"CLI {string.Join(' ', arguments.Take(2))}: expected {expected}, actual {actual}: {error}");
        if (expected == 0)
        {
            Assert(output.ToString() == "" && error.ToString() == "", "successful scoped CLI remains quiet");
        }
    }

    private static void Reject(Action action, string message, string? expectedMissingPath = null)
    {
        try
        {
            action();
        }
        catch (DeterministicValidationException)
        {
            return;
        }
        catch (FileNotFoundException exception) when (expectedMissingPath is not null && exception.FileName == expectedMissingPath)
        {
            return;
        }

        throw new InvalidOperationException("Expected rejection: " + message);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
