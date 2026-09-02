using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using BlazorComponentReadiness.Validator.Cli;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.IO;

internal static class EvidenceTests
{
    private const string KnownEvidenceId =
        "EV1-705e25664858608ec40d006cc3b50607ce9fbc9b9b3dcd9d0e316b36b8f3cfab";
    private const string KnownLedgerSha256 =
        "50652df704f93a6a146497681c7f25e73f152573dfa53ccd355568b9be11655a";
    private const string KnownAssessmentJson =
        """{"package":{"package_id":"sample.widgets","version":"1.2.3","nupkg_sha256":{"algorithm":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"component_id":"Tree"}""";
    private const string KnownLedgerJson =
        """{"schema_version":1,"ledger_kind":"repository","repository_subject":{"package":{"package_id":"sample.widgets","version":"1.2.3","nupkg_sha256":{"algorithm":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},"component_subject":null,"records":[{"stable_id":"EV1-705e25664858608ec40d006cc3b50607ce9fbc9b9b3dcd9d0e316b36b8f3cfab","claim":"Vendor documentation states keyboard support.","applicability":{"scope":"repository-wide","component_id":null},"provenance":{"kind":"vendor-public-documentation","locator":"https://docs.example.com/widgets","method":"Captured official documentation.","captured_at_utc":"2026-09-02T20:00:00Z","content_sha256":{"algorithm":"sha256","value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"retention":"commitment-only"},"supersedes":[]}]}""";

    public static void Run(string repositoryRoot, string pluginRoot)
    {
        TestKnownAnswersAndCanonicalBytes();
        TestCliCommandSurface();
        TestPublicProvenanceKinds();
        TestScopeAndExactIdentity();
        TestHostNeutralSourceMapping();
        TestBundleSelectionAndAmbiguity();
        TestSupersession();
        TestResourceCeilings();
        TestCliSubprocesses(repositoryRoot, pluginRoot);
    }

    private static void TestCliCommandSurface()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(["evidence", "--help"], output, error),
            "evidence help exit");
        foreach (var command in new[] { "ledger-build", "ledger-validate", "bundle" })
        {
            output.GetStringBuilder().Clear();
            error.GetStringBuilder().Clear();
            AssertEqual(
                ExitCodes.Success,
                CliApplication.Run(["evidence", command, "--help"], output, error),
                $"{command} help exit");
            Assert(
                output.ToString().Contains($"evidence {command}", StringComparison.Ordinal),
                $"{command} help contains exact grouped command");
        }
    }

    private static void TestKnownAnswersAndCanonicalBytes()
    {
        var assessmentBytes = Encoding.UTF8.GetBytes(KnownAssessmentJson);
        var ledgerBytes = Encoding.UTF8.GetBytes(KnownLedgerJson);
        var assessment = CanonicalEvidenceJson.ParseAssessment(assessmentBytes);
        var ledger = CanonicalEvidenceJson.ParseSourceLedger(ledgerBytes);

        AssertBytes(
            assessmentBytes,
            CanonicalEvidenceJson.SerializeAssessment(assessment),
            "known assessment canonical bytes");
        AssertBytes(
            ledgerBytes,
            CanonicalEvidenceJson.SerializeSourceLedger(ledger),
            "known source-ledger canonical bytes");
        AssertEqual(KnownEvidenceId, ledger.Records.Single().StableId, "known evidence ID");
        AssertEqual(
            KnownLedgerSha256,
            CanonicalEvidenceJson.ComputeSourceLedgerSha256(ledger),
            "known source-ledger digest");

        var rebuilt = EvidenceLedgerBuilder.BuildRepositoryLedger(
            ledger.RepositorySubject!,
            ledger.Records.Select(ToDraft));
        AssertBytes(
            ledgerBytes,
            CanonicalEvidenceJson.SerializeSourceLedger(rebuilt),
            "known ledger rebuild");

        ExpectValidation(
            () => CanonicalEvidenceJson.ParseSourceLedger(
                Encoding.UTF8.GetBytes(KnownLedgerJson + "\n")),
            "noncanonical trailing newline");
        ExpectValidation(
            () => CanonicalEvidenceJson.ParseAssessment(
                Encoding.UTF8.GetBytes(
                    KnownAssessmentJson.Replace(
                        "\"package\":",
                        "\"component_id\":\"Tree\",\"package\":",
                        StringComparison.Ordinal))),
            "property order and duplication");

        var forgedId = ledger with
        {
            Records =
            [
                ledger.Records[0] with
                {
                    StableId = "EV1-" + new string('f', 64)
                }
            ]
        };
        ExpectValidation(
            () => EvidenceLedgerValidator.ValidateSourceLedger(forgedId),
            "forged evidence ID");
    }

    private static void TestPublicProvenanceKinds()
    {
        var cases = new[]
        {
            (EvidenceIdentity.VendorPublicDocumentation, "https://docs.example.com/widgets"),
            (EvidenceIdentity.PackageArtifactMetadata, "package:Sample.Widgets.nuspec"),
            (EvidenceIdentity.VendorSourceRepository, "https://code.example.com/Vendor/Widgets/src/Tree.cs"),
            (EvidenceIdentity.ReproducedRuntimeObservation, "dotnet test Tree.Keyboard"),
            (EvidenceIdentity.OwnerSuppliedInternalEvidence, "accessibility-audit.pdf"),
            (EvidenceIdentity.OwnerDeclaredUnavailable, "source"),
            (EvidenceIdentity.OwnerDeclaredUnavailable, "artifact:private-sbom")
        };

        foreach (var (kind, locator) in cases)
        {
            var ledger = EvidenceLedgerBuilder.BuildRepositoryLedger(
                KnownRepositorySubject(),
                [RepositoryDraft(kind, locator, $"Evidence kind {kind} is explicit.")]);
            AssertEqual(kind, ledger.Records.Single().Provenance.Kind, $"provenance kind {kind}");
        }

        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildRepositoryLedger(
                KnownRepositorySubject(),
                [RepositoryDraft("closed-source", "source", "Source was not available.")]),
            "closed-source cannot be inferred through an unknown kind");
        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildRepositoryLedger(
                KnownRepositorySubject(),
                [RepositoryDraft(
                    EvidenceIdentity.OwnerDeclaredUnavailable,
                    "https://missing.example.com/source",
                    "A failed lookup is not an owner declaration.")]),
            "unavailable source must be an explicit owner declaration");
    }

    private static void TestScopeAndExactIdentity()
    {
        var assessment = KnownAssessment();
        var repositoryDraft = RepositoryDraft(
            EvidenceIdentity.PackageArtifactMetadata,
            "package:Sample.Widgets.nuspec",
            "Package metadata declares the license.");
        var componentDraft = ComponentDraft("Tree");

        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildRepositoryLedger(
                KnownRepositorySubject(),
                [componentDraft]),
            "component evidence in repository ledger");
        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildComponentLedger(
                assessment,
                [repositoryDraft]),
            "repository evidence in component ledger");
        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildComponentLedger(
                assessment,
                [ComponentDraft("Grid")]),
            "component scope mismatch");

        var repositoryLedger = EvidenceLedgerBuilder.BuildRepositoryLedger(
            KnownRepositorySubject(),
            [repositoryDraft]);
        var componentLedger = EvidenceLedgerBuilder.BuildComponentLedger(
            assessment,
            [componentDraft]);
        AssertEqual(
            2,
            EvidenceLedgerBuilder.BuildBundle(
                assessment,
                [repositoryLedger, componentLedger],
                [repositoryLedger.Records[0].StableId, componentLedger.Records[0].StableId])
                .Selection.Count,
            "compatible package/component bundle");

        foreach (var mismatch in new[]
        {
            assessment with
            {
                Package = assessment.Package with { PackageId = "other.widgets" }
            },
            assessment with
            {
                Package = assessment.Package with { Version = "1.2.4" }
            },
            assessment with
            {
                Package = assessment.Package with
                {
                    NupkgDigest = new Sha256Digest("sha256", new string('c', 64))
                }
            }
        })
        {
            ExpectValidation(
                () => EvidenceLedgerBuilder.BuildBundle(
                    mismatch,
                    [repositoryLedger],
                    [repositoryLedger.Records[0].StableId]),
                "exact package mismatch");
        }

        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildBundle(
                assessment with { ComponentId = "Grid" },
                [componentLedger],
                [componentLedger.Records[0].StableId]),
            "exact component mismatch");
    }

    private static void TestHostNeutralSourceMapping()
    {
        var locators = new[]
        {
            "https://github.com/Vendor/Widgets.git/src/Tree.cs",
            "https://gitlab.example.com/Vendor/Widgets/src/Tree.cs",
            "https://dev.azure.com/Vendor/Widgets/_git/Components/src/Tree.cs"
        };

        foreach (var locator in locators)
        {
            var ledger = EvidenceLedgerBuilder.BuildRepositoryLedger(
                KnownRepositorySubject(),
                [RepositoryDraft(
                    EvidenceIdentity.VendorSourceRepository,
                    locator,
                    "Captured vendor source at an exact revision.")]);
            var canonical = ledger.Records.Single().Provenance.Locator;
            Assert(
                canonical.Contains("/Vendor/Widgets", StringComparison.Ordinal),
                "source mapping preserves host-neutral path case");
            Assert(
                canonical.StartsWith("https://", StringComparison.Ordinal),
                "source mapping uses canonical HTTPS");
        }
    }

    private static void TestBundleSelectionAndAmbiguity()
    {
        var first = RepositoryDraft(
            EvidenceIdentity.VendorPublicDocumentation,
            "https://docs.example.com/first",
            "First public claim.");
        var second = RepositoryDraft(
            EvidenceIdentity.VendorPublicDocumentation,
            "https://docs.example.com/second",
            "Second public claim.") with
        {
            Provenance = RepositoryDraft(
                EvidenceIdentity.VendorPublicDocumentation,
                "https://docs.example.com/second",
                "Second public claim.").Provenance with
            {
                ContentDigest = new Sha256Digest("sha256", new string('c', 64))
            }
        };
        var ledger = EvidenceLedgerBuilder.BuildRepositoryLedger(
            KnownRepositorySubject(),
            [first, first, second]);
        AssertEqual(2, ledger.Records.Count, "identical evidence deduplication");

        var selectedIds = ledger.Records
            .Select(record => record.StableId)
            .Reverse()
            .Take(1)
            .ToArray();
        var bundle = EvidenceLedgerBuilder.BuildBundle(
            KnownAssessment(),
            [ledger],
            selectedIds);
        AssertEqual(selectedIds[0], bundle.Selection[0].EvidenceId, "selection order");
        Assert(
            ledger.Records.Any(record => !selectedIds.Contains(record.StableId, StringComparer.Ordinal)),
            "bundle source can contain an unselected record");
        AssertEqual(1, bundle.Selection.Count, "only explicitly selected evidence is referenced");

        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildBundle(
                KnownAssessment(),
                [ledger],
                [selectedIds[0], selectedIds[0]]),
            "duplicate selection");

        var overlapA = EvidenceLedgerBuilder.BuildRepositoryLedger(
            KnownRepositorySubject(),
            [first]);
        var overlapB = EvidenceLedgerBuilder.BuildRepositoryLedger(
            KnownRepositorySubject(),
            [first, second]);
        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildBundle(
                KnownAssessment(),
                [overlapA, overlapB],
                [overlapA.Records[0].StableId]),
            "ambiguous source-ledger membership");

        var forgedDigest = bundle with
        {
            SourceLedgers =
            [
                bundle.SourceLedgers[0] with
                {
                    SourceLedgerSha256 = new string('0', 64)
                }
            ]
        };
        ExpectValidation(
            () => EvidenceLedgerValidator.ValidateBundle(forgedDigest),
            "forged source-ledger digest");
    }

    private static void TestSupersession()
    {
        var originalDraft = RepositoryDraft(
            EvidenceIdentity.PackageArtifactMetadata,
            "package:Sample.Widgets.nuspec",
            "Original package declaration.");
        var original = EvidenceLedgerBuilder.BuildRepositoryLedger(
            KnownRepositorySubject(),
            [originalDraft]).Records.Single();
        var successorDraft = originalDraft with
        {
            Claim = "Replacement package declaration.",
            Provenance = originalDraft.Provenance with
            {
                CapturedAtUtc = "2026-09-02T21:00:00Z",
                ContentDigest = new Sha256Digest("sha256", new string('d', 64))
            },
            Supersedes = [original.StableId]
        };
        var ledger = EvidenceLedgerBuilder.BuildRepositoryLedger(
            KnownRepositorySubject(),
            [originalDraft, successorDraft]);
        var successor = ledger.Records.Single(record => record.Supersedes.Count == 1);

        ExpectValidation(
            () => EvidenceLedgerBuilder.BuildBundle(
                KnownAssessment(),
                [ledger],
                [original.StableId, successor.StableId]),
            "superseded ancestor selection");
        AssertEqual(
            successor.StableId,
            EvidenceLedgerBuilder.BuildBundle(
                KnownAssessment(),
                [ledger],
                [successor.StableId]).Selection.Single().EvidenceId,
            "successor-only selection");

        const string firstId =
            "EV1-1111111111111111111111111111111111111111111111111111111111111111";
        const string secondId =
            "EV1-2222222222222222222222222222222222222222222222222222222222222222";
        var cycle = new EvidenceSourceLedger(
            1,
            "repository",
            KnownRepositorySubject(),
            null,
            [
                new EvidenceRecord(
                    firstId,
                    originalDraft.Claim,
                    originalDraft.Applicability,
                    originalDraft.Provenance,
                    [secondId]),
                new EvidenceRecord(
                    secondId,
                    successorDraft.Claim,
                    successorDraft.Applicability,
                    successorDraft.Provenance,
                    [firstId])
            ]);
        Assert(
            CaptureValidation(
                () => EvidenceLedgerValidator.ValidateSourceLedger(cycle))
                .Message.Contains("cycle", StringComparison.Ordinal),
            "supersession cycle is diagnosed before forged IDs");
    }

    private static void TestResourceCeilings()
    {
        EvidenceCommand.ValidateSupplementalInputs(
            Enumerable.Repeat(0L, ResourceLimits.SupplementalInputCount).ToArray());
        ExpectValidation(
            () => EvidenceCommand.ValidateSupplementalInputs(
                Enumerable.Repeat(0L, ResourceLimits.SupplementalInputCount + 1).ToArray()),
            "33 supplemental inputs");
        EvidenceCommand.ValidateSupplementalInputs(
            [ResourceLimits.SupplementalInputAggregateBytes]);
        ExpectValidation(
            () => EvidenceCommand.ValidateSupplementalInputs(
                [ResourceLimits.SupplementalInputAggregateBytes, 1]),
            "supplemental aggregate one byte over");
        BoundedIO.EnsureLength(
            ResourceLimits.AuthoredLedgerBytes,
            ResourceLimits.AuthoredLedgerBytes,
            "authored source ledger");
        ExpectValidation(
            () => BoundedIO.EnsureLength(
                ResourceLimits.AuthoredLedgerBytes + 1,
                ResourceLimits.AuthoredLedgerBytes,
                "authored source ledger"),
            "authored source ledger one byte over");
        EvidenceCommand.EnsureSerializedOutput(ResourceLimits.SerializedArtifactBytes);
        ExpectValidation(
            () => EvidenceCommand.EnsureSerializedOutput(
                ResourceLimits.SerializedArtifactBytes + 1),
            "serialized evidence output one byte over");
    }

    private static void TestCliSubprocesses(string repositoryRoot, string pluginRoot)
    {
        var root = Path.Combine(repositoryRoot, "artifacts", "readiness-evidence-cli-tests");
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }

        Directory.CreateDirectory(root);
        try
        {
            var packagePath = Path.Combine(root, "Sample.Widgets.1.2.3.nupkg");
            CreatePackage(packagePath, "Sample.Widgets", "1.2.3");
            var inspected = EvidenceIdentity.FromInspectedPackage(
                NupkgInspector.Inspect(packagePath));
            var subject = new RepositoryLedgerSubject(inspected);
            var assessment = new ExactAssessmentIdentity(inspected, "Tree");
            var subjectPath = Path.Combine(root, "repository-subject.json");
            var assessmentPath = Path.Combine(root, "assessment.json");
            var repositoryDraftPath = Path.Combine(root, "repository-draft.json");
            var componentDraftPath = Path.Combine(root, "component-draft.json");
            var repositoryLedgerPath = Path.Combine(root, "repository-ledger.json");
            var componentLedgerPath = Path.Combine(root, "component-ledger.json");
            var bundlePath = Path.Combine(root, "bundle.json");

            File.WriteAllBytes(
                subjectPath,
                CanonicalEvidenceJson.SerializeRepositorySubject(subject));
            File.WriteAllBytes(
                assessmentPath,
                CanonicalEvidenceJson.SerializeAssessment(assessment));
            File.WriteAllText(
                repositoryDraftPath,
                DraftJson(RepositoryDraft(
                    EvidenceIdentity.OwnerDeclaredUnavailable,
                    "source",
                    "The package owner declared source unavailable.")),
                new UTF8Encoding(false));
            File.WriteAllText(
                componentDraftPath,
                DraftJson(ComponentDraft("Tree")),
                new UTF8Encoding(false));

            var validatorDirectory = Path.Combine(
                pluginRoot,
                "skills",
                "blazor-component-readiness",
                "scripts",
                "validator");
            var buildRoot = Path.Combine(root, "validator-build");
            var environment = new Dictionary<string, string>
            {
                ["READINESS_TEMP"] = buildRoot
            };
            RunProcess(
                "bash",
                [
                    Path.Combine(validatorDirectory, "run-validator.sh"),
                    "evidence",
                    "ledger-build",
                    "--kind",
                    "repository",
                    "--subject",
                    subjectPath,
                    "--draft",
                    repositoryDraftPath,
                    "--nupkg",
                    packagePath,
                    "--output",
                    repositoryLedgerPath
                ],
                repositoryRoot,
                environment,
                expectedExitCode: 0);

            var validatorDll = Path.Combine(
                buildRoot,
                "bin",
                "Release",
                "net11.0",
                "BlazorComponentReadiness.Validator.dll");
            RunProcess(
                "dotnet",
                [
                    validatorDll,
                    "evidence",
                    "ledger-validate",
                    "--ledger",
                    repositoryLedgerPath
                ],
                repositoryRoot,
                environment,
                expectedExitCode: 0);
            RunProcess(
                "dotnet",
                [
                    validatorDll,
                    "evidence",
                    "ledger-build",
                    "--kind",
                    "component",
                    "--subject",
                    assessmentPath,
                    "--draft",
                    componentDraftPath,
                    "--nupkg",
                    packagePath,
                    "--output",
                    componentLedgerPath
                ],
                repositoryRoot,
                environment,
                expectedExitCode: 0);

            var repositoryLedger = CanonicalEvidenceJson.ParseSourceLedger(
                File.ReadAllBytes(repositoryLedgerPath));
            var componentLedger = CanonicalEvidenceJson.ParseSourceLedger(
                File.ReadAllBytes(componentLedgerPath));
            var selected = string.Join(
                ',',
                repositoryLedger.Records[0].StableId,
                componentLedger.Records[0].StableId);
            RunProcess(
                "dotnet",
                [
                    validatorDll,
                    "evidence",
                    "bundle",
                    "--assessment",
                    assessmentPath,
                    "--source-ledger",
                    componentLedgerPath,
                    "--source-ledger",
                    repositoryLedgerPath,
                    "--ids",
                    selected,
                    "--output",
                    bundlePath
                ],
                repositoryRoot,
                environment,
                expectedExitCode: 0);
            var bundle = CanonicalEvidenceJson.ParseBundle(File.ReadAllBytes(bundlePath));
            AssertSequence(
                selected.Split(','),
                bundle.Selection.Select(selection => selection.EvidenceId),
                "CLI bundle selection order");
            AssertSequence(
                bundle.SourceLedgers
                    .Select(source => source.SourceLedgerSha256)
                    .Order(StringComparer.Ordinal),
                bundle.SourceLedgers.Select(source => source.SourceLedgerSha256),
                "CLI source-ledger digest ordering");

            var mismatchedSubjects = new[]
            {
                subject with
                {
                    Package = subject.Package with { PackageId = "other.widgets" }
                },
                subject with
                {
                    Package = subject.Package with { Version = "1.2.4" }
                },
                subject with
                {
                    Package = subject.Package with
                    {
                        NupkgDigest = new Sha256Digest("sha256", new string('f', 64))
                    }
                },
            };
            for (var index = 0; index < mismatchedSubjects.Length; index++)
            {
                var mismatchedSubjectPath = Path.Combine(root, $"mismatched-subject-{index}.json");
                File.WriteAllBytes(
                    mismatchedSubjectPath,
                    CanonicalEvidenceJson.SerializeRepositorySubject(mismatchedSubjects[index]));
                var mismatch = RunProcess(
                    "dotnet",
                    [
                        validatorDll,
                        "evidence",
                        "ledger-build",
                        "--kind",
                        "repository",
                        "--subject",
                        mismatchedSubjectPath,
                        "--draft",
                        repositoryDraftPath,
                        "--nupkg",
                        packagePath,
                        "--output",
                        Path.Combine(root, $"must-not-exist-{index}.json")
                    ],
                    repositoryRoot,
                    environment,
                    expectedExitCode: 1);
                Assert(
                    mismatch.StandardError.Contains(
                        "exact nupkg ID, version, or digest",
                        StringComparison.Ordinal),
                    $"CLI exact package mismatch {index}");
            }

            AssertEqual(
                2,
                RunProcess(
                    "dotnet",
                    [validatorDll, "evidence", "ledger-build"],
                    repositoryRoot,
                    environment,
                    expectedExitCode: 2).ExitCode,
                "CLI usage exit");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static ExactAssessmentIdentity KnownAssessment() =>
        CanonicalEvidenceJson.ParseAssessment(Encoding.UTF8.GetBytes(KnownAssessmentJson));

    private static RepositoryLedgerSubject KnownRepositorySubject() =>
        new(KnownAssessment().Package);

    private static EvidenceRecordDraft RepositoryDraft(
        string kind,
        string locator,
        string claim) =>
        new(
            claim,
            new EvidenceApplicability("repository-wide", null),
            new EvidenceProvenance(
                kind,
                locator,
                "Captured evidence deterministically.",
                "2026-09-02T20:00:00Z",
                new Sha256Digest("sha256", new string('b', 64)),
                "commitment-only"),
            []);

    private static EvidenceRecordDraft ComponentDraft(string componentId) =>
        new(
            "The component keyboard probe completed successfully.",
            new EvidenceApplicability("component-specific", componentId),
            new EvidenceProvenance(
                EvidenceIdentity.ReproducedRuntimeObservation,
                "dotnet test Tree.Keyboard",
                "Ran the retained component probe.",
                "2026-09-02T20:00:00Z",
                new Sha256Digest("sha256", new string('e', 64)),
                "commitment-only"),
            []);

    private static EvidenceRecordDraft ToDraft(EvidenceRecord record) =>
        new(
            record.Claim,
            record.Applicability,
            record.Provenance,
            record.Supersedes);

    private static string DraftJson(EvidenceRecordDraft draft)
    {
        static string Escape(string value) =>
            value.Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("\"", "\\\"", StringComparison.Ordinal);

        var componentId = draft.Applicability.ComponentId is null
            ? "null"
            : $"\"{Escape(draft.Applicability.ComponentId)}\"";
        var supersedes = string.Join(
            ',',
            draft.Supersedes.Select(value => $"\"{Escape(value)}\""));
        return
            $$"""{"schema_version":1,"records":[{"claim":"{{Escape(draft.Claim)}}","applicability":{"scope":"{{draft.Applicability.Scope}}","component_id":{{componentId}}},"provenance":{"kind":"{{draft.Provenance.Kind}}","locator":"{{Escape(draft.Provenance.Locator)}}","method":"{{Escape(draft.Provenance.Method)}}","captured_at_utc":"{{draft.Provenance.CapturedAtUtc}}","content_sha256":{"algorithm":"sha256","value":"{{draft.Provenance.ContentDigest.Value}}"},"retention":"commitment-only"},"supersedes":[{{supersedes}}]}]}""";
    }

    private static void CreatePackage(string path, string id, string version)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create);
        var entry = archive.CreateEntry($"{id}.nuspec", CompressionLevel.NoCompression);
        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        writer.Write(
            $"<package><metadata><id>{id}</id><version>{version}</version></metadata></package>");
    }

    private static ProcessResult RunProcess(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string> environment,
        int expectedExitCode)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        foreach (var pair in environment)
        {
            startInfo.Environment[pair.Key] = pair.Value;
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start {executable}.");
        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();
        var result = new ProcessResult(process.ExitCode, standardOutput, standardError);
        Assert(
            result.ExitCode == expectedExitCode,
            $"{executable} exit code: expected {expectedExitCode}, actual {result.ExitCode}.\n{result}");
        return result;
    }

    private static void ExpectValidation(Action action, string name)
    {
        _ = CaptureValidation(action, name);
    }

    private static DeterministicValidationException CaptureValidation(
        Action action,
        string name = "validation")
    {
        try
        {
            action();
        }
        catch (DeterministicValidationException exception)
        {
            return exception;
        }

        throw new InvalidOperationException($"{name}: expected deterministic validation failure.");
    }

    private static void AssertBytes(byte[] expected, byte[] actual, string name) =>
        Assert(expected.AsSpan().SequenceEqual(actual), $"{name}: byte mismatch.");

    private static void AssertSequence<T>(
        IEnumerable<T> expected,
        IEnumerable<T> actual,
        string name)
    {
        var expectedArray = expected.ToArray();
        var actualArray = actual.ToArray();
        Assert(
            expectedArray.SequenceEqual(actualArray),
            $"{name}: expected [{string.Join(", ", expectedArray)}], " +
            $"actual [{string.Join(", ", actualArray)}].");
    }

    private static void AssertEqual<T>(T expected, T actual, string name) =>
        Assert(
            EqualityComparer<T>.Default.Equals(expected, actual),
            $"{name}: expected '{expected}', actual '{actual}'.");

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record ProcessResult(
        int ExitCode,
        string StandardOutput,
        string StandardError)
    {
        public override string ToString() =>
            $"stdout:\n{StandardOutput}\nstderr:\n{StandardError}";
    }
}
