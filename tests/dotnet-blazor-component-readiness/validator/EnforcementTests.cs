using System.IO.Compression;
using System.Text;
using System.Text.Json;
using BlazorComponentReadiness.Validator.Assessment;
using BlazorComponentReadiness.Validator.Cli;
using BlazorComponentReadiness.Validator.Comparison;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Validation;

internal static class EnforcementTests
{
    private static readonly string[] LifecycleOperations =
    [
        "add-child",
        "remove-child",
        "keyed-reorder",
        "disable-or-remove-selected-child",
        "membership-reconciliation",
        "propagated-name-default-value-state",
        "focus-ownership-restoration",
        "single-roving-tab-stop",
        "callbacks-error-routing",
        "cleanup-disposal"
    ];

    public static void Run(string repositoryRoot, string pluginRoot)
    {
        var root = Path.Combine(repositoryRoot, "artifacts", "readiness-enforcement-tests");
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }

        Directory.CreateDirectory(root);
        var previousSkillRoot = Environment.GetEnvironmentVariable("READINESS_SKILL_ROOT");
        Environment.SetEnvironmentVariable(
            "READINESS_SKILL_ROOT",
            Path.Combine(pluginRoot, "skills", "blazor-component-readiness"));
        try
        {
            TestStructuredVerifiedBoundaries(root);
            TestDynamicLifecycleMatrix(root);
            TestToolchainDisposition(root);
            TestComparisonInputGate(root);
        }
        finally
        {
            Environment.SetEnvironmentVariable("READINESS_SKILL_ROOT", previousSkillRoot);
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static void TestStructuredVerifiedBoundaries(string root)
    {
        var fixture = CreateFixture(Path.Combine(root, "boundaries"), lifecycleRequired: false);
        var weakCases = new[]
        {
            ("LP-04", EvidenceIdentity.PackageArtifactMetadata, "package:entry/README.md"),
            ("PI-02", EvidenceIdentity.PackageArtifactMetadata, "package:entry/lib/net11.0/Synthetic.Controls.dll"),
            ("SUP-01", EvidenceIdentity.OwnerSuppliedPublicEvidence, "owner-contact.txt")
        };
        File.WriteAllText(
            Path.Combine(fixture.Root, "owner-contact.txt"),
            "Organization and contact metadata only.",
            new UTF8Encoding(false));
        foreach (var (rowId, kind, locator) in weakCases)
        {
            var input = kind == EvidenceIdentity.OwnerSuppliedPublicEvidence
                ? fixture.Manifest with
                {
                    OwnerInputs =
                    [
                        CreateOwnerInput(
                            fixture.Root,
                            "owner-contact.txt",
                            EvidenceIdentity.OwnerSuppliedPublicEvidence)
                    ]
                }
                : fixture.Manifest;
            var inputBytes = InputManifestService.Serialize(input);
            var initialized = AssessmentService.Initialize(
                "package",
                fixture.Root,
                input,
                inputBytes,
                null,
                []);
            var digest = kind == EvidenceIdentity.OwnerSuppliedPublicEvidence
                ? input.OwnerInputs.Single().ContentDigest
                : new Sha256Digest(
                    "sha256",
                    NupkgInspector.ComputeEvidenceContentSha256(fixture.NupkgPath, locator));
            var weakEvidence = BuildEvidence(
                initialized.Identity,
                [
                    Draft(
                        initialized.Identity,
                        kind,
                        locator,
                        "Captured only a weak metadata hint.",
                        digest)
                ]);
            var weakAssessment = CompleteRows(
                initialized,
                new Dictionary<string, RowConclusion>(StringComparer.Ordinal)
                {
                    [rowId] = Verified(weakEvidence.Selection.Single().EvidenceId)
                });
            ExpectValidation(
                () => Validate(
                    fixture.Root,
                    input,
                    inputBytes,
                    weakAssessment,
                    weakEvidence),
                $"{rowId} weak hint cannot verify");
        }

        WriteFile(fixture.Root, "dependencies.json", "{\"dependencies\":[\"alpha\"]}");
        WriteFile(fixture.Root, "assets.json", "{\"assets\":[\"bundle.js\"]}");
        WriteFile(fixture.Root, "notices.json", "{\"mapping\":{\"bundle.js\":\"alpha\"}}");
        var dependency = CreateEvidenceInput(fixture.Root, "dependencies.json", "dependency-inventory");
        var assets = CreateEvidenceInput(fixture.Root, "assets.json", "bundled-asset-inventory");
        var notices = CreateEvidenceInput(fixture.Root, "notices.json", "notice-mapping");
        var noticeProtocolBytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "notice-coverage");
            writer.WriteString("coverage", "complete");
            WriteDigest(writer, "dependency_inventory_sha256", dependency.ContentDigest);
            WriteDigest(writer, "bundled_asset_inventory_sha256", assets.ContentDigest);
            WriteDigest(writer, "notice_mapping_sha256", notices.ContentDigest);
            writer.WriteEndObject();
        });
        File.WriteAllBytes(Path.Combine(fixture.Root, "notice-protocol.json"), noticeProtocolBytes);
        var noticeProtocol = CreateEvidenceInput(
            fixture.Root,
            "notice-protocol.json",
            "structured-protocol");

        WriteFile(fixture.Root, "authenticode.log", "Signature verification completed for the exact artifact.");
        var authenticodeLog = CreateEvidenceInput(
            fixture.Root,
            "authenticode.log",
            "authenticode-log");
        var dll = NupkgInspector.GetFileEntryDigests(fixture.NupkgPath, ".dll").Single();
        var authenticodeProtocolBytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "authenticode-verification");
            writer.WritePropertyName("artifacts");
            writer.WriteStartArray();
            writer.WriteStartObject();
            writer.WriteString("package_entry", dll.Key);
            WriteDigest(writer, "artifact_sha256", new Sha256Digest("sha256", dll.Value));
            writer.WriteString("expected_identity", "Synthetic release signing identity");
            writer.WriteString("observed_identity", "Synthetic release signing identity");
            writer.WriteString("file_digest_disposition", "valid");
            writer.WriteString("chain_disposition", "valid");
            writer.WriteString("timestamp_disposition", "valid");
            writer.WriteString("revocation_disposition", "not-applicable");
            WriteDigest(writer, "raw_observation_sha256", authenticodeLog.ContentDigest);
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
        });
        File.WriteAllBytes(
            Path.Combine(fixture.Root, "authenticode-protocol.json"),
            authenticodeProtocolBytes);
        var authenticodeProtocol = CreateEvidenceInput(
            fixture.Root,
            "authenticode-protocol.json",
            "structured-protocol");

        var supportProtocolBytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "support-ownership");
            writer.WriteString("accountable_role", "Release support owner");
            writer.WriteString("accountable_owner", "Component support rotation");
            writer.WriteString("scope", "Synthetic.Controls package line");
            writer.WriteString("backup_owner", "Secondary component support rotation");
            writer.WriteString("escalation_path", "Escalate through the release incident channel");
            writer.WriteString("effective_at_utc", "2026-09-03T00:00:00Z");
            writer.WriteEndObject();
        });
        File.WriteAllBytes(
            Path.Combine(fixture.Root, "support-ownership.json"),
            supportProtocolBytes);
        var supportOwner = CreateOwnerInput(
            fixture.Root,
            "support-ownership.json",
            EvidenceIdentity.OwnerSuppliedPublicEvidence);

        var strongInput = fixture.Manifest with
        {
            EvidenceInputs = new[]
            {
                assets,
                authenticodeLog,
                authenticodeProtocol,
                dependency,
                noticeProtocol,
                notices
            }.OrderBy(item => item.Basename, StringComparer.Ordinal).ToArray(),
            OwnerInputs = [supportOwner]
        };
        var strongInputBytes = InputManifestService.Serialize(strongInput);
        InputManifestService.Validate(strongInput, fixture.Root, requireConfirmed: true);
        var package = AssessmentService.Initialize(
            "package",
            fixture.Root,
            strongInput,
            strongInputBytes,
            null,
            []);
        var evidence = BuildEvidence(
            package.Identity,
            [
                Draft(
                    package.Identity,
                    EvidenceIdentity.ReviewerGeneratedAnalysis,
                    noticeProtocol.Basename,
                    EvidenceProtocolValidator.NoticeCoverageMethod,
                    noticeProtocol.ContentDigest),
                Draft(
                    package.Identity,
                    EvidenceIdentity.ReproducedRuntimeObservation,
                    authenticodeProtocol.Basename,
                    EvidenceProtocolValidator.AuthenticodeMethod,
                    authenticodeProtocol.ContentDigest),
                Draft(
                    package.Identity,
                    EvidenceIdentity.OwnerSuppliedPublicEvidence,
                    supportOwner.Basename,
                    EvidenceProtocolValidator.SupportOwnershipMethod,
                    supportOwner.ContentDigest)
            ]);
        var ids = evidence.SourceLedgers.Single().Ledger.Records.ToDictionary(
            record => record.Provenance.Method,
            record => record.StableId,
            StringComparer.Ordinal);
        var assessment = CompleteRows(
            package,
            new Dictionary<string, RowConclusion>(StringComparer.Ordinal)
            {
                ["LP-04"] = Verified(ids[EvidenceProtocolValidator.NoticeCoverageMethod]),
                ["PI-02"] = Verified(ids[EvidenceProtocolValidator.AuthenticodeMethod]),
                ["SUP-01"] = Verified(ids[EvidenceProtocolValidator.SupportOwnershipMethod])
            });
        Validate(fixture.Root, strongInput, strongInputBytes, assessment, evidence);

        var incompleteNoticeBytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "notice-coverage");
            writer.WriteString("coverage", "incomplete");
            WriteDigest(writer, "dependency_inventory_sha256", dependency.ContentDigest);
            WriteDigest(writer, "bundled_asset_inventory_sha256", assets.ContentDigest);
            WriteDigest(writer, "notice_mapping_sha256", notices.ContentDigest);
            writer.WriteEndObject();
        });
        File.WriteAllBytes(
            Path.Combine(fixture.Root, "notice-incomplete.json"),
            incompleteNoticeBytes);
        var incompleteNotice = CreateEvidenceInput(
            fixture.Root,
            "notice-incomplete.json",
            "structured-protocol");
        var gapInput = strongInput with
        {
            EvidenceInputs = strongInput.EvidenceInputs
                .Append(incompleteNotice)
                .OrderBy(item => item.Basename, StringComparer.Ordinal)
                .ToArray()
        };
        var gapInputBytes = InputManifestService.Serialize(gapInput);
        var gapPackage = AssessmentService.Initialize(
            "package",
            fixture.Root,
            gapInput,
            gapInputBytes,
            null,
            []);
        var gapEvidence = BuildEvidence(
            gapPackage.Identity,
            [
                Draft(
                    gapPackage.Identity,
                    EvidenceIdentity.ReviewerGeneratedAnalysis,
                    incompleteNotice.Basename,
                    EvidenceProtocolValidator.NoticeCoverageMethod,
                    incompleteNotice.ContentDigest)
            ]);
        var gapId = gapEvidence.Selection.Single().EvidenceId;
        var gapAssessment = CompleteRows(
            gapPackage,
            new Dictionary<string, RowConclusion>(StringComparer.Ordinal)
            {
                ["LP-04"] = new RowConclusion(
                    "gap",
                    "The exact inventory shows that required notice coverage is incomplete.",
                    [gapId],
                    null,
                    null,
                    null)
            });
        Validate(fixture.Root, gapInput, gapInputBytes, gapAssessment, gapEvidence);

        var failedAuthenticodeBytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "authenticode-verification");
            writer.WritePropertyName("artifacts");
            writer.WriteStartArray();
            writer.WriteStartObject();
            writer.WriteString("package_entry", dll.Key);
            WriteDigest(writer, "artifact_sha256", new Sha256Digest("sha256", dll.Value));
            writer.WriteString("expected_identity", "Synthetic release signing identity");
            writer.WriteString("observed_identity", "Unexpected signing identity");
            writer.WriteString("file_digest_disposition", "invalid");
            writer.WriteString("chain_disposition", "not-tested");
            writer.WriteString("timestamp_disposition", "not-tested");
            writer.WriteString("revocation_disposition", "not-tested");
            WriteDigest(writer, "raw_observation_sha256", authenticodeLog.ContentDigest);
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
        });
        File.WriteAllBytes(
            Path.Combine(fixture.Root, "authenticode-failed.json"),
            failedAuthenticodeBytes);
        var failedAuthenticode = CreateEvidenceInput(
            fixture.Root,
            "authenticode-failed.json",
            "structured-protocol");
        var authGapInput = strongInput with
        {
            EvidenceInputs = strongInput.EvidenceInputs
                .Append(failedAuthenticode)
                .OrderBy(item => item.Basename, StringComparer.Ordinal)
                .ToArray()
        };
        var authGapInputBytes = InputManifestService.Serialize(authGapInput);
        var authGapPackage = AssessmentService.Initialize(
            "package",
            fixture.Root,
            authGapInput,
            authGapInputBytes,
            null,
            []);
        var authGapEvidence = BuildEvidence(
            authGapPackage.Identity,
            [
                Draft(
                    authGapPackage.Identity,
                    EvidenceIdentity.ReproducedRuntimeObservation,
                    failedAuthenticode.Basename,
                    EvidenceProtocolValidator.AuthenticodeMethod,
                    failedAuthenticode.ContentDigest)
            ]);
        var authGapId = authGapEvidence.Selection.Single().EvidenceId;
        var authGapAssessment = CompleteRows(
            authGapPackage,
            new Dictionary<string, RowConclusion>(StringComparer.Ordinal)
            {
                ["PI-02"] = new RowConclusion(
                    "gap",
                    "Direct verification found an unexpected identity and invalid file digest.",
                    [authGapId],
                    null,
                    null,
                    null)
            });
        Validate(
            fixture.Root,
            authGapInput,
            authGapInputBytes,
            authGapAssessment,
            authGapEvidence);
    }

    private static void TestDynamicLifecycleMatrix(string root)
    {
        var fixture = CreateFixture(Path.Combine(root, "lifecycle"), lifecycleRequired: true);
        var rawInputs = new List<InputEvidenceArtifact>();
        var rawDigests = new Dictionary<string, Sha256Digest>(StringComparer.Ordinal);
        foreach (var operation in LifecycleOperations)
        {
            var basename = $"raw-{operation}.json";
            WriteFile(
                fixture.Root,
                basename,
                $"{{\"operation\":\"{operation}\",\"phase\":\"after-initial-render\",\"outcome\":\"passed\"}}");
            var rawInput = CreateEvidenceInput(fixture.Root, basename, "raw-observation");
            rawInputs.Add(rawInput);
            rawDigests.Add(operation, rawInput.ContentDigest);
        }

        var protocolBytes = LifecycleProtocol(rawDigests);
        File.WriteAllBytes(Path.Combine(fixture.Root, "lifecycle-protocol.json"), protocolBytes);
        var protocolInput = CreateEvidenceInput(
            fixture.Root,
            "lifecycle-protocol.json",
            "structured-protocol");
        var input = fixture.Manifest with
        {
            EvidenceInputs = rawInputs
                .Append(protocolInput)
                .OrderBy(item => item.Basename, StringComparer.Ordinal)
                .ToArray()
        };
        var inputBytes = InputManifestService.Serialize(input);
        var initialized = AssessmentService.Initialize(
            "unified",
            fixture.Root,
            input,
            inputBytes,
            "dynamic-group",
            []);
        var evidence = BuildEvidence(
            initialized.Identity,
            [
                Draft(
                    initialized.Identity,
                    EvidenceIdentity.ReproducedRuntimeObservation,
                    protocolInput.Basename,
                    EvidenceProtocolValidator.LifecycleMethod,
                    protocolInput.ContentDigest)
            ]);
        var evidenceId = evidence.Selection.Single().EvidenceId;
        var conclusions = new Dictionary<string, RowConclusion>(StringComparer.Ordinal);
        foreach (var rowId in new[] { "A11Y-06", "A11Y-07", "A11Y-08", "BEQ-12", "BEQ-15" })
        {
            conclusions[rowId] = Verified(evidenceId);
        }

        var assessment = CompleteRows(initialized, conclusions);
        Validate(fixture.Root, input, inputBytes, assessment, evidence);

        var listedOnly = input with
        {
            EvidenceInputs = input.EvidenceInputs
                .Where(item => item.Basename != protocolInput.Basename)
                .ToArray()
        };
        WriteFile(
            fixture.Root,
            "listed-only.json",
            "{\"schema_version\":1,\"protocol\":\"dynamic-child-lifecycle\",\"operations\":[]}");
        var listedInput = CreateEvidenceInput(
            fixture.Root,
            "listed-only.json",
            "structured-protocol");
        listedOnly = listedOnly with
        {
            EvidenceInputs = listedOnly.EvidenceInputs
                .Append(listedInput)
                .OrderBy(item => item.Basename, StringComparer.Ordinal)
                .ToArray()
        };
        var listedBytes = InputManifestService.Serialize(listedOnly);
        var listedInitialized = AssessmentService.Initialize(
            "unified",
            fixture.Root,
            listedOnly,
            listedBytes,
            "dynamic-group",
            []);
        var listedEvidence = BuildEvidence(
            listedInitialized.Identity,
            [
                Draft(
                    listedInitialized.Identity,
                    EvidenceIdentity.ReproducedRuntimeObservation,
                    listedInput.Basename,
                    EvidenceProtocolValidator.LifecycleMethod,
                    listedInput.ContentDigest)
            ]);
        var listedAssessment = CompleteRows(
            listedInitialized,
            conclusions.ToDictionary(
                item => item.Key,
                _ => Verified(listedEvidence.Selection.Single().EvidenceId),
                StringComparer.Ordinal));
        ExpectValidation(
            () => Validate(
                fixture.Root,
                listedOnly,
                listedBytes,
                listedAssessment,
                listedEvidence),
            "listing lifecycle matrix without post-initialization observations");

        var notTestedDigests = rawDigests.ToDictionary(
            item => item.Key,
            item => item.Value,
            StringComparer.Ordinal);
        var blockedProtocolBytes = LifecycleProtocol(
            notTestedDigests,
            blockedOperation: "keyed-reorder");
        File.WriteAllBytes(
            Path.Combine(fixture.Root, "lifecycle-blocked.json"),
            blockedProtocolBytes);
        var blockedProtocol = CreateEvidenceInput(
            fixture.Root,
            "lifecycle-blocked.json",
            "structured-protocol");
        var blockedInput = input with
        {
            EvidenceInputs = input.EvidenceInputs
                .Where(item => item.Basename != protocolInput.Basename)
                .Append(blockedProtocol)
                .OrderBy(item => item.Basename, StringComparer.Ordinal)
                .ToArray()
        };
        var blockedBytes = InputManifestService.Serialize(blockedInput);
        var blockedInitialized = AssessmentService.Initialize(
            "unified",
            fixture.Root,
            blockedInput,
            blockedBytes,
            "dynamic-group",
            []);
        var blockedEvidence = BuildEvidence(
            blockedInitialized.Identity,
            [
                Draft(
                    blockedInitialized.Identity,
                    EvidenceIdentity.ReproducedRuntimeObservation,
                    blockedProtocol.Basename,
                    EvidenceProtocolValidator.LifecycleMethod,
                    blockedProtocol.ContentDigest)
            ]);
        var blockedId = blockedEvidence.Selection.Single().EvidenceId;
        var blockedConclusions = conclusions.ToDictionary(
            item => item.Key,
            _ => Verified(blockedId),
            StringComparer.Ordinal);
        blockedConclusions["A11Y-06"] = new RowConclusion(
            "not tested",
            "The keyed reorder operation was blocked because the synthetic host omitted stable keys.",
            [blockedId],
            null,
            "Rerun keyed reorder with stable child keys and retain the raw observation.",
            null);
        Validate(
            fixture.Root,
            blockedInput,
            blockedBytes,
            CompleteRows(blockedInitialized, blockedConclusions),
            blockedEvidence);
    }

    private static void TestToolchainDisposition(string root)
    {
        var fixture = CreateFixture(Path.Combine(root, "toolchain"), lifecycleRequired: false);
        WriteFile(fixture.Root, "trim.log", "Supported toolchain emitted one package warning.");
        var rawLog = CreateEvidenceInput(fixture.Root, "trim.log", "toolchain-log");
        var protocolBytes = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "toolchain-probe");
            writer.WriteString("toolchain_name", "Synthetic .NET SDK");
            writer.WriteString("toolchain_version", "11.0.100-preview.7");
            writer.WriteString("target_framework", "net11.0");
            writer.WriteString("support_disposition", "supported");
            writer.WriteString("command", "dotnet publish -p:PublishTrimmed=true");
            writer.WriteString("result", "failed");
            WriteDigest(writer, "raw_log_sha256", rawLog.ContentDigest);
            writer.WriteEndObject();
        });
        File.WriteAllBytes(Path.Combine(fixture.Root, "toolchain-protocol.json"), protocolBytes);
        var protocol = CreateEvidenceInput(
            fixture.Root,
            "toolchain-protocol.json",
            "structured-protocol");
        var input = fixture.Manifest with
        {
            EvidenceInputs = new[] { rawLog, protocol }
                .OrderBy(item => item.Basename, StringComparer.Ordinal)
                .ToArray()
        };
        var inputBytes = InputManifestService.Serialize(input);
        var initialized = AssessmentService.Initialize(
            "unified",
            fixture.Root,
            input,
            inputBytes,
            "static-control",
            []);
        var evidence = BuildEvidence(
            initialized.Identity,
            [
                Draft(
                    initialized.Identity,
                    EvidenceIdentity.ReproducedRuntimeObservation,
                    protocol.Basename,
                    EvidenceProtocolValidator.ToolchainMethod,
                    protocol.ContentDigest)
            ]);
        var id = evidence.Selection.Single().EvidenceId;
        var assessment = CompleteRows(
            initialized,
            new Dictionary<string, RowConclusion>(StringComparer.Ordinal)
            {
                ["TA-02"] = new RowConclusion(
                    "gap",
                    "The supported named toolchain emitted a package-attributable trimming warning.",
                    [id],
                    null,
                    null,
                    null),
                ["TA-04"] = new RowConclusion(
                    "not tested",
                    "Reachability analysis was blocked because detailed linker diagnostics were unavailable.",
                    [],
                    null,
                    "Rerun with detailed linker diagnostics and retain the exact supported-toolchain log.",
                    null)
            });
        Validate(fixture.Root, input, inputBytes, assessment, evidence);

        var unresolved = assessment with
        {
            Rows = assessment.Rows.Select(row =>
                row.Id == "TA-04"
                    ? row with
                    {
                        Status = "not tested",
                        Observation = null
                    }
                    : row).ToArray()
        };
        ExpectValidation(
            () => Validate(fixture.Root, input, inputBytes, unresolved, evidence),
            "trim comparison row requires exact blocker");
    }

    private static void TestComparisonInputGate(string root)
    {
        var fixtureRoot = Path.Combine(root, "comparison");
        Directory.CreateDirectory(fixtureRoot);
        var nupkg = Path.Combine(fixtureRoot, "package.bin");
        CreatePackage(nupkg);
        WriteFile(fixtureRoot, "source.bin", "exact source archive bytes");
        WriteFile(fixtureRoot, "retrieval.bin", "HTTP 200 raw response metadata");
        WriteFile(fixtureRoot, "sdk.bin", "Synthetic SDK 11.0.100");
        WriteFile(fixtureRoot, "browser.bin", "Synthetic Browser 1.0");
        WriteFile(fixtureRoot, "trim.bin", "raw trim output");
        var inspected = NupkgInspector.Inspect(nupkg);
        var draft = CreateComparisonDraft(inspected, includeToolchain: true);
        var manifest = ComparisonInputService.Freeze(
            fixtureRoot,
            Encoding.UTF8.GetBytes(draft));
        var bytes = ComparisonInputService.Serialize(manifest);
        ComparisonInputService.Validate(
            ComparisonInputService.Parse(bytes),
            fixtureRoot);
        var draftPath = Path.Combine(fixtureRoot, "comparison-inputs.draft.json");
        var confirmedPath = Path.Combine(fixtureRoot, "comparison-inputs.confirmed.json");
        File.WriteAllText(draftPath, draft, new UTF8Encoding(false));
        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "comparison",
                    "inputs-freeze",
                    "--root",
                    fixtureRoot,
                    "--draft",
                    draftPath,
                    "--output",
                    confirmedPath
                ],
                output,
                error),
            $"comparison freeze CLI: {error}");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "comparison",
                    "inputs-validate",
                    "--root",
                    fixtureRoot,
                    "--manifest",
                    confirmedPath
                ],
                output,
                error),
            $"comparison validate CLI: {error}");

        var withoutToolchain = CreateComparisonDraft(inspected, includeToolchain: false);
        ExpectValidation(
            () => ComparisonInputService.Freeze(
                fixtureRoot,
                Encoding.UTF8.GetBytes(withoutToolchain)),
            "available trim probe requires named toolchain");

        WriteFile(fixtureRoot, "notes.bin", "{\"status\":\"verified\"}");
        var conclusionBearing = CreateComparisonDraft(
            inspected,
            includeToolchain: true,
            extraAllowedInput: ",{\"id\":\"notes\",\"kind\":\"raw-probe\",\"path\":\"notes.bin\"}",
            extraProbeInput: ",\"notes\"");
        ExpectValidation(
            () => ComparisonInputService.Freeze(
                fixtureRoot,
                Encoding.UTF8.GetBytes(conclusionBearing)),
            "comparison allowed input rejects conclusion material");

        var unresolved = CreateComparisonDraft(inspected, includeToolchain: true)
            .Replace(
                "\"disposition\":\"available\",\"blocker\":null,\"toolchain_id\":\"sdk\"",
                "\"disposition\":\"unresolved\",\"blocker\":null,\"toolchain_id\":\"sdk\"",
                StringComparison.Ordinal);
        ExpectValidation(
            () => ComparisonInputService.Freeze(
                fixtureRoot,
                Encoding.UTF8.GetBytes(unresolved)),
            "comparison dispositions cannot remain unresolved");
    }

    private static Fixture CreateFixture(string root, bool lifecycleRequired)
    {
        Directory.CreateDirectory(root);
        var nupkgPath = Path.Combine(root, "package.nupkg");
        CreatePackage(nupkgPath);
        WriteFile(root, "README.md", "# Synthetic package");
        var inspected = NupkgInspector.Inspect(nupkgPath);
        var lifecycle = lifecycleRequired
            ? new DynamicChildLifecycle(
                "required",
                ["grouped-children", "registered-children", "selected-children"],
                null)
            : new DynamicChildLifecycle(
                "not-applicable",
                [],
                "This synthetic control does not manage grouped, registered, selected, or composite children.");
        var manifest = new InputManifest(
            InputManifestService.SchemaVersion,
            "confirmed",
            "release-candidate",
            new InputPackage(
                "synthetic.controls",
                "1.0.0",
                new Sha256Digest("sha256", inspected.NupkgSha256),
                "package.nupkg",
                "package.nupkg",
                "local-file"),
            new InputSource(
                "closed-source",
                null,
                null,
                null,
                null),
            [new InputRetrievalAttempt("package", "package.nupkg", "local-file", "succeeded", null)],
            [],
            [],
            [],
            [],
            [],
            [
                new InputComponent(
                    lifecycleRequired ? "dynamic-group" : "static-control",
                    lifecycleRequired ? "Dynamic Group" : "Static Control",
                    ["interactive-server"],
                    [],
                    lifecycle)
            ],
            []);
        InputManifestService.Validate(manifest, root, requireConfirmed: true);
        return new Fixture(root, nupkgPath, manifest);
    }

    private static ReadinessAssessment CompleteRows(
        ReadinessAssessment initialized,
        IReadOnlyDictionary<string, RowConclusion> conclusions)
    {
        var rows = initialized.Rows.Select(row =>
        {
            if (conclusions.TryGetValue(row.Id, out var conclusion))
            {
                return row with
                {
                    Status = conclusion.Status,
                    Observation = conclusion.Observation,
                    EvidenceIds = conclusion.EvidenceIds,
                    OwnerAction = conclusion.OwnerAction,
                    AssessmentFollowUp = conclusion.AssessmentFollowUp,
                    NotApplicableRationale = conclusion.NotApplicableRationale
                };
            }

            return row with
            {
                Status = "not applicable",
                Observation = null,
                EvidenceIds = [],
                OwnerAction = null,
                AssessmentFollowUp = null,
                NotApplicableRationale =
                    "This synthetic enforcement fixture does not exercise this requirement."
            };
        }).ToArray();
        return initialized with
        {
            Rows = rows,
            SummaryGroups = initialized.AssessmentKind == "package"
                ? BuildSummaryGroups(rows)
                : [],
            CompletionState = "complete"
        };
    }

    private static RowConclusion Verified(string evidenceId) =>
        new(
            "verified",
            "The structured evidence protocol directly establishes this bounded requirement.",
            [evidenceId],
            null,
            null,
            null);

    private static EvidenceRecordDraft Draft(
        ExactAssessmentIdentity identity,
        string kind,
        string locator,
        string method,
        Sha256Digest digest) =>
        new(
            "The structured protocol records direct evidence for this bounded requirement.",
            identity.AssessmentKind == "component" ||
                method == EvidenceProtocolValidator.LifecycleMethod
                ? new EvidenceApplicability("component-specific", identity.ComponentId)
                : new EvidenceApplicability("repository-wide", null),
            new EvidenceProvenance(
                kind,
                locator,
                method,
                "2026-09-03T00:00:00Z",
                digest,
                "commitment-only"),
            []);

    private static EvidenceBundle BuildEvidence(
        ExactAssessmentIdentity identity,
        IReadOnlyList<EvidenceRecordDraft> drafts)
    {
        var repositoryDrafts = drafts
            .Where(draft => draft.Applicability.Scope == "repository-wide")
            .ToArray();
        var componentDrafts = drafts
            .Where(draft => draft.Applicability.Scope == "component-specific")
            .ToArray();
        var ledgers = new List<EvidenceSourceLedger>();
        if (repositoryDrafts.Length > 0)
        {
            ledgers.Add(EvidenceLedgerBuilder.BuildRepositoryLedger(
                new RepositoryLedgerSubject(
                    identity.AssessmentKind,
                    identity.Package,
                    identity.InputManifestDigest,
                    identity.ComponentId),
                repositoryDrafts));
        }

        if (componentDrafts.Length > 0)
        {
            ledgers.Add(EvidenceLedgerBuilder.BuildComponentLedger(identity, componentDrafts));
        }

        return EvidenceLedgerBuilder.BuildBundle(
            identity,
            ledgers,
            ledgers.SelectMany(ledger => ledger.Records)
                .Select(record => record.StableId)
                .ToArray());
    }

    private static void Validate(
        string root,
        InputManifest input,
        byte[] inputBytes,
        ReadinessAssessment assessment,
        EvidenceBundle evidence)
    {
        AssessmentService.Validate(
            root,
            assessment,
            AssessmentService.Serialize(assessment),
            input,
            inputBytes,
            evidence);
    }

    private static IReadOnlyList<AssessmentSummaryGroup> BuildSummaryGroups(
        IReadOnlyList<AssessmentRow> rows) =>
        RubricLoader.Load().Statuses
            .Select(status => new
            {
                Status = status,
                Rows = rows.Where(row => row.Status == status).ToArray()
            })
            .Where(group => group.Rows.Length > 0)
            .Select(group => new AssessmentSummaryGroup(
                group.Status,
                $"These package rows have the factual status '{group.Status}'.",
                group.Rows.Select(row => row.Id).ToArray(),
                group.Rows.SelectMany(row => row.EvidenceIds)
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray()))
            .ToArray();

    private static InputEvidenceArtifact CreateEvidenceInput(
        string root,
        string basename,
        string kind)
    {
        var bytes = File.ReadAllBytes(Path.Combine(root, basename));
        return new InputEvidenceArtifact(
            basename,
            kind,
            ContractJson.RawDigest(bytes),
            bytes.LongLength);
    }

    private static OwnerInput CreateOwnerInput(
        string root,
        string basename,
        string provenance)
    {
        var bytes = File.ReadAllBytes(Path.Combine(root, basename));
        return new OwnerInput(
            basename,
            provenance,
            ContractJson.RawDigest(bytes),
            bytes.LongLength);
    }

    private static byte[] LifecycleProtocol(
        IReadOnlyDictionary<string, Sha256Digest> digests,
        string? blockedOperation = null) =>
        StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "dynamic-child-lifecycle");
            writer.WritePropertyName("operations");
            writer.WriteStartArray();
            foreach (var operation in LifecycleOperations)
            {
                writer.WriteStartObject();
                writer.WriteString("operation", operation);
                if (operation == blockedOperation)
                {
                    writer.WriteString("disposition", "not-tested");
                    writer.WriteNull("outcome");
                    writer.WriteNull("raw_observation_sha256");
                    writer.WriteString(
                        "not_tested_reason",
                        "The synthetic host omitted stable child keys for this operation.");
                }
                else
                {
                    writer.WriteString("disposition", "observed");
                    writer.WriteString("outcome", "passed");
                    WriteDigest(writer, "raw_observation_sha256", digests[operation]);
                    writer.WriteNull("not_tested_reason");
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        });

    private static string CreateComparisonDraft(
        PackageIdentity package,
        bool includeToolchain,
        string extraAllowedInput = "",
        string extraProbeInput = "")
    {
        var toolchain = includeToolchain
            ? """
              [{"id":"sdk","name":"Synthetic .NET SDK","version":"11.0.100","disposition":"available","blocker":null,"input_ids":["sdk-version"]}]
              """
            : "[]";
        var toolchainId = includeToolchain ? "\"sdk\"" : "null";
        return $$"""
        {
          "schema_version": 1,
          "state": "draft",
          "package": {
            "package_id": "{{package.Id}}",
            "version": "{{package.Version}}",
            "nupkg_input_id": "package",
            "nupkg_sha256": {"algorithm":"sha256","value":"{{package.NupkgSha256}}"}
          },
          "source": {
            "availability": "source-available",
            "repository_uri": "https://code.example.test/synthetic/source",
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "archive_input_id": "source"
          },
          "allowed_inputs": [
            {"id":"browser-version","kind":"browser-identity","path":"browser.bin"},
            {"id":"package","kind":"nupkg","path":"package.bin"},
            {"id":"retrieval","kind":"retrieval-record","path":"retrieval.bin"},
            {"id":"sdk-version","kind":"toolchain-identity","path":"sdk.bin"},
            {"id":"source","kind":"source-archive","path":"source.bin"},
            {"id":"trim-log","kind":"probe-log","path":"trim.bin"}{{extraAllowedInput}}
          ],
          "toolchains": {{toolchain}},
          "browsers": [
            {"id":"browser","name":"Synthetic Browser","version":"1.0","disposition":"available","blocker":null,"input_ids":["browser-version"]}
          ],
          "retrievals": [
            {"id":"package-fetch","subject":"Exact package retrieval","locator":"https://packages.example.test/synthetic","disposition":"available","blocker":null,"toolchain_id":null,"browser_id":null,"input_ids":["retrieval"]}
          ],
          "probes": [
            {"id":"trim-probe","subject":"Supported trim comparison","locator":"local trim command","disposition":"available","blocker":null,"toolchain_id":{{toolchainId}},"browser_id":null,"input_ids":["trim-log"{{extraProbeInput}}]}
          ]
        }
        """;
    }

    private static void CreatePackage(string path)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        var nuspec = archive.CreateEntry("Synthetic.Controls.nuspec", CompressionLevel.NoCompression);
        nuspec.LastWriteTime = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using (var stream = nuspec.Open())
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: false))
        {
            writer.Write(
                "<package><metadata><id>Synthetic.Controls</id><version>1.0.0</version></metadata></package>");
        }

        var dll = archive.CreateEntry(
            "lib/net11.0/Synthetic.Controls.dll",
            CompressionLevel.NoCompression);
        dll.LastWriteTime = nuspec.LastWriteTime;
        using (var dllStream = dll.Open())
        {
            dllStream.Write(Encoding.UTF8.GetBytes("synthetic managed assembly bytes"));
        }

        var readme = archive.CreateEntry("README.md", CompressionLevel.NoCompression);
        readme.LastWriteTime = nuspec.LastWriteTime;
        using var readmeStream = readme.Open();
        readmeStream.Write(Encoding.UTF8.GetBytes("# Synthetic package"));
    }

    private static void WriteFile(string root, string relativePath, string content) =>
        File.WriteAllText(
            Path.Combine(root, relativePath),
            content,
            new UTF8Encoding(false));

    private static void WriteDigest(
        Utf8JsonWriter writer,
        string property,
        Sha256Digest digest)
    {
        writer.WritePropertyName(property);
        writer.WriteStartObject();
        writer.WriteString("algorithm", digest.Algorithm);
        writer.WriteString("value", digest.Value);
        writer.WriteEndObject();
    }

    private static void ExpectValidation(Action action, string name)
    {
        try
        {
            action();
            throw new InvalidOperationException(
                $"{name}: expected deterministic validation failure.");
        }
        catch (DeterministicValidationException)
        {
        }
    }

    private static void AssertEqual<T>(T expected, T actual, string name)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new InvalidOperationException(
                $"{name}: expected '{expected}', actual '{actual}'.");
        }
    }

    private sealed record Fixture(
        string Root,
        string NupkgPath,
        InputManifest Manifest);

    private sealed record RowConclusion(
        string Status,
        string? Observation,
        IReadOnlyList<string> EvidenceIds,
        string? OwnerAction,
        string? AssessmentFollowUp,
        string? NotApplicableRationale);
}
