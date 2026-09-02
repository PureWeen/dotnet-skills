using System.IO.Compression;
using System.Diagnostics;
using System.Text;
using BlazorComponentReadiness.Validator.Assessment;
using BlazorComponentReadiness.Validator.Cli;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Rendering;
using BlazorComponentReadiness.Validator.Validation;

internal static class AssessmentTests
{
    public static void Run(string repositoryRoot, string pluginRoot)
    {
        var root = Path.Combine(repositoryRoot, "artifacts", "readiness-commit4-tests");
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
            var fixture = CreateInputFixture(root);
            TestRubricAndInputContracts(fixture, pluginRoot);
            TestAssessmentKinds(fixture);
            TestStatusAndEvidenceBoundaries(fixture);
            TestCliAndRendering(fixture);
            TestCliSubprocess(fixture, pluginRoot);
            TestSnapshotMutation(root);
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

    private static Fixture CreateInputFixture(string root)
    {
        File.WriteAllText(Path.Combine(root, "docs.html"), "<h1>Official docs</h1>", new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(root, "package-readme.md"), "# Package README\n", new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(root, "owner-audit.txt"), "Retained owner audit evidence.", new UTF8Encoding(false));
        var nupkg = Path.Combine(root, "Sample.Widgets.01.002.000.nupkg");
        CreatePackage(nupkg, "Sample.Widgets", "01.002.000");
        var candidatesPath = Path.Combine(root, "candidates.json");
        File.WriteAllText(
            candidatesPath,
            """
            {
              "schema_version": 1,
              "acquisition": "release-candidate",
              "source": {
                "availability": "source-available",
                "repository_uri": "HTTPS://GitHub.Example.COM/Vendor/Widgets/",
                "commit": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "mapping": "Package metadata and source tag map to this commit.",
                "confidence": "HIGH"
              },
              "documentation": [
                {"url": "HTTPS://Docs.Example.COM/Widgets/", "content_path": "docs.html"}
              ],
              "package_sources": [
                {"kind": "package-readme", "locator": "package:entry/README.md", "content_path": "package-readme.md"}
              ],
              "owner_inputs": [
                {"path": "owner-audit.txt", "provenance": "owner-supplied-internal-evidence"}
              ],
              "components": [
                {"id": " Fancy Tree ", "display_name": "Fancy Tree", "render_modes": ["Server", "STATIC SSR", "WASM"]}
              ],
              "exclusions": [
                {"subject": "Mobile browser matrix", "rationale": "Explicitly outside this bounded assessment."}
              ]
            }
            """,
            new UTF8Encoding(false));
        var candidateBytes = File.ReadAllBytes(candidatesPath);
        var draft = InputManifestService.Discover(root, nupkg, candidateBytes);
        var draftBytes = InputManifestService.Serialize(draft);
        var draftPath = Path.Combine(root, "input.draft.json");
        File.WriteAllBytes(draftPath, draftBytes);
        var confirmed = InputManifestService.Confirm(draft, root);
        var confirmedBytes = InputManifestService.Serialize(confirmed);
        var confirmedPath = Path.Combine(root, "input.confirmed.json");
        File.WriteAllBytes(confirmedPath, confirmedBytes);
        return new Fixture(
            root,
            nupkg,
            candidatesPath,
            draftPath,
            confirmedPath,
            draft,
            confirmed,
            confirmedBytes);
    }

    private static void TestRubricAndInputContracts(Fixture fixture, string pluginRoot)
    {
        var rubric = RubricLoader.Load();
        AssertEqual(110, rubric.CoreRequirements.Count, "rubric core count");
        AssertEqual(46, RubricLoader.Select(rubric, "package", []).Count, "package row count");
        AssertEqual(64, RubricLoader.Select(rubric, "component", []).Count, "component row count");
        AssertEqual(116, RubricLoader.Select(rubric, "unified", ["scaffolder"]).Count, "overlay row count");
        AssertEqual(
            "023a6204a20be9a6558cdba8b284a1729ffe0439781c1c73b94d577fe66279d5",
            rubric.ScopeMapDigest.Value,
            "scope digest");
        var validatorSource = Directory.GetFiles(
                Path.Combine(pluginRoot, "skills", "blazor-component-readiness", "scripts", "validator"),
                "*.cs",
                SearchOption.AllDirectories)
            .Select(File.ReadAllText);
        Assert(
            !validatorSource.Any(source => source.Contains("\"LP-01\"", StringComparison.Ordinal)),
            "production validator does not compile the 110-row table");

        AssertEqual("draft", fixture.Draft.State, "draft state");
        AssertEqual("confirmed", fixture.Confirmed.State, "confirmed state");
        AssertEqual("sample.widgets", fixture.Confirmed.Package.PackageId, "canonical package ID");
        AssertEqual("1.2.0", fixture.Confirmed.Package.Version, "canonical package version");
        AssertEqual("fancy-tree", fixture.Confirmed.Components.Single().Id, "canonical component ID");
        AssertSequence(
            ["interactive-server", "interactive-webassembly", "static-ssr"],
            fixture.Confirmed.Components.Single().RenderModes,
            "canonical render modes");
        AssertEqual(
            "https://github.example.com/Vendor/Widgets",
            fixture.Confirmed.Source.RepositoryUri,
            "host-neutral repository URI");
        AssertEqual(
            "https://docs.example.com/Widgets",
            fixture.Confirmed.Documentation.Single().Url,
            "official documentation URI");
        InputManifestService.Validate(fixture.Confirmed, fixture.Root, requireConfirmed: true);
        ExpectValidation(
            () => AssessmentService.Initialize(
                "unified",
                fixture.Root,
                fixture.Draft,
                InputManifestService.Serialize(fixture.Draft),
                "fancy-tree",
                []),
            "draft cannot initialize assessment");

        File.AppendAllText(Path.Combine(fixture.Root, "owner-audit.txt"), "mutation");
        ExpectValidation(
            () => InputManifestService.Validate(fixture.Confirmed, fixture.Root, requireConfirmed: true),
            "stale owner digest");
        File.WriteAllText(
            Path.Combine(fixture.Root, "owner-audit.txt"),
            "Retained owner audit evidence.",
            new UTF8Encoding(false));

        var unsafeCandidates = File.ReadAllText(fixture.CandidatesPath)
            .Replace("\"owner-audit.txt\"", "\"../owner-audit.txt\"", StringComparison.Ordinal);
        ExpectValidation(
            () => InputManifestService.Discover(
                fixture.Root,
                fixture.NupkgPath,
                Encoding.UTF8.GetBytes(unsafeCandidates)),
            "owner path escape");
        var closedCandidates = File.ReadAllText(fixture.CandidatesPath)
            .Replace(
                """
                "availability": "source-available",
                    "repository_uri": "HTTPS://GitHub.Example.COM/Vendor/Widgets/",
                    "commit": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "mapping": "Package metadata and source tag map to this commit.",
                    "confidence": "HIGH"
                """,
                """
                "availability": "closed-source",
                    "repository_uri": null,
                    "commit": null,
                    "mapping": null,
                    "confidence": null
                """,
                StringComparison.Ordinal);
        AssertEqual(
            "closed-source",
            InputManifestService.Discover(
                fixture.Root,
                fixture.NupkgPath,
                Encoding.UTF8.GetBytes(closedCandidates)).Source.Availability,
            "closed-source state");
        var unresolvedCandidates = closedCandidates.Replace(
            "\"availability\": \"closed-source\"",
            "\"availability\": \"unresolved\"",
            StringComparison.Ordinal);
        AssertEqual(
            "unresolved",
            InputManifestService.Discover(
                fixture.Root,
                fixture.NupkgPath,
                Encoding.UTF8.GetBytes(unresolvedCandidates)).Source.Availability,
            "unresolved state");
        var publishedCandidates = File.ReadAllText(fixture.CandidatesPath).Replace(
            "\"acquisition\": \"release-candidate\"",
            "\"acquisition\": \"published\"",
            StringComparison.Ordinal);
        AssertEqual(
            "published",
            InputManifestService.Discover(
                fixture.Root,
                fixture.NupkgPath,
                Encoding.UTF8.GetBytes(publishedCandidates)).Acquisition,
            "published acquisition");

        File.AppendAllText(fixture.NupkgPath, "mutation", new UTF8Encoding(false));
        ExpectValidation(
            () => InputManifestService.Validate(fixture.Confirmed, fixture.Root, requireConfirmed: true),
            "package digest mismatch");
        File.Delete(fixture.NupkgPath);
        CreatePackage(fixture.NupkgPath, "Sample.Widgets", "01.002.000");

        var ownerInputs = new List<OwnerInput>();
        for (var index = 0; index < ResourceLimits.SupplementalInputCount + 1; index++)
        {
            var basename = $"owner-{index:00}.txt";
            var bytes = Encoding.UTF8.GetBytes($"owner input {index}");
            File.WriteAllBytes(Path.Combine(fixture.Root, basename), bytes);
            ownerInputs.Add(new OwnerInput(
                basename,
                "owner-supplied-internal-evidence",
                ContractJson.RawDigest(bytes),
                bytes.Length));
        }

        InputManifestService.Validate(
            fixture.Confirmed with
            {
                OwnerInputs = ownerInputs.Take(ResourceLimits.SupplementalInputCount).ToArray()
            },
            fixture.Root,
            requireConfirmed: true);
        ExpectValidation(
            () => InputManifestService.Validate(
                fixture.Confirmed with { OwnerInputs = ownerInputs },
                fixture.Root,
                requireConfirmed: true),
            "owner input count ceiling");

        var symlink = Path.Combine(fixture.Root, "owner-link.txt");
        try
        {
            File.CreateSymbolicLink(symlink, Path.Combine(fixture.Root, "owner-audit.txt"));
            var symlinkCandidates = File.ReadAllText(fixture.CandidatesPath)
                .Replace("\"owner-audit.txt\"", "\"owner-link.txt\"", StringComparison.Ordinal);
            ExpectValidation(
                () => InputManifestService.Discover(
                    fixture.Root,
                    fixture.NupkgPath,
                    Encoding.UTF8.GetBytes(symlinkCandidates)),
                "owner symlink escape");
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
        }
    }

    private static void TestAssessmentKinds(Fixture fixture)
    {
        var unified = AssessmentService.Initialize(
            "unified", fixture.Root, fixture.Confirmed, fixture.ConfirmedBytes, "Fancy Tree", []);
        var package = AssessmentService.Initialize(
            "package", fixture.Root, fixture.Confirmed, fixture.ConfirmedBytes, null, []);
        var component = AssessmentService.Initialize(
            "component", fixture.Root, fixture.Confirmed, fixture.ConfirmedBytes, "fancy-tree", []);
        AssertEqual(110, unified.Rows.Count, "unified exact rows");
        AssertEqual(46, package.Rows.Count, "package exact rows");
        AssertEqual(64, component.Rows.Count, "component exact rows");
        Assert(unified.Rows.All(row => row.Status is null), "init placeholders are null, not legacy tokens");
        Assert(package.Rows.All(row => row.Scope == "repository-wide"), "package ownership");
        Assert(component.Rows.All(row => row.Scope == "component-specific"), "component ownership");
        Assert(component.PackageReference is not null, "component exact package reference");
        AssertEqual(
            ContractJson.RawDigest(fixture.ConfirmedBytes),
            unified.Identity.InputManifestDigest,
            "evidence identity uses exact confirmed input-manifest bytes");
        var unifiedEvidence = BuildEvidence(unified.Identity);
        var packageEvidence = BuildEvidence(package.Identity);
        var componentEvidence = BuildEvidence(component.Identity);
        Validate(fixture, Complete(unified, unifiedEvidence, "gap"), unifiedEvidence);
        Validate(fixture, Complete(package, packageEvidence, "gap"), packageEvidence);
        var completedComponent = Complete(component, componentEvidence, "gap");
        Validate(fixture, completedComponent, componentEvidence);
        var componentBytes = AssessmentService.Serialize(completedComponent);
        var componentEvidenceBytes = CanonicalEvidenceJson.SerializeBundle(componentEvidence);
        var componentReport = ReportService.RenderMarkdown(
            completedComponent,
            fixture.Confirmed,
            componentEvidence);
        Assert(
            ReportService.CreateManifest(
                completedComponent,
                componentBytes,
                fixture.Confirmed,
                fixture.ConfirmedBytes,
                componentEvidence,
                componentEvidenceBytes,
                componentReport).PackageReference is not null,
            "component validation manifest carries optional exact package reference");

        var overlay = AssessmentService.Initialize(
            "unified",
            fixture.Root,
            fixture.Confirmed,
            fixture.ConfirmedBytes,
            "fancy-tree",
            ["ai-skill"]);
        AssertEqual(116, overlay.Rows.Count, "selected overlay rows");
        Assert(
            overlay.Rows.Take(110).All(row => !row.Id.StartsWith("AI-", StringComparison.Ordinal)) &&
            overlay.Rows.Skip(110).All(row => row.Id.StartsWith("AI-", StringComparison.Ordinal)),
            "overlay has no unselected placeholders");

        var reordered = Complete(unified, BuildEvidence(unified.Identity), "gap") with
        {
            Rows = Complete(unified, BuildEvidence(unified.Identity), "gap").Rows.Reverse().ToArray()
        };
        ExpectValidation(
            () => Validate(fixture, reordered, BuildEvidence(unified.Identity)),
            "reordered rows");
        var unknownRows = unified.Rows.ToArray();
        unknownRows[0] = unknownRows[0] with { Id = "OLD-01" };
        ExpectValidation(
            () => Validate(
                fixture,
                unified with { Rows = unknownRows },
                BuildEvidence(unified.Identity)),
            "unknown row");
        var duplicateRows = unified.Rows.ToArray();
        duplicateRows[1] = duplicateRows[0];
        ExpectValidation(
            () => Validate(
                fixture,
                unified with { Rows = duplicateRows },
                BuildEvidence(unified.Identity)),
            "duplicate row");
    }

    private static void TestStatusAndEvidenceBoundaries(Fixture fixture)
    {
        var initialized = AssessmentService.Initialize(
            "unified", fixture.Root, fixture.Confirmed, fixture.ConfirmedBytes, "fancy-tree", []);
        foreach (var status in new[]
                 {
                     "verified",
                     "gap",
                     "owner evidence required",
                     "not tested",
                     "not applicable"
                 })
        {
            var evidence = BuildEvidence(initialized.Identity);
            Validate(fixture, Complete(initialized, evidence, status), evidence);
        }

        var baseEvidence = BuildEvidence(initialized.Identity);
        var valid = Complete(initialized, baseEvidence, "owner evidence required");
        var oldStatus = Complete(initialized, baseEvidence, "gap");
        ExpectValidation(
            () => Validate(
                fixture,
                oldStatus with
                {
                    Rows =
                    [
                        oldStatus.Rows[0] with { Status = "defect" },
                        .. oldStatus.Rows.Skip(1)
                    ]
                },
                baseEvidence),
            "legacy status token");
        ExpectValidation(
            () => Validate(
                fixture,
                valid with
                {
                    Rows =
                    [
                        valid.Rows[0] with { OwnerAction = "TBD" },
                        .. valid.Rows.Skip(1)
                    ]
                },
                baseEvidence),
            "TBD owner action");
        var tbdGap = Complete(initialized, baseEvidence, "gap");
        ExpectValidation(
            () => Validate(
                fixture,
                tbdGap with
                {
                    Rows =
                    [
                        tbdGap.Rows[0] with { Observation = "TBD" },
                        .. tbdGap.Rows.Skip(1)
                    ]
                },
                baseEvidence),
            "TBD factual observation");
        ExpectValidation(
            () => Validate(
                fixture,
                Complete(initialized, baseEvidence, "not tested") with
                {
                    Rows =
                    [
                        Complete(initialized, baseEvidence, "not tested").Rows[0] with
                        {
                            AssessmentFollowUp = null
                        },
                        .. Complete(initialized, baseEvidence, "not tested").Rows.Skip(1)
                    ]
                },
                baseEvidence),
            "not tested follow-up");
        ExpectValidation(
            () => Validate(
                fixture,
                Complete(initialized, baseEvidence, "gap") with
                {
                    Rows =
                    [
                        Complete(initialized, baseEvidence, "gap").Rows[0] with { Observation = null },
                        .. Complete(initialized, baseEvidence, "gap").Rows.Skip(1)
                    ]
                },
                baseEvidence),
            "gap observation");
        var unused = Complete(initialized, baseEvidence, "not applicable");
        unused = unused with
        {
            Rows =
            [
                unused.Rows[0] with { EvidenceIds = [] },
                .. unused.Rows.Skip(1)
            ]
        };
        ExpectValidation(() => Validate(fixture, unused, baseEvidence), "unused selected evidence");
        ExpectValidation(
            () => Validate(
                fixture,
                valid with { CompletionState = "complete", Rows = initialized.Rows },
                baseEvidence),
            "incomplete represented complete");
        var targeted = initialized with
        {
            Rows =
            [
                Complete(initialized, baseEvidence, "gap").Rows[0],
                .. initialized.Rows.Skip(1)
            ],
            CompletionState = "targeted"
        };
        Validate(fixture, targeted, baseEvidence);
        ExpectValidation(
            () => Validate(
                fixture,
                targeted with { CompletionState = "complete" },
                baseEvidence),
            "targeted rows cannot be complete");
    }

    private static void TestCliAndRendering(Fixture fixture)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(["inputs", "--help"], output, error),
            "inputs help");
        output.GetStringBuilder().Clear();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(["assessment", "--help"], output, error),
            "assessment help");
        output.GetStringBuilder().Clear();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(["report", "--help"], output, error),
            "report help");
        foreach (var command in new[] { "discover", "confirm", "validate" })
        {
            output.GetStringBuilder().Clear();
            AssertEqual(
                ExitCodes.Success,
                CliApplication.Run(["inputs", command, "--help"], output, error),
                $"inputs {command} help");
        }

        var cliDraft = Path.Combine(fixture.Root, "cli-input.draft.json");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "inputs", "discover",
                    "--root", fixture.Root,
                    "--nupkg", fixture.NupkgPath,
                    "--candidates", fixture.CandidatesPath,
                    "--output", cliDraft
                ],
                output,
                error),
            "inputs discover CLI");
        var cliConfirmed = Path.Combine(fixture.Root, "cli-input.confirmed.json");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "inputs", "confirm",
                    "--root", fixture.Root,
                    "--draft", cliDraft,
                    "--output", cliConfirmed
                ],
                output,
                error),
            "inputs confirm CLI");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                ["inputs", "validate", "--root", fixture.Root, "--manifest", cliConfirmed],
                output,
                error),
            "inputs validate CLI");
        var cliAssessment = Path.Combine(fixture.Root, "cli-unified.assessment.json");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "assessment", "init",
                    "--kind", "unified",
                    "--root", fixture.Root,
                    "--input", cliConfirmed,
                    "--output", cliAssessment,
                    "--component", "Fancy Tree",
                    "--overlays", "scaffolder"
                ],
                output,
                error),
            "assessment init CLI");
        AssertEqual(
            116,
            AssessmentService.Parse(File.ReadAllBytes(cliAssessment)).Rows.Count,
            "assessment init CLI exact selected rows");

        var initialized = AssessmentService.Initialize(
            "unified", fixture.Root, fixture.Confirmed, fixture.ConfirmedBytes, "fancy-tree", []);
        var evidence = BuildEvidence(initialized.Identity);
        var assessment = Complete(initialized, evidence, "gap");
        var assessmentBytes = AssessmentService.Serialize(assessment);
        var evidenceBytes = CanonicalEvidenceJson.SerializeBundle(evidence);
        var assessmentPath = Path.Combine(fixture.Root, "unified.assessment.json");
        var evidencePath = Path.Combine(fixture.Root, "unified.evidence.json");
        File.WriteAllBytes(assessmentPath, assessmentBytes);
        File.WriteAllBytes(evidencePath, evidenceBytes);
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "assessment", "validate",
                    "--root", fixture.Root,
                    "--input", fixture.ConfirmedPath,
                    "--assessment", assessmentPath,
                    "--evidence", evidencePath
                ],
                output,
                error),
            "structural success with gap exits zero");

        var actualMarkdown = ReportService.RenderMarkdown(assessment, fixture.Confirmed, evidence);
        var goldenInput = fixture.Confirmed with
        {
            Package = fixture.Confirmed.Package with
            {
                NupkgDigest = new Sha256Digest("sha256", new string('a', 64))
            }
        };
        var fixedEvidenceId = "EV1-" + new string('c', 64);
        var goldenAssessment = assessment with
        {
            Rows =
            [
                assessment.Rows[0] with { EvidenceIds = [fixedEvidenceId] },
                .. assessment.Rows.Skip(1)
            ]
        };
        var embedded = evidence.SourceLedgers.Single();
        var goldenEvidence = evidence with
        {
            SourceLedgers =
            [
                embedded with
                {
                    Ledger = embedded.Ledger with
                    {
                        Records =
                        [
                            embedded.Ledger.Records.Single() with { StableId = fixedEvidenceId }
                        ]
                    }
                }
            ],
            Selection =
            [
                evidence.Selection.Single() with { EvidenceId = fixedEvidenceId }
            ]
        };
        var firstMarkdown = ReportService.RenderMarkdown(goldenAssessment, goldenInput, goldenEvidence);
        var secondMarkdown = ReportService.RenderMarkdown(goldenAssessment, goldenInput, goldenEvidence);
        AssertEqual(
            "55f915b0e0aededab7e2f71f3b6e8e2f4b394e7652f6bc12f817d147f9751534",
            ContractJson.RawDigest(firstMarkdown).Value,
            "deterministic report golden digest");
        AssertBytes(firstMarkdown, secondMarkdown, "same inputs byte-identical Markdown");
        var markdown = Encoding.UTF8.GetString(firstMarkdown);
        Assert(markdown.Contains("## Assessment inputs", StringComparison.Ordinal), "readable inputs section");
        Assert(markdown.Contains("`gap`: 1", StringComparison.Ordinal), "factual unranked status counts");
        Assert(markdown.Contains("[vendor-public-documentation]", StringComparison.Ordinal), "provenance labels");
        Assert(!markdown.Contains("verdict", StringComparison.OrdinalIgnoreCase), "no default verdict");
        Assert(!markdown.Contains("priority", StringComparison.OrdinalIgnoreCase), "no ranked remediation");
        AssertEqual(110, markdown.Split('\n').Count(line => line.StartsWith("| `", StringComparison.Ordinal)), "all rows rendered");

        var revisions = Path.Combine(fixture.Root, "revisions");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "report", "render",
                    "--root", fixture.Root,
                    "--input", fixture.ConfirmedPath,
                    "--assessment", assessmentPath,
                    "--evidence", evidencePath,
                    "--output", revisions
                ],
                output,
                error),
            "report render CLI");
        var revision = Path.Combine(revisions, "0001");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                ["report", "verify", "--root", fixture.Root, "--revision", revision],
                output,
                error),
            "report verify CLI");
        Assert(File.Exists(Path.Combine(revision, "input-manifest.json")), "input snapshot");
        Assert(File.Exists(Path.Combine(revision, "unified.validation.json")), "validation manifest");
        var renderedManifest = ReportService.ParseManifest(
            File.ReadAllBytes(Path.Combine(revision, "unified.validation.json")));
        AssertEqual(
            ContractJson.RawDigest(fixture.ConfirmedBytes),
            renderedManifest.InputManifestDigest,
            "manifest input binding");
        AssertEqual(
            ContractJson.RawDigest(actualMarkdown),
            renderedManifest.ReportDigest,
            "manifest report binding");
        AssertSequence(
            evidence.Selection.Select(item => item.EvidenceId),
            renderedManifest.SelectedEvidenceIds,
            "manifest selected evidence binding");
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                [
                    "report", "render",
                    "--root", fixture.Root,
                    "--input", fixture.ConfirmedPath,
                    "--assessment", assessmentPath,
                    "--evidence", evidencePath,
                    "--output", revisions
                ],
                output,
                error),
            "existing revision refusal");
        var predecessorOutput = Path.Combine(fixture.Root, "predecessor-revisions");
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                [
                    "report", "render",
                    "--root", fixture.Root,
                    "--input", fixture.ConfirmedPath,
                    "--assessment", assessmentPath,
                    "--evidence", evidencePath,
                    "--output", predecessorOutput,
                    "--predecessor", new string('a', 64)
                ],
                output,
                error),
            "0001 predecessor refusal");
        Assert(!Directory.Exists(Path.Combine(predecessorOutput, "0001")), "no output on predecessor validation failure");

        var reportPath = Path.Combine(revision, "unified.report.md");
        File.AppendAllText(reportPath, "x", new UTF8Encoding(false));
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                ["report", "verify", "--root", fixture.Root, "--revision", revision],
                output,
                error),
            "one-byte report mutation");
        File.WriteAllBytes(reportPath, actualMarkdown);
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                ["report", "verify", "--root", fixture.Root, "--revision", revision],
                output,
                error),
            "report restored");

        var manifestPath = Path.Combine(revision, "unified.validation.json");
        var manifestBytes = File.ReadAllBytes(manifestPath);
        manifestBytes[^1] = (byte)'\n';
        File.WriteAllBytes(manifestPath, manifestBytes);
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                ["report", "verify", "--root", fixture.Root, "--revision", revision],
                output,
                error),
            "manifest one-byte binding mutation");

        var invalidOutput = Path.Combine(fixture.Root, "invalid-revisions");
        var invalidAssessment = assessment with { Rows = assessment.Rows.Skip(1).ToArray() };
        var invalidPath = Path.Combine(fixture.Root, "invalid.assessment.json");
        File.WriteAllBytes(invalidPath, AssessmentService.Serialize(invalidAssessment));
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                [
                    "report", "render",
                    "--root", fixture.Root,
                    "--input", fixture.ConfirmedPath,
                    "--assessment", invalidPath,
                    "--evidence", evidencePath,
                    "--output", invalidOutput
                ],
                output,
                error),
            "invalid render exit");
        Assert(!Directory.Exists(Path.Combine(invalidOutput, "0001")), "no report output on validation failure");
    }

    private static void TestSnapshotMutation(string root)
    {
        var path = Path.Combine(root, "snapshot.txt");
        File.WriteAllText(path, "before", new UTF8Encoding(false));
        var snapshot = ImmutableInputSnapshot.Capture(path, "snapshot");
        File.WriteAllText(path, "after", new UTF8Encoding(false));
        ExpectValidation(snapshot.EnsureUnchanged, "input mutation race");
    }

    private static void TestCliSubprocess(Fixture fixture, string pluginRoot)
    {
        var validator = Path.Combine(
            pluginRoot,
            "skills",
            "blazor-component-readiness",
            "scripts",
            "validator");
        var info = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "pwsh" : "bash",
            WorkingDirectory = fixture.Root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        if (OperatingSystem.IsWindows())
        {
            info.ArgumentList.Add("-NoLogo");
            info.ArgumentList.Add("-NoProfile");
            info.ArgumentList.Add("-File");
            info.ArgumentList.Add(Path.Combine(validator, "run-validator.ps1"));
        }
        else
        {
            info.ArgumentList.Add(Path.Combine(validator, "run-validator.sh"));
        }

        foreach (var argument in new[]
                 {
                     "inputs", "validate",
                     "--root", fixture.Root,
                     "--manifest", fixture.ConfirmedPath
                 })
        {
            info.ArgumentList.Add(argument);
        }

        var external = Path.Combine(fixture.Root, "cli-subprocess-artifacts");
        info.Environment["READINESS_TEMP"] = external;
        using var process = Process.Start(info)
            ?? throw new InvalidOperationException("Could not start validator CLI subprocess.");
        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert(
            process.ExitCode == ExitCodes.Success,
            $"CLI subprocess failed.\nstdout:\n{standardOutput}\nstderr:\n{standardError}");
        Assert(
            File.Exists(Path.Combine(
                external,
                "bin",
                "Release",
                "net11.0",
                "BlazorComponentReadiness.Validator.dll")),
            "CLI subprocess uses external launcher output");
    }

    private static ReadinessAssessment Complete(
        ReadinessAssessment initialized,
        EvidenceBundle evidence,
        string firstStatus)
    {
        var evidenceId = evidence.Selection.Single().EvidenceId;
        var rows = initialized.Rows.Select((row, index) =>
        {
            if (index != 0)
            {
                return row with
                {
                    Status = "not applicable",
                    NotApplicableRationale = "This synthetic fixture records a bounded non-applicability rationale."
                };
            }

            return firstStatus switch
            {
                "verified" => row with
                {
                    Status = firstStatus,
                    Observation = "The retained evidence directly establishes this synthetic observation.",
                    EvidenceIds = [evidenceId]
                },
                "gap" => row with
                {
                    Status = firstStatus,
                    Observation = "The retained evidence directly demonstrates this bounded product gap.",
                    EvidenceIds = [evidenceId]
                },
                "owner evidence required" => row with
                {
                    Status = firstStatus,
                    Observation = "Provide the retained release record that establishes this requirement.",
                    EvidenceIds = [evidenceId],
                    OwnerAction = "Supply the exact retained owner-controlled release evidence."
                },
                "not tested" => row with
                {
                    Status = firstStatus,
                    EvidenceIds = [evidenceId],
                    AssessmentFollowUp = "Run the bounded synthetic probe and record its exact result."
                },
                "not applicable" => row with
                {
                    Status = firstStatus,
                    EvidenceIds = [evidenceId],
                    NotApplicableRationale = "The bounded synthetic package does not expose this capability."
                },
                _ => throw new InvalidOperationException()
            };
        }).ToArray();
        return initialized with { Rows = rows, CompletionState = "complete" };
    }

    private static EvidenceBundle BuildEvidence(ExactAssessmentIdentity identity)
    {
        var record = new EvidenceRecordDraft(
            "Official vendor documentation records this synthetic requirement.",
            identity.AssessmentKind == "component"
                ? new EvidenceApplicability("component-specific", identity.ComponentId)
                : new EvidenceApplicability("repository-wide", null),
            new EvidenceProvenance(
                EvidenceIdentity.VendorPublicDocumentation,
                "https://docs.example.com/Widgets",
                "Captured official documentation content.",
                "2026-09-02T20:00:00Z",
                new Sha256Digest("sha256", new string('b', 64)),
                "commitment-only"),
            []);
        EvidenceSourceLedger ledger;
        if (identity.AssessmentKind == "component")
        {
            ledger = EvidenceLedgerBuilder.BuildComponentLedger(identity, [record]);
        }
        else
        {
            ledger = EvidenceLedgerBuilder.BuildRepositoryLedger(
                new RepositoryLedgerSubject(
                    identity.AssessmentKind,
                    identity.Package,
                    identity.InputManifestDigest,
                    identity.ComponentId),
                [record]);
        }

        return EvidenceLedgerBuilder.BuildBundle(
            identity,
            [ledger],
            [ledger.Records.Single().StableId]);
    }

    private static void Validate(
        Fixture fixture,
        ReadinessAssessment assessment,
        EvidenceBundle evidence)
    {
        var assessmentBytes = AssessmentService.Serialize(assessment);
        AssessmentService.Validate(
            assessment,
            assessmentBytes,
            fixture.Confirmed,
            fixture.ConfirmedBytes,
            evidence);
    }

    private static void CreatePackage(string path, string id, string version)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        var entry = archive.CreateEntry($"{id}.nuspec", CompressionLevel.NoCompression);
        entry.LastWriteTime = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: false);
        writer.Write($"<package><metadata><id>{id}</id><version>{version}</version></metadata></package>");
    }

    private static void ExpectValidation(Action action, string name)
    {
        try
        {
            action();
            throw new InvalidOperationException($"{name}: expected deterministic validation failure.");
        }
        catch (DeterministicValidationException)
        {
        }
    }

    private static void AssertSequence<T>(IEnumerable<T> expected, IEnumerable<T> actual, string name)
    {
        var expectedArray = expected.ToArray();
        var actualArray = actual.ToArray();
        Assert(
            expectedArray.SequenceEqual(actualArray),
            $"{name}: expected [{string.Join(", ", expectedArray)}], actual [{string.Join(", ", actualArray)}].");
    }

    private static void AssertBytes(byte[] expected, byte[] actual, string name) =>
        Assert(expected.AsSpan().SequenceEqual(actual), $"{name}: byte mismatch.");

    private static void AssertEqual<T>(T expected, T actual, string name) =>
        Assert(EqualityComparer<T>.Default.Equals(expected, actual), $"{name}: expected '{expected}', actual '{actual}'.");

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed record Fixture(
        string Root,
        string NupkgPath,
        string CandidatesPath,
        string DraftPath,
        string ConfirmedPath,
        InputManifest Draft,
        InputManifest Confirmed,
        byte[] ConfirmedBytes);
}
