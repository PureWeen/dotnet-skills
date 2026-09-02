using System.IO.Compression;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
            TestReportInputMutationRaces(fixture);
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
              "package_origin": {
                "locator": "Sample.Widgets.01.002.000.nupkg",
                "retrieval_method": "local-file"
              },
              "source": {
                "availability": "source-available",
                "repository_uri": "HTTPS://GitHub.Example.COM/Vendor/Widgets/",
                "commit": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "mapping": "Package metadata and source tag map to this commit.",
                "confidence": "HIGH"
              },
              "retrieval_attempts": [
                {
                  "subject": "source",
                  "locator": "https://source.example.test/widgets",
                  "retrieval_method": "repository-fetch",
                  "result": "succeeded",
                  "detail": "The exact source commit was acquired."
                },
                {
                  "subject": "documentation",
                  "locator": "https://docs.example.test/widgets",
                  "retrieval_method": "direct-download",
                  "result": "network-failure",
                  "detail": "The first bounded request failed."
                },
                {
                  "subject": "package",
                  "locator": "Sample.Widgets.01.002.000.nupkg",
                  "retrieval_method": "local-file",
                  "result": "succeeded",
                  "detail": null
                }
              ],
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
        AssertEqual(
            "Sample.Widgets.01.002.000.nupkg",
            fixture.Confirmed.Package.OriginLocator,
            "package origin locator");
        AssertEqual("local-file", fixture.Confirmed.Package.RetrievalMethod, "package retrieval method");
        AssertEqual(3, fixture.Confirmed.RetrievalAttempts.Count, "bounded retrieval attempt records");
        Assert(
            fixture.Confirmed.RetrievalAttempts.Any(attempt => attempt.Result == "network-failure"),
            "acquisition failure remains an explicit input result");
        var boundedAttempts = Enumerable.Range(0, ResourceLimits.RetrievalAttemptCount - 1)
            .Select(index => new InputRetrievalAttempt(
                "documentation",
                $"https://docs-{index:00}.example.test/widgets",
                "direct-download",
                "not-found",
                "The bounded retrieval attempt did not locate the document."))
            .Append(new InputRetrievalAttempt(
                "package",
                fixture.Confirmed.Package.OriginLocator,
                fixture.Confirmed.Package.RetrievalMethod,
                "succeeded",
                null))
            .OrderBy(
                attempt =>
                    $"{attempt.Subject}\0{attempt.Locator}\0{attempt.RetrievalMethod}\0{attempt.Result}\0{attempt.Detail}",
                StringComparer.Ordinal)
            .ToArray();
        InputManifestService.Validate(
            fixture.Confirmed with { RetrievalAttempts = boundedAttempts },
            fixture.Root,
            requireConfirmed: true);
        ExpectValidation(
            () => InputManifestService.Validate(
                fixture.Confirmed with
                {
                    RetrievalAttempts =
                    [
                        .. boundedAttempts,
                        new InputRetrievalAttempt(
                            "source",
                            "https://source-over-limit.example.test/widgets",
                            "repository-fetch",
                            "not-found",
                            null)
                    ]
                },
                fixture.Root,
                requireConfirmed: true),
            "retrieval attempt count ceiling");
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
        TestVendorEditedDraft(fixture);
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
        ExpectValidation(
            () => Validate(
                fixture,
                completedComponent with
                {
                    PackageReference = completedComponent.PackageReference! with
                    {
                        AssessmentDigest = null
                    }
                },
                componentEvidence),
            "complete component package assessment digest");
        ExpectValidation(
            () => Validate(
                fixture,
                completedComponent with
                {
                    PackageReference = completedComponent.PackageReference! with
                    {
                        ReportDigest = null
                    }
                },
                componentEvidence),
            "complete component package report digest");
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
            "a5c891963f099ae3b4daa953ab6fffa3ad55b79bc1aa46e8d42ca119f185aecf",
            ContractJson.RawDigest(firstMarkdown).Value,
            "deterministic report golden digest");
        AssertBytes(firstMarkdown, secondMarkdown, "same inputs byte-identical Markdown");
        var markdown = Encoding.UTF8.GetString(firstMarkdown);
        Assert(markdown.Contains("## Assessment inputs", StringComparison.Ordinal), "readable inputs section");
        Assert(markdown.Contains("Package retrieval method", StringComparison.Ordinal), "package origin rendered");
        Assert(markdown.Contains("network-failure", StringComparison.Ordinal), "retrieval failure rendered");
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
        using (var pluginManifest = JsonDocument.Parse(File.ReadAllBytes(
                   Path.Combine(
                       Environment.GetEnvironmentVariable("READINESS_SKILL_ROOT")!,
                       "..",
                       "..",
                       "plugin.json"))))
        {
            AssertEqual(
                pluginManifest.RootElement.GetProperty("version").GetString(),
                renderedManifest.PluginVersion,
                "manifest plugin version comes from installed plugin.json");
        }
        AssertEqual(
            ContractVersions.ValidatorVersion,
            renderedManifest.ValidatorVersion,
            "manifest validator version comes from assembly");
        AssertEqual(
            RendererContract.Version,
            renderedManifest.RendererVersion,
            "manifest renderer version comes from renderer contract");
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
        Assert(renderedManifest.PredecessorManifestDigest is null, "0001 predecessor is null");
        Assert(renderedManifest.FeedbackDigest is null, "0001 feedback digest is null");
        AssertEqual(0, renderedManifest.DeclaredChangedIds.Count, "0001 changed IDs are empty");
        var forwardManifest = renderedManifest with
        {
            PredecessorManifestDigest = new Sha256Digest("sha256", new string('d', 64)),
            FeedbackDigest = new Sha256Digest("sha256", new string('e', 64)),
            DeclaredChangedIds = ["A11Y-01", "SEC-01"]
        };
        var forwardRoundTrip = ReportService.ParseManifest(ReportService.SerializeManifest(forwardManifest));
        AssertEqual(
            forwardManifest.PredecessorManifestDigest,
            forwardRoundTrip.PredecessorManifestDigest,
            "predecessor digest round-trips");
        AssertEqual(
            forwardManifest.FeedbackDigest,
            forwardRoundTrip.FeedbackDigest,
            "feedback digest round-trips");
        AssertSequence(
            forwardManifest.DeclaredChangedIds,
            forwardRoundTrip.DeclaredChangedIds,
            "declared changed IDs round-trip");
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

    private static void TestVendorEditedDraft(Fixture fixture)
    {
        var draft = JsonNode.Parse(File.ReadAllBytes(fixture.DraftPath))!.AsObject();
        var package = draft["package"]!.AsObject();
        package["package_id"] = "vendor-edited-value";
        package["version"] = "99.0.0";
        package["nupkg_path"] = $" {Path.GetFileName(fixture.NupkgPath)} ";
        package["origin_locator"] = $" {Path.GetFileName(fixture.NupkgPath)} ";
        package["retrieval_method"] = "LOCAL-FILE";
        package["nupkg_sha256"]!["value"] = new string('f', 64);
        var source = draft["source"]!.AsObject();
        source["repository_uri"] = " HTTPS://GitHub.Example.COM/Vendor/Widgets/ ";
        source["mapping"] = " Updated source mapping supplied by the vendor. ";
        source["confidence"] = "MEDIUM";
        var documentation = draft["documentation"]!.AsArray()[0]!.AsObject();
        documentation["url"] = " HTTPS://Docs.Example.COM/Widgets/ ";
        documentation["content_path"] = " docs.html ";
        documentation["content_sha256"]!["value"] = new string('f', 64);
        var packageSource = draft["package_sources"]!.AsArray()[0]!.AsObject();
        packageSource["content_path"] = " package-readme.md ";
        packageSource["content_sha256"]!["value"] = new string('f', 64);
        var owner = draft["owner_inputs"]!.AsArray()[0]!.AsObject();
        owner["basename"] = " owner-audit.txt ";
        owner["content_sha256"]!["value"] = new string('f', 64);
        owner["size"] = 1;
        var component = draft["components"]!.AsArray()[0]!.AsObject();
        component["id"] = " Fancy Tree ";
        component["render_modes"] = new JsonArray("WASM", "Server", "STATIC SSR", "WASM");
        draft["exclusions"] = new JsonArray(
            new JsonObject
            {
                ["subject"] = " Zeta exclusion ",
                ["rationale"] = " A bounded reason for the second exclusion. "
            },
            new JsonObject
            {
                ["subject"] = " Alpha exclusion ",
                ["rationale"] = " A bounded reason for the first exclusion. "
            });
        var attempts = draft["retrieval_attempts"]!.AsArray();
        draft["retrieval_attempts"] = new JsonArray(
            attempts.Reverse().Select(item => item!.DeepClone()).ToArray());
        var acquisition = draft["acquisition"]!.DeepClone();
        draft.Remove("acquisition");
        draft.Add("acquisition", acquisition);

        var ownerPath = Path.Combine(fixture.Root, "owner-audit.txt");
        var originalOwner = File.ReadAllBytes(ownerPath);
        File.AppendAllText(ownerPath, " Vendor update.", new UTF8Encoding(false));
        try
        {
            var editedBytes = Encoding.UTF8.GetBytes(
                draft.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            var canonicalDraft = InputManifestService.ParseDraft(editedBytes, fixture.Root);
            var confirmed = InputManifestService.Confirm(canonicalDraft, fixture.Root);
            AssertEqual("sample.widgets", confirmed.Package.PackageId, "confirm reinspects package ID");
            AssertEqual("1.2.0", confirmed.Package.Version, "confirm reinspects package version");
            AssertEqual(
                new Sha256Digest("sha256", NupkgInspector.Inspect(fixture.NupkgPath).NupkgSha256),
                confirmed.Package.NupkgDigest,
                "confirm reinspects package digest");
            AssertEqual("docs.html", confirmed.Documentation.Single().ContentPath, "confirm canonicalizes document path");
            AssertEqual(
                ContractJson.RawDigest(File.ReadAllBytes(Path.Combine(fixture.Root, "docs.html"))),
                confirmed.Documentation.Single().ContentDigest,
                "confirm recomputes documentation digest");
            AssertEqual(
                ContractJson.RawDigest(File.ReadAllBytes(Path.Combine(fixture.Root, "package-readme.md"))),
                confirmed.PackageSources.Single().ContentDigest,
                "confirm recomputes package source digest");
            AssertEqual(
                ContractJson.RawDigest(File.ReadAllBytes(ownerPath)),
                confirmed.OwnerInputs.Single().ContentDigest,
                "confirm recomputes owner digest");
            AssertEqual(
                new FileInfo(ownerPath).Length,
                confirmed.OwnerInputs.Single().Size,
                "confirm recomputes owner size");
            AssertEqual("medium", confirmed.Source.Confidence, "confirm canonicalizes confidence");
            AssertEqual(
                "Updated source mapping supplied by the vendor.",
                confirmed.Source.Mapping,
                "confirm canonicalizes mapping");
            AssertSequence(
                ["interactive-server", "interactive-webassembly", "static-ssr"],
                confirmed.Components.Single().RenderModes,
                "confirm canonicalizes render modes");
            AssertSequence(
                ["Alpha exclusion", "Zeta exclusion"],
                confirmed.Exclusions.Select(item => item.Subject),
                "confirm canonicalizes collection order");
        }
        finally
        {
            File.WriteAllBytes(ownerPath, originalOwner);
        }

        var output = new StringWriter();
        var error = new StringWriter();
        var draftText = File.ReadAllText(fixture.DraftPath);
        var unknownPath = Path.Combine(fixture.Root, "draft-unknown.json");
        File.WriteAllText(
            unknownPath,
            draftText.Replace("{\"schema_version\":1,", "{\"schema_version\":1,\"unknown\":true,", StringComparison.Ordinal),
            new UTF8Encoding(false));
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                [
                    "inputs", "confirm",
                    "--root", fixture.Root,
                    "--draft", unknownPath,
                    "--output", Path.Combine(fixture.Root, "unknown-confirmed.json")
                ],
                output,
                error),
            "draft parser rejects unknown properties");

        var duplicatePath = Path.Combine(fixture.Root, "draft-duplicate.json");
        File.WriteAllText(
            duplicatePath,
            draftText.Replace("{\"schema_version\":1,", "{\"schema_version\":1,\"schema_version\":1,", StringComparison.Ordinal),
            new UTF8Encoding(false));
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                [
                    "inputs", "confirm",
                    "--root", fixture.Root,
                    "--draft", duplicatePath,
                    "--output", Path.Combine(fixture.Root, "duplicate-confirmed.json")
                ],
                output,
                error),
            "draft parser rejects duplicate properties");

        var noncanonicalConfirmed = Path.Combine(fixture.Root, "noncanonical-confirmed.json");
        File.WriteAllText(
            noncanonicalConfirmed,
            JsonNode.Parse(fixture.ConfirmedBytes)!.ToJsonString(
                new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(false));
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                ["inputs", "validate", "--root", fixture.Root, "--manifest", noncanonicalConfirmed],
                output,
                error),
            "inputs validate requires exact canonical confirmed bytes");
    }

    private static void TestSnapshotMutation(string root)
    {
        var path = Path.Combine(root, "snapshot.txt");
        File.WriteAllText(path, "before", new UTF8Encoding(false));
        var snapshot = ImmutableInputSnapshot.Capture(path, "snapshot");
        File.WriteAllText(path, "after", new UTF8Encoding(false));
        ExpectValidation(snapshot.EnsureUnchanged, "input mutation race");
    }

    private static void TestReportInputMutationRaces(Fixture fixture)
    {
        var initialized = AssessmentService.Initialize(
            "unified",
            fixture.Root,
            fixture.Confirmed,
            fixture.ConfirmedBytes,
            "fancy-tree",
            []);
        var evidence = BuildEvidence(initialized.Identity);
        var assessment = Complete(initialized, evidence, "gap");
        var paths = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["input"] = fixture.ConfirmedPath,
            ["assessment"] = Path.Combine(fixture.Root, "race.assessment.json"),
            ["evidence"] = Path.Combine(fixture.Root, "race.evidence.json"),
            ["nupkg"] = fixture.NupkgPath,
            ["documentation"] = Path.Combine(fixture.Root, "docs.html"),
            ["package-source"] = Path.Combine(fixture.Root, "package-readme.md"),
            ["owner-input"] = Path.Combine(fixture.Root, "owner-audit.txt")
        };
        File.WriteAllBytes(paths["assessment"], AssessmentService.Serialize(assessment));
        File.WriteAllBytes(paths["evidence"], CanonicalEvidenceJson.SerializeBundle(evidence));
        var originals = paths.ToDictionary(
            pair => pair.Key,
            pair => File.ReadAllBytes(pair.Value),
            StringComparer.Ordinal);
        foreach (var pair in paths)
        {
            var outputRoot = Path.Combine(fixture.Root, $"race-{pair.Key}");
            var output = new StringWriter();
            var error = new StringWriter();
            ReportCommand.BeforePublishForTests = () =>
                File.AppendAllText(pair.Value, "mutation", new UTF8Encoding(false));
            try
            {
                AssertEqual(
                    ExitCodes.ValidationFailure,
                    CliApplication.Run(
                        [
                            "report", "render",
                            "--root", fixture.Root,
                            "--input", paths["input"],
                            "--assessment", paths["assessment"],
                            "--evidence", paths["evidence"],
                            "--output", outputRoot
                        ],
                        output,
                        error),
                    $"{pair.Key} report transaction mutation");
                Assert(
                    !Directory.Exists(Path.Combine(outputRoot, "0001")),
                    $"{pair.Key} mutation creates no 0001");
                Assert(
                    !Directory.Exists(outputRoot) ||
                    !Directory.EnumerateDirectories(outputRoot, "*.staging", SearchOption.TopDirectoryOnly).Any(),
                    $"{pair.Key} mutation cleans staging directory");
            }
            finally
            {
                ReportCommand.BeforePublishForTests = null;
                File.WriteAllBytes(pair.Value, originals[pair.Key]);
            }
        }
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
        var completed = initialized with { Rows = rows, CompletionState = "complete" };
        if (completed.AssessmentKind == "component")
        {
            completed = completed with
            {
                PackageReference = completed.PackageReference! with
                {
                    AssessmentDigest = new Sha256Digest("sha256", new string('d', 64)),
                    ReportDigest = new Sha256Digest("sha256", new string('e', 64))
                }
            };
        }

        return completed;
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
