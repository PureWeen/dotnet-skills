using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using BlazorComponentReadiness.Validator.Assessment;
using BlazorComponentReadiness.Validator.Cli;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.Inventory;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Library;
using BlazorComponentReadiness.Validator.Validation;

internal static class LibraryTests
{
    public static void Run(string repositoryRoot, string pluginRoot)
    {
        var root = Path.Combine(repositoryRoot, "artifacts", "readiness-commit6-tests");
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
            var fixture = CreateFixture(root);
            TestDiscoveryAndConfirmation(fixture);
            TestDraftCannotRun(fixture);
            TestInterruptedAndIncompleteState(fixture);
            var packageRevisions = CreatePackageRevisions(fixture);
            TestMissingOutputPreventsComplete(fixture, packageRevisions);
            CreateComponentRevisions(fixture, packageRevisions);
            TestCompleteReconcileAndIndex(fixture);
            TestCorruptManifestReconstruction(fixture);
            TestConflictsAndWrongPackage(fixture);
            TestCliSubprocess(fixture, pluginRoot);
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

    private static Fixture CreateFixture(string root)
    {
        var inputs = Path.Combine(root, "inputs");
        Directory.CreateDirectory(inputs);
        var packageA = CreatePackageSet(
            root,
            "Alpha.Controls",
            "01.000.000",
            "release-candidate",
            [
                ("Alpha Grid", new[] { "interactive-server", "static-ssr" }),
                ("Alpha Tree", new[] { "interactive-webassembly" })
            ]);
        var packageB = CreatePackageSet(
            root,
            "Beta.Controls",
            "2.5.0-rc.1",
            "published",
            [
                ("Beta Chart", new[] { "interactive-auto", "interactive-server" }),
                ("Beta Dialog", new[] { "standalone-webassembly", "static-ssr" })
            ]);

        var candidatesPath = Path.Combine(root, "inventory-candidates.json");
        File.WriteAllText(
            candidatesPath,
            JsonSerializer.Serialize(
                new
                {
                    schema_version = 1,
                    packages = new[]
                    {
                        Candidate(packageB),
                        Candidate(packageA)
                    }
                }),
            new UTF8Encoding(false));
        var draftPath = Path.Combine(root, "inventory.draft.json");
        var confirmedPath = Path.Combine(root, "inventory.confirmed.json");
        var runPath = Path.Combine(root, "run-manifest.json");
        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "inventory", "discover",
                    "--root", root,
                    "--candidates", candidatesPath,
                    "--output", draftPath
                ],
                output,
                error),
            $"inventory discover: {error}");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "inventory", "confirm",
                    "--root", root,
                    "--draft", draftPath,
                    "--output", confirmedPath
                ],
                output,
                error),
            $"inventory confirm: {error}");
        var inventoryBytes = File.ReadAllBytes(confirmedPath);
        var inventory = InventoryService.Parse(inventoryBytes);
        return new Fixture(
            root,
            candidatesPath,
            draftPath,
            confirmedPath,
            runPath,
            inventory,
            inventoryBytes,
            [packageA, packageB]);
    }

    private static PackageSet CreatePackageSet(
        string root,
        string id,
        string version,
        string acquisition,
        IReadOnlyList<(string DisplayName, string[] Modes)> components)
    {
        var canonicalId = Canonicalization.PackageId(id);
        var canonicalVersion = NuGetVersionNormalizer.Normalize(version);
        var nupkgRelative = $"inputs/{canonicalId}.{canonicalVersion}.nupkg";
        var nupkg = Path.Combine(root, nupkgRelative);
        CreatePackage(nupkg, id, version);
        var inspected = NupkgInspector.Inspect(nupkg);
        var package = new EvidencePackageIdentity(
            canonicalId,
            canonicalVersion,
            new Sha256Digest("sha256", inspected.NupkgSha256));
        var componentContracts = components
            .Select(item => new InputComponent(
                Canonicalization.ComponentId(item.DisplayName),
                item.DisplayName,
                item.Modes.Order(StringComparer.Ordinal).ToArray()))
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .ToArray();
        var packageInput = CreateInput(
            acquisition,
            package,
            nupkgRelative,
            componentContracts);
        var packageInputPath = $"inputs/{canonicalId}.package.input-manifest.json";
        File.WriteAllBytes(
            Path.Combine(root, packageInputPath),
            InputManifestService.Serialize(packageInput));
        InputManifestService.Validate(packageInput, root, requireConfirmed: true);

        var componentPaths = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var component in componentContracts)
        {
            var componentInput = CreateInput(
                acquisition,
                package,
                nupkgRelative,
                [component]);
            var path = $"inputs/{canonicalId}.{component.Id}.input-manifest.json";
            File.WriteAllBytes(Path.Combine(root, path), InputManifestService.Serialize(componentInput));
            InputManifestService.Validate(componentInput, root, requireConfirmed: true);
            componentPaths.Add(component.Id, path);
        }

        return new PackageSet(package, acquisition, packageInputPath, componentContracts, componentPaths);
    }

    private static InputManifest CreateInput(
        string acquisition,
        EvidencePackageIdentity package,
        string nupkgRelative,
        IReadOnlyList<InputComponent> components) =>
        new(
            InputManifestService.SchemaVersion,
            "confirmed",
            acquisition,
            new InputPackage(
                package.PackageId,
                package.Version,
                package.NupkgDigest,
                nupkgRelative,
                nupkgRelative,
                "local-file"),
            new InputSource("closed-source", null, null, null, null),
            [new InputRetrievalAttempt("package", nupkgRelative, "local-file", "succeeded", null)],
            [],
            [],
            [],
            components,
            [new InputExclusion("Synthetic external services", "Outside this deterministic library fixture.")]);

    private static object Candidate(PackageSet package) => new
    {
        input_manifest_path = package.PackageInputPath,
        revision_root = $"packages/{package.Package.PackageId}/{package.Package.Version}/revisions",
        components = package.Components
            .Reverse()
            .Select(component => new
            {
                component_id = $" {component.DisplayName} ",
                input_manifest_path = package.ComponentInputPaths[component.Id],
                revision_root =
                    $"packages/{package.Package.PackageId}/{package.Package.Version}/components/{component.Id}/revisions",
                render_modes = component.RenderModes
                    .Select(mode => mode switch
                    {
                        "interactive-server" => "Server",
                        "interactive-webassembly" => "WASM",
                        "static-ssr" => "STATIC SSR",
                        "interactive-auto" => "Auto",
                        "standalone-webassembly" => "standalone wasm",
                        _ => mode
                    })
                    .Reverse()
                    .ToArray(),
                exclusions = Array.Empty<object>()
            })
            .ToArray(),
        exclusions = new[]
        {
            new
            {
                subject = "Synthetic external services",
                rationale = "Outside this deterministic library fixture."
            }
        }
    };

    private static void TestDiscoveryAndConfirmation(Fixture fixture)
    {
        var draft = InventoryService.Parse(File.ReadAllBytes(fixture.DraftPath));
        AssertEqual("draft", draft.State, "inventory draft state");
        Assert(draft.InventoryId is null && draft.RunId is null, "draft has no run identity");
        AssertEqual("confirmed", fixture.Inventory.State, "inventory confirmed state");
        Assert(fixture.Inventory.InventoryId == fixture.Inventory.RunId, "inventory and run identity match");
        Assert(
            fixture.Inventory.InventoryId!.StartsWith("LIB1-", StringComparison.Ordinal),
            "deterministic inventory ID prefix");
        AssertEqual(2, fixture.Inventory.Packages.Count, "two exact package units");
        AssertEqual(4, fixture.Inventory.Packages.Sum(item => item.Components.Count), "four component units");
        AssertEqual(
            6,
            fixture.Inventory.Packages.Count + fixture.Inventory.Packages.Sum(item => item.Components.Count),
            "six total work units");
        Assert(
            fixture.Inventory.Packages.Select(item => item.Package.PackageId)
                .SequenceEqual(["alpha.controls", "beta.controls"], StringComparer.Ordinal),
            "packages canonical and separately sorted");
        Assert(
            fixture.Inventory.Packages.SelectMany(item => item.Components)
                .All(component => component.RenderModes.SequenceEqual(
                    component.RenderModes.Order(StringComparer.Ordinal),
                    StringComparer.Ordinal)),
            "render modes canonical and sorted");
        InventoryService.Validate(fixture.Inventory, fixture.Root, requireConfirmed: true);

        var repeated = InventoryService.Confirm(draft, fixture.Root);
        AssertBytes(
            fixture.InventoryBytes,
            InventoryService.Serialize(repeated),
            "confirmed inventory deterministic bytes and identity");
        var immutableBytes = File.ReadAllBytes(fixture.ConfirmedPath);
        AssertEqual(
            ExitCodes.EnvironmentFailure,
            CliApplication.Run(
                [
                    "inventory", "confirm",
                    "--root", fixture.Root,
                    "--draft", fixture.DraftPath,
                    "--output", fixture.ConfirmedPath
                ],
                new StringWriter(),
                new StringWriter()),
            "confirmed inventory immutable create-new");
        AssertBytes(
            immutableBytes,
            File.ReadAllBytes(fixture.ConfirmedPath),
            "confirmed inventory overwrite preserves bytes");

        var duplicateCandidates = File.ReadAllText(fixture.CandidatesPath);
        using var duplicateDocument = JsonDocument.Parse(duplicateCandidates);
        var firstPackage = duplicateDocument.RootElement.GetProperty("packages")[0];
        var packagePath = firstPackage.GetProperty("input_manifest_path").GetString()!;
        var package = fixture.Packages.Single(item => item.PackageInputPath == packagePath);
        var duplicatePath = Path.Combine(fixture.Root, "duplicate-candidates.json");
        File.WriteAllText(
            duplicatePath,
            JsonSerializer.Serialize(new
            {
                schema_version = 1,
                packages = new[] { Candidate(package), Candidate(package) }
            }),
            new UTF8Encoding(false));
        ExpectValidation(
            () => InventoryService.Discover(fixture.Root, File.ReadAllBytes(duplicatePath)),
            "duplicate package ownership");

        var siblingInput = CreateInput(
            package.Acquisition,
            package.Package,
            $"inputs/{package.Package.PackageId}.{package.Package.Version}.nupkg",
            package.Components);
        var siblingPath = $"inputs/{package.Package.PackageId}.sibling-component.input-manifest.json";
        File.WriteAllBytes(
            Path.Combine(fixture.Root, siblingPath),
            InputManifestService.Serialize(siblingInput));
        var badCandidate = JsonSerializer.Serialize(new
        {
            schema_version = 1,
            packages = new[]
            {
                new
                {
                    input_manifest_path = package.PackageInputPath,
                    revision_root =
                        $"packages/{package.Package.PackageId}/{package.Package.Version}/revisions",
                    components = new[]
                    {
                        new
                        {
                            component_id = package.Components[0].Id,
                            input_manifest_path = siblingPath,
                            revision_root =
                                $"packages/{package.Package.PackageId}/{package.Package.Version}/components/{package.Components[0].Id}/revisions",
                            render_modes = package.Components[0].RenderModes,
                            exclusions = Array.Empty<object>()
                        },
                        new
                        {
                            component_id = package.Components[1].Id,
                            input_manifest_path = package.ComponentInputPaths[package.Components[1].Id],
                            revision_root =
                                $"packages/{package.Package.PackageId}/{package.Package.Version}/components/{package.Components[1].Id}/revisions",
                            render_modes = package.Components[1].RenderModes,
                            exclusions = Array.Empty<object>()
                        }
                    },
                    exclusions = Array.Empty<object>()
                }
            }
        });
        ExpectValidation(
            () => InventoryService.Discover(fixture.Root, Encoding.UTF8.GetBytes(badCandidate)),
            "sibling component input leakage");
    }

    private static void TestDraftCannotRun(Fixture fixture)
    {
        var draftBytes = File.ReadAllBytes(fixture.DraftPath);
        var draft = InventoryService.Parse(draftBytes);
        ExpectValidation(
            () => LibraryService.Reconcile(fixture.Root, draft, draftBytes),
            "draft inventory cannot run");
    }

    private static void TestInterruptedAndIncompleteState(Fixture fixture)
    {
        RunCli(
            fixture,
            [
                "library", "reconcile",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath
            ]);
        var pendingBytes = File.ReadAllBytes(fixture.RunPath);
        var pending = LibraryService.Parse(pendingBytes);
        AssertEqual("incomplete", pending.State, "empty library incomplete");
        AssertEqual(6, pending.Units.Count(unit => unit.State == "pending"), "all initial units pending");

        var first = pending.Units[0] with { State = "active" };
        var active = pending with
        {
            Units = [first, .. pending.Units.Skip(1)]
        };
        File.WriteAllBytes(fixture.RunPath, LibraryService.Serialize(active));
        RunCli(
            fixture,
            [
                "library", "reconcile",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath
            ]);
        var interrupted = LibraryService.Parse(File.ReadAllBytes(fixture.RunPath));
        Assert(interrupted.Interrupted, "interrupted run state recorded");
        AssertEqual("incomplete", interrupted.Units[0].State, "interrupted active unit becomes incomplete");
        AssertEqual(5, interrupted.Units.Count(unit => unit.State == "pending"), "remaining units stay pending");

        RunCli(
            fixture,
            [
                "library", "index",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath,
                "--json", Path.Combine(fixture.Root, "library-index.json"),
                "--markdown", Path.Combine(fixture.Root, "library-index.md")
            ]);
        Assert(
            File.ReadAllText(Path.Combine(fixture.Root, "library-index.md"))
                .Contains("**Overall state:** `incomplete`", StringComparison.Ordinal),
            "incomplete factual index");
    }

    private static Dictionary<string, string> CreatePackageRevisions(Fixture fixture)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var package in fixture.Inventory.Packages)
        {
            var inputPath = Path.Combine(fixture.Root, package.InputManifestPath);
            var inputBytes = File.ReadAllBytes(inputPath);
            var input = InputManifestService.Parse(inputBytes);
            var initialized = AssessmentService.Initialize(
                "package",
                fixture.Root,
                input,
                inputBytes,
                null,
                []);
            var evidence = BuildEvidence(initialized.Identity, []);
            var assessment = Complete(initialized, evidence);
            var revision = Render(
                fixture.Root,
                inputPath,
                assessment,
                evidence,
                Path.Combine(fixture.Root, package.RevisionRoot),
                packageRevision: null);
            result.Add(package.UnitId, revision);
        }

        return result;
    }

    private static void TestMissingOutputPreventsComplete(
        Fixture fixture,
        IReadOnlyDictionary<string, string> packageRevisions)
    {
        var firstPackage = fixture.Inventory.Packages[0];
        var component = firstPackage.Components[0];
        CreateComponentRevision(fixture, component, packageRevisions[firstPackage.UnitId]);
        RunCli(
            fixture,
            [
                "library", "reconcile",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath
            ]);
        var manifest = LibraryService.Parse(File.ReadAllBytes(fixture.RunPath));
        AssertEqual("incomplete", manifest.State, "missing component output prevents complete");
        AssertEqual(3, manifest.Units.Count(unit => unit.State == "completed"), "two packages and one component completed");
        AssertEqual(3, manifest.Units.Count(unit => unit.State is "pending" or "incomplete"), "remaining component units incomplete");

        var falseComplete = manifest with { State = "complete" };
        ExpectValidation(
            () => LibraryService.Validate(
                fixture.Root,
                fixture.Inventory,
                fixture.InventoryBytes,
                falseComplete),
            "missing units cannot claim complete");
    }

    private static void CreateComponentRevisions(
        Fixture fixture,
        IReadOnlyDictionary<string, string> packageRevisions)
    {
        foreach (var package in fixture.Inventory.Packages)
        {
            foreach (var component in package.Components)
            {
                if (!Directory.Exists(Path.Combine(fixture.Root, component.RevisionRoot)))
                {
                    CreateComponentRevision(
                        fixture,
                        component,
                        packageRevisions[package.UnitId]);
                }
            }
        }
    }

    private static void CreateComponentRevision(
        Fixture fixture,
        InventoryComponent component,
        string packageRevision)
    {
        var inputPath = Path.Combine(fixture.Root, component.InputManifestPath);
        var inputBytes = File.ReadAllBytes(inputPath);
        var input = InputManifestService.Parse(inputBytes);
        var binding = RevisionService.LoadPackageBinding(
            fixture.Root,
            packageRevision,
            feedbackBytes: null);
        var initialized = AssessmentService.Initialize(
            "component",
            fixture.Root,
            input,
            inputBytes,
            component.ComponentId,
            [],
            binding);
        var evidence = BuildEvidence(initialized.Identity, component.RenderModes);
        var assessment = Complete(initialized, evidence);
        _ = Render(
            fixture.Root,
            inputPath,
            assessment,
            evidence,
            Path.Combine(fixture.Root, component.RevisionRoot),
            packageRevision);

        var claims = evidence.SourceLedgers.SelectMany(ledger => ledger.Ledger.Records)
            .Select(record => record.Claim)
            .ToArray();
        Assert(
            component.RenderModes.All(mode => claims.Any(claim => claim.Contains(mode, StringComparison.Ordinal))),
            $"every claimed render mode represented for {component.ComponentId}");
        Assert(
            fixture.Inventory.Packages.SelectMany(item => item.Components)
                .Where(item => item.UnitId != component.UnitId)
                .All(sibling => claims.All(claim =>
                    !claim.Contains(sibling.ComponentId, StringComparison.Ordinal))),
            $"no sibling component evidence leakage for {component.ComponentId}");
    }

    private static void TestCompleteReconcileAndIndex(Fixture fixture)
    {
        var validationPaths = fixture.Inventory.Packages
            .SelectMany(package =>
                new[] { package.RevisionRoot }
                    .Concat(package.Components.Select(component => component.RevisionRoot)))
            .Select(root => Directory.GetFiles(
                Path.Combine(fixture.Root, root),
                "*.validation.json",
                SearchOption.AllDirectories).Single())
            .ToArray();
        var before = validationPaths.ToDictionary(path => path, File.ReadAllBytes, StringComparer.Ordinal);
        RunCli(
            fixture,
            [
                "library", "reconcile",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath
            ]);
        var runBytes = File.ReadAllBytes(fixture.RunPath);
        var manifest = LibraryService.Parse(runBytes);
        AssertEqual("complete", manifest.State, "complete library state");
        AssertEqual(6, manifest.Units.Count(unit => unit.State == "completed"), "all units completed");
        Assert(
            manifest.Units.Where(unit => unit.Kind == "component")
                .All(unit => unit.PackageUnitId is not null &&
                    unit.PackageValidationManifestDigest is not null),
            "every component names exact package unit and package validation revision");
        RunCli(
            fixture,
            [
                "library", "validate",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath
            ]);
        foreach (var pair in before)
        {
            AssertBytes(pair.Value, File.ReadAllBytes(pair.Key), "reconcile preserves completed manifest bytes");
        }

        var jsonPath = Path.Combine(fixture.Root, "library-index.json");
        var markdownPath = Path.Combine(fixture.Root, "library-index.md");
        RunCli(
            fixture,
            [
                "library", "index",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath,
                "--json", jsonPath,
                "--markdown", markdownPath
            ]);
        var json = File.ReadAllBytes(jsonPath);
        var markdown = File.ReadAllBytes(markdownPath);
        RunCli(
            fixture,
            [
                "library", "index",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath,
                "--json", jsonPath,
                "--markdown", markdownPath
            ]);
        AssertBytes(json, File.ReadAllBytes(jsonPath), "deterministic factual library JSON");
        AssertBytes(markdown, File.ReadAllBytes(markdownPath), "deterministic factual library Markdown");
        var text = Encoding.UTF8.GetString(markdown).ToLowerInvariant();
        foreach (var prohibited in new[] { "verdict", "ranking", "priority", "decision guidance", "recommendation" })
        {
            Assert(!text.Contains(prohibited, StringComparison.Ordinal), $"factual index excludes {prohibited}");
        }

        Assert(text.Contains("alpha.controls", StringComparison.Ordinal), "index includes first package");
        Assert(text.Contains("beta.controls", StringComparison.Ordinal), "index includes second package");
        Assert(text.Contains("**overall state:** `complete`", StringComparison.Ordinal), "index factual complete state");

        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "inventory", "status",
                    "--root", fixture.Root,
                    "--inventory", fixture.ConfirmedPath,
                    "--run-manifest", fixture.RunPath
                ],
                output,
                error),
            $"inventory status: {error}");
        Assert(output.ToString().Contains("\"completed\":6", StringComparison.Ordinal), "status completed count");
    }

    private static void TestCorruptManifestReconstruction(Fixture fixture)
    {
        var expected = File.ReadAllBytes(fixture.RunPath);
        File.Delete(fixture.RunPath);
        Reconcile(fixture);
        AssertBytes(expected, File.ReadAllBytes(fixture.RunPath), "missing run manifest reconstructs exactly");

        File.WriteAllText(fixture.RunPath, "{\"schema_version\":1", new UTF8Encoding(false));
        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(
                [
                    "inventory", "status",
                    "--root", fixture.Root,
                    "--inventory", fixture.ConfirmedPath,
                    "--run-manifest", fixture.RunPath
                ],
                output,
                error),
            "truncated run manifest status invalid");
        Assert(output.ToString().Contains("\"state\":\"invalid\"", StringComparison.Ordinal), "status reports invalid state");
        Reconcile(fixture);
        AssertBytes(expected, File.ReadAllBytes(fixture.RunPath), "truncated run manifest reconstructs exactly");

        var parsed = LibraryService.Parse(expected);
        var stale = parsed with
        {
            InventoryDigest = new Sha256Digest("sha256", new string('f', 64))
        };
        File.WriteAllBytes(fixture.RunPath, LibraryService.Serialize(stale));
        Reconcile(fixture);
        AssertBytes(expected, File.ReadAllBytes(fixture.RunPath), "stale run manifest reconstructs exactly");
    }

    private static void TestConflictsAndWrongPackage(Fixture fixture)
    {
        var first = fixture.Inventory.Packages[0].Components[0];
        var second = fixture.Inventory.Packages[1].Components[0];
        var secondRoot = Path.Combine(fixture.Root, second.RevisionRoot);
        var saved = Path.Combine(fixture.Root, "saved-second-revision");
        Directory.Move(Path.Combine(secondRoot, "0001"), saved);
        CopyDirectory(
            Path.Combine(fixture.Root, first.RevisionRoot, "0001"),
            Path.Combine(secondRoot, "0001"));
        try
        {
            ExpectValidation(
                () => LibraryService.Reconcile(
                    fixture.Root,
                    fixture.Inventory,
                    fixture.InventoryBytes),
                "conflicting duplicate manifest and component wrong package fail");
        }
        finally
        {
            Directory.Delete(Path.Combine(secondRoot, "0001"), recursive: true);
            Directory.Move(saved, Path.Combine(secondRoot, "0001"));
        }

        Reconcile(fixture);
    }

    private static void TestCliSubprocess(Fixture fixture, string pluginRoot)
    {
        var root = Path.Combine(fixture.Root, "cli-library");
        Directory.CreateDirectory(Path.Combine(root, "inputs"));
        foreach (var file in Directory.GetFiles(Path.Combine(fixture.Root, "inputs")))
        {
            File.Copy(file, Path.Combine(root, "inputs", Path.GetFileName(file)));
        }

        File.Copy(fixture.CandidatesPath, Path.Combine(root, "inventory-candidates.json"));
        var draft = Path.Combine(root, "inventory.draft.json");
        var confirmed = Path.Combine(root, "inventory.confirmed.json");
        var run = Path.Combine(root, "run-manifest.json");
        var json = Path.Combine(root, "library-index.json");
        var markdown = Path.Combine(root, "library-index.md");
        var validator = Path.Combine(
            pluginRoot,
            "skills",
            "blazor-component-readiness",
            "scripts",
            "validator");
        var external = Path.Combine(root, "launcher-artifacts");
        RunLauncher(
            validator,
            root,
            external,
            [
                "inventory", "discover",
                "--root", root,
                "--candidates", Path.Combine(root, "inventory-candidates.json"),
                "--output", draft
            ]);
        var dll = Path.Combine(
            external,
            "bin",
            "Release",
            "net11.0",
            "BlazorComponentReadiness.Validator.dll");
        RunDll(dll, root, [
            "inventory", "confirm",
            "--root", root,
            "--draft", draft,
            "--output", confirmed
        ]);
        RunDll(dll, root, [
            "library", "reconcile",
            "--root", root,
            "--inventory", confirmed,
            "--run-manifest", run
        ]);
        RunDll(dll, root, [
            "library", "validate",
            "--root", root,
            "--inventory", confirmed,
            "--run-manifest", run
        ]);
        RunDll(dll, root, [
            "library", "index",
            "--root", root,
            "--inventory", confirmed,
            "--run-manifest", run,
            "--json", json,
            "--markdown", markdown
        ]);
        RunDll(dll, root, [
            "inventory", "status",
            "--root", root,
            "--inventory", confirmed,
            "--run-manifest", run
        ]);
        Assert(File.Exists(json) && File.Exists(markdown), "CLI subprocess covers all six library commands");
    }

    private static EvidenceBundle BuildEvidence(
        ExactAssessmentIdentity identity,
        IReadOnlyList<string> renderModes)
    {
        var modes = renderModes.Count == 0 ? new[] { "package-wide" } : renderModes;
        var drafts = modes.Select((mode, index) => new EvidenceRecordDraft(
            identity.ComponentId is null
                ? "Exact package evidence supports this package-wide synthetic assessment."
                : $"The {identity.ComponentId} probe exercised render mode {mode}.",
            identity.ComponentId is null
                ? new EvidenceApplicability("repository-wide", null)
                : new EvidenceApplicability("component-specific", identity.ComponentId),
            new EvidenceProvenance(
                identity.ComponentId is null
                    ? EvidenceIdentity.PackageArtifactMetadata
                    : EvidenceIdentity.ReproducedRuntimeObservation,
                identity.ComponentId is null
                    ? NupkgInspector.WholePackageEvidenceLocator
                    : $"probe://{identity.Package.PackageId}/{identity.ComponentId}/render-mode/{mode}",
                identity.ComponentId is null
                    ? "Inspected the exact synthetic package."
                    : $"Ran the bounded synthetic {mode} probe.",
                $"2026-09-02T2{index}:00:00Z",
                new Sha256Digest(
                    "sha256",
                    Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
                        Encoding.UTF8.GetBytes($"{identity.Package.PackageId}\0{identity.ComponentId}\0{mode}")))),
                "commitment-only"),
            [])).ToArray();
        EvidenceSourceLedger ledger = identity.AssessmentKind == "component"
            ? EvidenceLedgerBuilder.BuildComponentLedger(identity, drafts)
            : EvidenceLedgerBuilder.BuildRepositoryLedger(
                new RepositoryLedgerSubject(
                    identity.AssessmentKind,
                    identity.Package,
                    identity.InputManifestDigest,
                    null),
                drafts);
        return EvidenceLedgerBuilder.BuildBundle(
            identity,
            [ledger],
            ledger.Records.Select(record => record.StableId).ToArray());
    }

    private static ReadinessAssessment Complete(
        ReadinessAssessment initialized,
        EvidenceBundle evidence)
    {
        var evidenceIds = evidence.Selection.Select(item => item.EvidenceId)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var rows = initialized.Rows.Select((row, index) =>
            index == 0
                ? row with
                {
                    Status = "verified",
                    Observation = "The retained deterministic evidence establishes this synthetic observation.",
                    EvidenceIds = evidenceIds
                }
                : row with
                {
                    Status = "not applicable",
                    NotApplicableRationale = "This deterministic fixture records bounded non-applicability."
                }).ToArray();
        return initialized with
        {
            Rows = rows,
            SummaryGroups = initialized.AssessmentKind == "package"
                ?
                [
                    new AssessmentSummaryGroup(
                        "verified",
                        "One package requirement is verified by retained deterministic evidence.",
                        [rows[0].Id],
                        evidenceIds),
                    new AssessmentSummaryGroup(
                        "not applicable",
                        "The remaining package requirements are synthetically not applicable.",
                        rows.Skip(1).Select(row => row.Id).ToArray(),
                        [])
                ]
                : [],
            CompletionState = "complete"
        };
    }

    private static string Render(
        string root,
        string inputPath,
        ReadinessAssessment assessment,
        EvidenceBundle evidence,
        string revisionRoot,
        string? packageRevision)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(revisionRoot)!);
        var stem = assessment.Identity.ComponentId ?? assessment.Identity.Package.PackageId;
        var assessmentPath = Path.Combine(root, $"{stem}.{assessment.AssessmentKind}.assessment.json");
        var evidencePath = Path.Combine(root, $"{stem}.{assessment.AssessmentKind}.evidence.json");
        File.WriteAllBytes(assessmentPath, AssessmentService.Serialize(assessment));
        File.WriteAllBytes(evidencePath, CanonicalEvidenceJson.SerializeBundle(evidence));
        var args = new List<string>
        {
            "report", "render",
            "--root", root,
            "--input", inputPath,
            "--assessment", assessmentPath,
            "--evidence", evidencePath,
            "--output", revisionRoot
        };
        if (packageRevision is not null)
        {
            args.Add("--package-revision");
            args.Add(packageRevision);
        }

        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(args, output, error),
            $"render {assessment.AssessmentKind}: {error}");
        return Path.Combine(revisionRoot, "0001");
    }

    private static void Reconcile(Fixture fixture) =>
        RunCli(
            fixture,
            [
                "library", "reconcile",
                "--root", fixture.Root,
                "--inventory", fixture.ConfirmedPath,
                "--run-manifest", fixture.RunPath
            ]);

    private static void RunCli(Fixture fixture, IReadOnlyList<string> args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(args, output, error),
            $"CLI {string.Join(' ', args.Take(2))}: {error}");
    }

    private static void RunLauncher(
        string validator,
        string workingDirectory,
        string external,
        IReadOnlyList<string> args)
    {
        var info = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "pwsh" : "bash",
            WorkingDirectory = workingDirectory,
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

        foreach (var argument in args)
        {
            info.ArgumentList.Add(argument);
        }

        info.Environment["READINESS_TEMP"] = external;
        RunProcess(info, "library launcher subprocess");
    }

    private static void RunDll(
        string dll,
        string workingDirectory,
        IReadOnlyList<string> args)
    {
        var info = new ProcessStartInfo
        {
            FileName = "dotnet",
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        info.ArgumentList.Add(dll);
        foreach (var argument in args)
        {
            info.ArgumentList.Add(argument);
        }

        RunProcess(info, $"CLI subprocess {string.Join(' ', args.Take(2))}");
    }

    private static void RunProcess(ProcessStartInfo info, string name)
    {
        using var process = Process.Start(info)
            ?? throw new InvalidOperationException($"Could not start {name}.");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert(
            process.ExitCode == ExitCodes.Success,
            $"{name} failed with {process.ExitCode}.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }

    private static void CopyDirectory(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var file in Directory.GetFiles(source))
        {
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
        }

        foreach (var directory in Directory.GetDirectories(source))
        {
            CopyDirectory(directory, Path.Combine(destination, Path.GetFileName(directory)));
        }
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

    private sealed record PackageSet(
        EvidencePackageIdentity Package,
        string Acquisition,
        string PackageInputPath,
        IReadOnlyList<InputComponent> Components,
        IReadOnlyDictionary<string, string> ComponentInputPaths);

    private sealed record Fixture(
        string Root,
        string CandidatesPath,
        string DraftPath,
        string ConfirmedPath,
        string RunPath,
        LibraryInventory Inventory,
        byte[] InventoryBytes,
        IReadOnlyList<PackageSet> Packages);
}
