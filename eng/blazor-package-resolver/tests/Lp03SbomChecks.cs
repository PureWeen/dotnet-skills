using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using BlazorPackageResolver;

internal static class Lp03SbomChecks
{
    internal static void Run(Registry registry)
    {
        var root = Path.Combine(Path.GetTempPath(), "lp03-sbom-" + Guid.NewGuid().ToString("N"));
        try
        {
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("PYTHON") ?? "python")
                { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "-B", Path.Combine(FixtureCorpus.Tests(), "oracles", "lp03_sbom_expectations.py"),
                "--materialize", root }) start.ArgumentList.Add(arg);
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(120000))
            {
                process.Kill(entireProcessTree: true);
                throw new InvalidOperationException("Synthetic byte materialization timeout.");
            }
            Check(process.ExitCode == 0, output.Result + error.Result);
            // Python writes prescribed stimuli/answers only; this calls the actual native resolver.
            var fixture = Path.Combine(root, "cases.json");
            var cases = JsonNode.Parse(File.ReadAllBytes(fixture))!["cases"]!.AsArray();
            var positive = cases.Single(c => (string?)c!["case_id"] == "all-mit-no-grants-no-reviews")!;
            var pins = positive["inputs"]!.AsArray();
            var checkedInputs = pins.ToDictionary(p => (string)p!["role"]!, p =>
            {
                var pin = JsonSerializer.Deserialize<PinnedInput>(p!.ToJsonString(),
                    new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower })!;
                return new CheckedInput(pin, File.ReadAllBytes(Path.Combine(root, pin.Path)));
            }, StringComparer.Ordinal);
            var mutations = 0;
            MixedInventoryChecks.Run(registry, checkedInputs);
            var first = Replay.Run(fixture, registry);
            Check(first.SequenceEqual(Replay.Run(fixture, registry)), "Current profile replay determinism");
            void Mutate(string role, Action<JsonNode> edit, string branch)
            {
                var inputs = new Dictionary<string, CheckedInput>(checkedInputs, StringComparer.Ordinal);
                var doc = JsonNode.Parse(inputs[role].Content.Span)!;
                edit(doc);
                Replace(inputs, role, Encoding.UTF8.GetBytes(doc.ToJsonString()));
                if (role == "sbom")
                {
                    var scope = JsonNode.Parse(inputs["assessment"].Content.Span)!;
                    scope["sbom_sha256"] = inputs["sbom"].Identity.Sha256;
                    scope["designation"]!["sbom_sha256"] = inputs["sbom"].Identity.Sha256;
                    Replace(inputs, "assessment", Encoding.UTF8.GetBytes(scope.ToJsonString()));
                }
                var result = registry.Dispatch(new("native-hostile-" + mutations, "LP-03",
                    inputs.Values.Select(i => i.Identity).ToArray(), inputs));
                Check(result.BranchId == branch, "Native hostile mutation " + mutations + ": " + result.BranchId);
                mutations++;
            }
            Mutate("sbom", d => d["packages"]![0]!["versionInfo"] = "v2.0.0", "binding-conflict");
            Mutate("sbom", d => d["packages"]![1]!["versionInfo"] = "2.0.0", "binding-conflict");
            Mutate("sbom", d =>
            {
                d["packages"]![1]!["versionInfo"] = "2.0.0";
                d["packages"]![1]!["externalRefs"]![0]!["referenceLocator"] = "pkg:nuget/example.controls@2.0.0";
            }, "binding-conflict");
            Mutate("sbom", d => d["packages"]!.AsArray().RemoveAt(1), "closure-unresolved");
            Mutate("sbom", d => d["relationships"]!.AsArray().Add(d["relationships"]![1]!.DeepClone()), "closure-unresolved");
            Mutate("sbom", d => d["packages"]![2]!["name"] = "other", "binding-conflict");
            Mutate("sbom", d => d["packages"]![2]!["externalRefs"]![0]!["referenceLocator"] = "pkg:npm/example@1.0.0", "binding-conflict");
            Mutate("sbom", d => d["relationships"]![2]!["relationshipType"] = "OPTIONAL_DEPENDENCY_OF", "closure-unresolved");
            Mutate("sbom", d => d["documentDescribes"]!.AsArray().Add("SPDXRef-Root"), "closure-unresolved");
            Mutate("sbom", d => d["packages"]![2]!["filesAnalyzed"] = "false", "input-invalid");
            Mutate("sbom", d => d["packages"]![2]!["supplier"] = 1, "input-invalid");
            Mutate("sbom", d => d["creationInfo"]!["creators"]![0] = 1, "input-invalid");
            Mutate("assessment", d => d["designation"]!["root"]!["sha256"] = new string('0', 64), "binding-conflict");
            Mutate("assessment", d => d["inventory_scope"] = "partial", "closure-unresolved");
            Mutate("assessment", d => d["designation"]!["scope"] = "partial", "closure-unresolved");
            Mutate("assessment", d => d["unexpected"] = true, "input-invalid");
            Mutate("sbom", d => d["name"] = new string('a', 16385), "input-invalid");
            Mutate("sbom", d => d["packages"]![2]!["SPDXID"] = "DocumentRef-external:component", "closure-unresolved");
            Mutate("sbom", d =>
            {
                var packages = d["packages"]!.AsArray();
                while (packages.Count < 67) packages.Add(packages[2]!.DeepClone());
            }, "closure-unresolved");
            Mutate("sbom", d =>
            {
                var relationships = d["relationships"]!.AsArray();
                while (relationships.Count < 513) relationships.Add(relationships[1]!.DeepClone());
            }, "closure-unresolved");
            Mutate("sbom", d => d["packages"]![2]!["hasFiles"] = new JsonArray("SPDXRef-File-absent"), "closure-unresolved");
            Mutate("sbom", d =>
            {
                var packages = d["packages"]!.AsArray();
                var prototype = packages[2]!.DeepClone();
                packages.RemoveAt(2);
                var ids = new List<string>();
                for (var index = 0; index < 64; index++)
                {
                    var item = prototype.DeepClone();
                    var id = "SPDXRef-Dependency-" + new string('x', 230) + index.ToString("D2");
                    ids.Add(id);
                    item["SPDXID"] = id;
                    item["name"] = "d" + index.ToString("D2");
                    item["externalRefs"]![0]!["referenceLocator"] = "pkg:nuget/" + item["name"] + "@1.0.0";
                    packages.Add(item);
                }
                var relationships = new JsonArray(d["relationships"]![0]!.DeepClone(), d["relationships"]![1]!.DeepClone());
                void Edge(string from, string to) => relationships.Add(new JsonObject
                {
                    ["relationshipType"] = "DEPENDS_ON", ["spdxElementId"] = from, ["relatedSpdxElement"] = to
                });
                foreach (var id in ids) Edge("SPDXRef-Product", id);
                foreach (var from in ids)
                    foreach (var to in ids)
                        if (from != to && relationships.Count < 512) Edge(from, to);
                d["relationships"] = relationships;
            }, "input-invalid");
            var declarations = 0;
            void Declaration(string label, XElement dependencies, string branch, string? refusedAttribute = null,
                bool copyleft = false)
            {
                var inputs = new Dictionary<string, CheckedInput>(checkedInputs, StringComparer.Ordinal);
                Replace(inputs, "package", Package("example.controls", dependencies));
                var scope = JsonNode.Parse(inputs["assessment"].Content.Span)!;
                scope["root"]!["sha256"] = inputs["package"].Identity.Sha256;
                scope["designation"]!["root"]!["sha256"] = inputs["package"].Identity.Sha256;
                Replace(inputs, "assessment", Encoding.UTF8.GetBytes(scope.ToJsonString()));
                if (copyleft)
                    Replace(inputs, "dependency-000", Package("example.dependency", expression: "GPL-3.0-only"));
                var result = registry.Dispatch(new("native-root-declaration-" + declarations, "LP-03",
                    inputs.Values.Select(i => i.Identity).ToArray(), inputs));
                Check(result.BranchId == branch, label + ": " + result.BranchId + " / " + result.MissingFact);
                if (refusedAttribute is not null)
                    Check(result.Decision == "escalated" && result.Applicability == "unknown" &&
                        result.Finding is null && result.RequiredInput == "authoritative-release-inventory" &&
                        result.NextCategory == "dependency-acquisition" &&
                        result.MissingFact == "Unsupported or malformed root dependency " + refusedAttribute + " declaration. " +
                            Lp03DependencyLicensesResolver.NpmTrust,
                        label + ": unsupported declaration must be not tested, not a gap or positive.");
                declarations++;
            }
            XElement Dependency(string? version, string? attribute = null, string? value = null)
            {
                var node = new XElement("dependency", new XAttribute("id", "example.dependency"));
                if (version is not null) node.Add(new XAttribute("version", version));
                if (attribute is not null) node.Add(new XAttribute(attribute, value!));
                return node;
            }
            XElement Dependencies(int position, string? version, string? attribute = null, string? value = null)
            {
                var node = Dependency(version, attribute, value);
                if (position == -1) return new XElement("dependencies", node);
                return new XElement("dependencies", Enumerable.Range(0, 3).Select(index =>
                    new XElement("group", new XAttribute("targetFramework", $"net{index + 8}.0"),
                        index == position ? node : Dependency("0.5.0"))));
            }
            foreach (var version in new string?[] { null, "0.0.0", "0.5.0", "0.99999.99999", "1.0.0", "[1.0.0]" })
                for (var position = -1; position < 3; position++)
                    Declaration($"supported version {version ?? "(omitted)"} / group {position}",
                        Dependencies(position, version), "dependencies-policy-satisfied");
            foreach (var version in new[]
            {
                "not-a-version", "", " ", " 1.0.0 ", "01.0.0", "1.0", "1.0.0.0", "0.0.100000",
                "1.0.0-beta.1", "1.0.0+build", "1.*", "[1.0.0", "1.0.0]", "[[1.0.0]]",
                "[1.0.0,2.0.0)", "(,1.0.0]", "[1.0.0,)", "(,)", new string('1', 4096)
            })
                for (var position = -1; position < 3; position++)
                    Declaration($"unsupported version {version} / group {position}",
                        Dependencies(position, version), "closure-unresolved", "version");
            foreach (var attribute in new[] { "include", "exclude" })
            {
                foreach (var value in new[]
                {
                    "Build,Analyzers", " runtime , COMPILE ", "all", "none",
                    "Runtime,Compile,Build,Native,ContentFiles,Analyzers,BuildTransitive",
                    "Build" + new string(' ', 251)
                })
                    Declaration($"supported {attribute} {value}", Dependencies(-1, "1.0.0", attribute, value),
                        "dependencies-policy-satisfied");
                foreach (var value in new[]
                {
                    "", " ", "NotAnAsset", "Build,Unknown", "Build,,Analyzers", ",Build", "Build,",
                    "Build;Analyzers", "Build,build", "All,Compile", "None,Build",
                    "Build" + new string(' ', 252)
                })
                    for (var position = -1; position < 3; position++)
                        Declaration($"unsupported {attribute} {value} / group {position}",
                            Dependencies(position, "1.0.0", attribute, value), "closure-unresolved", attribute);
            }
            var both = Dependencies(-1, "0.5.0", "include", "All");
            both.Element("dependency")!.Add(new XAttribute("exclude", "Build,Analyzers"));
            Declaration("both asset attributes; literal minimum is not selected version", both, "dependencies-policy-satisfied");
            Declaration("include none never removes inventoried copyleft dependency",
                Dependencies(-1, "1.0.0", "include", "none"), "incompatible-dependency-license", copyleft: true);
            var request = Path.Combine(root, "admit.json");
            var admissionPins = pins.Where(p => (string?)p!["role"] is "package" or "assessment" or "sbom")
                .Select(p => p!.DeepClone()).ToArray();
            File.WriteAllText(request, new JsonObject { ["schema_version"] = 1,
                ["inputs"] = new JsonArray(admissionPins) }.ToJsonString(), new UTF8Encoding(false));
            using var admitted = JsonDocument.Parse(Requests.AdmitSbom(request));
            var admission = admitted.RootElement.GetProperty("admission");
            Check(admission.GetProperty("structural_admission").GetString() == "admitted" &&
                admission.GetProperty("designation_admission").GetString() == "designated", "Separate shared admission results");
            Check(admission.GetProperty("inventory").GetProperty("dependencies").GetArrayLength() == 1, "Exact inventory API");
            Console.WriteLine($"LP-03 SBOM: {cases.Count} prescribed current-profile native replays, " +
                $"{mutations} native hostile mutations, {declarations} native root-declaration checks; " +
                $"real shared admission API; SHA-256 {Catalog.Digest(first)}.");
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static void Replace(Dictionary<string, CheckedInput> inputs, string role, byte[] bytes)
    {
        var pin = inputs[role].Identity with { Sha256 = Catalog.Digest(bytes) };
        inputs[role] = new(pin, bytes);
    }
    private static byte[] Package(string id, XElement? dependencies = null, string expression = "MIT")
    {
        var metadata = new XElement("metadata", new XElement("id", id), new XElement("version", "1.0.0"),
            new XElement("license", new XAttribute("type", "expression"), expression), dependencies);
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("Package.nuspec", CompressionLevel.NoCompression);
            entry.LastWriteTime = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
            using var stream = entry.Open();
            stream.Write(Encoding.UTF8.GetBytes(new XElement("package", metadata).ToString(SaveOptions.DisableFormatting)));
        }
        return buffer.ToArray();
    }
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("LP-03 B-prime check: " + message);
    }
}
