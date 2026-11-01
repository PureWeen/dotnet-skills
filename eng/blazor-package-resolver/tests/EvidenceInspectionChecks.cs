using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BlazorPackageResolver;

[assembly: System.Reflection.AssemblyMetadata("RepositoryUrl", "https://example.test/inspection-fixture")]
[assembly: System.Reflection.AssemblyMetadata("RepositoryCommit", "1234567890123456789012345678901234567890")]

internal static class EvidenceInspectionChecks
{
    internal static void Run(string directory)
    {
        const string commit = "1234567890123456789012345678901234567890";
        const string prefix = "sample-" + commit + "/";
        var script = "export const example = 1;"u8.ToArray();
        var package = Zip(
            ("sample.nuspec", Metadata("sample.library",
                """<dependency id="Example.Dependency" version="[1.0.0,2.0.0)" />""")),
            ("[Content_Types].xml", "<Types/>"u8.ToArray()),
            ("staticwebassets/example.js", script),
            ("lib/net8.0/sample.dll", "unmapped compiled bytes"u8.ToArray()),
            ("LICENSE.txt", "retained grant text, not an applicability review"u8.ToArray()));
        var dependency = Zip(
            ("dependency.nuspec", Metadata("example.dependency", "")),
            ("LICENSE.txt", "a named file does not establish a whole-package grant"u8.ToArray()));
        var source = Zip(
            (prefix + "src/example.js", script),
            (prefix + "samples/Getting Started/Page.razor", "<p>Example</p>"u8.ToArray()),
            (prefix + "assets/Check Box.svg", "<svg/>"u8.ToArray()),
            (prefix + "src/Library.csproj", Encoding.UTF8.GetBytes(
                """<Project Sdk="Microsoft.NET.Sdk.Razor"><PropertyGroup><PackageId>sample.library</PackageId></PropertyGroup><PropertyGroup Condition="false"><PackageId>Other.Library</PackageId></PropertyGroup></Project>""")),
            (prefix + "Directory.Build.props", "<Project/>"u8.ToArray()),
            (prefix + "src/Directory.Build.targets", "<Project><Target Name='X'><Exec Command='never execute'/></Target></Project>"u8.ToArray()),
            (prefix + "other/Directory.Build.props", "<Project/>"u8.ToArray()),
            (prefix + "NOTICE.txt", "Literal source notice; not an obligation review."u8.ToArray()),
            (prefix + "LICENSE-boundary.txt", Enumerable.Repeat((byte)'x', 4096).ToArray()),
            (prefix + "LICENSE-large.txt", new byte[4097]),
            (prefix + "COPYING-invalid.txt", new byte[] { 0xff }));
        var pins = new List<PinnedInput>();
        var inputs = new Dictionary<string, CheckedInput>(StringComparer.Ordinal);
        foreach (var (role, data) in new[] { ("package", package), ("source-archive", source), ("dependency-000", dependency) })
        {
            var pin = new PinnedInput(role, role + ".bin", Catalog.Digest(data));
            pins.Add(pin);
            inputs.Add(role, new(pin, data));
        }
        var output = PackageEvidenceInspection.Run(pins, inputs);
        Check(!Lp02PublicSourceResolver.TryArchive(source, out _, commit),
            "The shared default archive profile remains strict; source consumers explicitly admit interior spaces");
        using var document = JsonDocument.Parse(output);
        var result = document.RootElement;
        Check(result.GetProperty("producer").GetString() == "package-evidence-observations/1.0.0", "Bounded observation profile");
        Check(result.GetProperty("package").GetProperty("id").GetString() == "sample.library" &&
            result.GetProperty("package").GetProperty("declared_dependencies")[0].GetProperty("version").GetString() == "[1.0.0,2.0.0)",
            "Observed identity and original range declaration, not a resolved version");
        Check(result.GetProperty("supplied_dependencies").GetArrayLength() == 1 &&
            result.GetProperty("supplied_dependencies")[0].GetProperty("license_declarations")[0]
                .GetProperty("value").GetString() == "MIT", "Supplied exact dependency declaration retained");
        Check(result.GetProperty("package").GetProperty("repository_declarations")[0]
                .GetProperty("commit").GetString() == commit &&
            result.GetProperty("package").GetProperty("license_or_notice_candidates")[0]
                .GetProperty("utf8_text").GetString() == "retained grant text, not an applicability review",
            "Literal repository declarations and complete bounded license text survive without legal interpretation");
        var notices = result.GetProperty("source").GetProperty("license_or_notice_candidates").EnumerateArray().ToArray();
        Check(notices.Single(item => item.GetProperty("path").GetString() == prefix + "NOTICE.txt")
                .GetProperty("text_state").GetString() == "retained-utf8" &&
            notices.Single(item => item.GetProperty("path").GetString() == prefix + "LICENSE-boundary.txt")
                .GetProperty("utf8_text").GetString() == new string('x', 4096) &&
            notices.Single(item => item.GetProperty("path").GetString() == prefix + "LICENSE-large.txt")
                .GetProperty("text_state").GetString() == "size-limit" &&
            notices.Single(item => item.GetProperty("path").GetString() == prefix + "COPYING-invalid.txt")
                .GetProperty("text_state").GetString() == "unsupported-utf8" &&
            notices.Where(item => item.GetProperty("text_state").GetString() != "retained-utf8")
                .All(item => item.GetProperty("utf8_text").ValueKind == JsonValueKind.Null),
            "Named source notices preserve exact digests and explicit size/encoding limits without clipped or normalized text");
        var unsafeAssembly = result.GetProperty("assembly_candidates")[0];
        Check(unsafeAssembly.GetProperty("state").GetString() == "unsafe" &&
            unsafeAssembly.GetProperty("name").ValueKind == JsonValueKind.Null &&
            unsafeAssembly.GetProperty("public_key_length").ValueKind == JsonValueKind.Null,
            "Malformed DLL bytes remain explicit unsupported candidates, not invented unsigned assemblies");
        var fixture = File.ReadAllBytes(typeof(EvidenceInspectionChecks).Assembly.Location);
        var assemblyPackage = Zip(
            ("sample.nuspec", Metadata("sample.library", "")),
            ("lib/net8.0/sample.dll", fixture), ("lib/net9.0/sample.dll", fixture),
            ("lib/net10.0/sample.dll", fixture), ("assets/renamed.png", fixture));
        var assemblyPin = pins[0] with { Sha256 = Catalog.Digest(assemblyPackage) };
        using (var observed = JsonDocument.Parse(PackageEvidenceInspection.Run([assemblyPin],
            new Dictionary<string, CheckedInput> { ["package"] = new(assemblyPin, assemblyPackage) })))
        {
            var assemblies = observed.RootElement.GetProperty("assembly_candidates").EnumerateArray().ToArray();
            Check(assemblies.Length == 4 && assemblies.All(item =>
                item.GetProperty("name").GetString() == "ResolverChecks" &&
                item.GetProperty("version").GetString() is not null &&
                item.GetProperty("informational_versions").GetArrayLength() > 0 &&
                item.GetProperty("repository_metadata").EnumerateArray().Any(value =>
                    value.GetProperty("type").GetString() == "RepositoryUrl" &&
                    value.GetProperty("value").GetString() == "https://example.test/inspection-fixture") &&
                item.GetProperty("repository_metadata").EnumerateArray().Any(value =>
                    value.GetProperty("type").GetString() == "RepositoryCommit" &&
                    value.GetProperty("value").GetString() == commit) &&
                item.GetProperty("state").GetString() == "unsigned" &&
                item.GetProperty("public_key_length").GetInt32() == 0 &&
                !item.GetProperty("strong_name_signed_flag").GetBoolean() &&
                item.GetProperty("strong_name_signature_size").GetInt32() == 0 &&
                item.GetProperty("sha256").GetString() == Catalog.Digest(fixture)),
                "Every shipped PE, including renamed bytes, retains identity, declared version/repository and checked signing fields without loading it");
        }
        var project = result.GetProperty("source").GetProperty("projects")[0];
        Check(project.GetProperty("sdk_declaration").GetString() == "Microsoft.NET.Sdk.Razor" &&
            project.GetProperty("parse_state").GetString() == "unevaluated-xml" &&
            project.GetProperty("package_id_declarations").GetArrayLength() == 2 &&
            project.GetProperty("ancestor_build_files").GetArrayLength() == 2,
            "Razor and relevant inherited build files retained without evaluating conditional identities or targets");
        Check(result.GetProperty("source").GetProperty("declared_root_matches").GetBoolean(), "Literal declared archive prefix comparison");
        var match = result.GetProperty("exact_source_matches").EnumerateArray().Single();
        Check(match.GetProperty("package_entry").GetString() == "staticwebassets/example.js" &&
            match.GetProperty("sha256").GetString() == Catalog.Digest(script) &&
            match.GetProperty("source_entries")[0].GetString() == prefix + "src/example.js",
            "Exact source-text byte correspondence retained independently of unmapped compiled bytes");
        Check(result.GetProperty("package_entries").EnumerateArray().Any(entry =>
                entry.GetProperty("path").GetString() == "lib/net8.0/sample.dll") &&
            result.GetProperty("limitations").EnumerateArray().Any(value =>
                value.GetString()!.Contains("compiled build correspondence", StringComparison.Ordinal)),
            "Compiled payload remains inventoried without claiming build correspondence");
        Check(!result.TryGetProperty("decision", out _) && !result.TryGetProperty("status", out _) &&
            !result.TryGetProperty("reviews", out _) && result.GetProperty("diagnostics").GetArrayLength() == 0,
            "No invented status, verdict, admission or legal review");
        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            foreach (var culture in new[] { "tr-TR", "ar-SA" })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                Check(PackageEvidenceInspection.Run(pins, inputs).SequenceEqual(output), "Culture-independent canonical observations");
            }
        }
        finally { CultureInfo.CurrentCulture = originalCulture; }
        var malformedSource = Zip((prefix + "src/Broken.csproj",
            "<!DOCTYPE Project [<!ENTITY x SYSTEM 'file:///never-read'>]><Project>&x;</Project>"u8.ToArray()));
        var changed = new Dictionary<string, CheckedInput>(inputs);
        var malformedPin = pins[1] with { Sha256 = Catalog.Digest(malformedSource) };
        changed["source-archive"] = new(malformedPin, malformedSource);
        using (var malformed = JsonDocument.Parse(PackageEvidenceInspection.Run(
            [pins[0], malformedPin, pins[2]], changed)))
        {
            Check(malformed.RootElement.GetProperty("diagnostics").GetArrayLength() == 1 &&
                malformed.RootElement.GetProperty("source").GetProperty("projects")[0]
                    .GetProperty("parse_state").GetString() == "unsupported-xml-or-encoding",
                "Unsupported project XML is an explicit limitation, not evaluated content or a silent success");
        }
        changed["source-archive"] = new(pins[1], malformedSource);
        Reject(() => PackageEvidenceInspection.Run(pins, changed), "Changed checked buffer rejected");
        var conflictingSource = Zip(("other-revision/src/Library.csproj", "<Project/>"u8.ToArray()));
        var conflictingPin = pins[1] with { Sha256 = Catalog.Digest(conflictingSource) };
        changed = new(inputs) { ["source-archive"] = new(conflictingPin, conflictingSource) };
        using (var conflicting = JsonDocument.Parse(PackageEvidenceInspection.Run(
            [pins[0], conflictingPin, pins[2]], changed)))
            Check(!conflicting.RootElement.GetProperty("source").GetProperty("declared_root_matches").GetBoolean() &&
                conflicting.RootElement.GetProperty("source").GetProperty("projects").GetArrayLength() == 1 &&
                conflicting.RootElement.GetProperty("diagnostics").GetArrayLength() == 1,
                "Conflicting archive prefix retains local observations with an explicit diagnostic, not source authentication");
        var excessDependencies = Enumerable.Range(0, 65)
            .Select(index => new PinnedInput($"dependency-{index:000}", $"dependency-{index:000}.bin",
                Catalog.Digest(dependency))).ToArray();
        changed = new(StringComparer.Ordinal) { ["package"] = inputs["package"] };
        foreach (var pin in excessDependencies) changed.Add(pin.Role, new(pin, dependency));
        Reject(() => PackageEvidenceInspection.Run([pins[0], .. excessDependencies], changed),
            "The 64-dependency limit is checked before observing packages",
            "Inspection requires one package, optional source-archive and at most 64 dependency-NNN inputs.");
        var repeatedPin = new PinnedInput("dependency-001", "repeated.bin", Catalog.Digest(dependency));
        changed = new(inputs) { ["dependency-001"] = new(repeatedPin, dependency) };
        Reject(() => PackageEvidenceInspection.Run([.. pins, repeatedPin], changed), "Duplicate dependency identities rejected");
        var unsafeBytes = Zip(("../escape", "data"u8.ToArray()));
        var unsafePin = pins[1] with { Sha256 = Catalog.Digest(unsafeBytes) };
        changed = new(inputs) { ["source-archive"] = new(unsafePin, unsafeBytes) };
        Reject(() => PackageEvidenceInspection.Run([pins[0], unsafePin, pins[2]], changed), "Unsafe source archive rejected");
        foreach (var unsafePath in new[] { prefix + "../escape", prefix + "src/ file.cs",
            prefix + "src/file.cs ", prefix + "src\\escape.cs", prefix + "src/file:stream" })
        {
            var invalid = Zip((unsafePath, "data"u8.ToArray()));
            var invalidPin = pins[1] with { Sha256 = Catalog.Digest(invalid) };
            changed = new(inputs) { ["source-archive"] = new(invalidPin, invalid) };
            Reject(() => PackageEvidenceInspection.Run([pins[0], invalidPin, pins[2]], changed),
                "Inspection path extension still rejects traversal, alias-prone spaces and platform syntax");
        }
        var manyProjects = Zip(Enumerable.Range(0, 65).Select(index =>
            (prefix + $"src/Project{index}.csproj", "<Project/>"u8.ToArray())).ToArray());
        var manyProjectsPin = pins[1] with { Sha256 = Catalog.Digest(manyProjects) };
        changed = new(inputs) { ["source-archive"] = new(manyProjectsPin, manyProjects) };
        Reject(() => PackageEvidenceInspection.Run([pins[0], manyProjectsPin, pins[2]], changed),
            "The 64-project limit fails rather than silently dropping projects",
            "Source inspection supports at most 64 project files.");
        var oversizedProject = Zip((prefix + "src/Large.csproj",
            new byte[Lp02PublicSourceResolver.MaxSelectedFileBytes + 1]));
        var oversizedProjectPin = pins[1] with { Sha256 = Catalog.Digest(oversizedProject) };
        changed = new(inputs) { ["source-archive"] = new(oversizedProjectPin, oversizedProject) };
        using (var oversized = JsonDocument.Parse(PackageEvidenceInspection.Run(
            [pins[0], oversizedProjectPin, pins[2]], changed)))
            Check(oversized.RootElement.GetProperty("diagnostics").GetArrayLength() == 1 &&
                oversized.RootElement.GetProperty("source").GetProperty("projects")[0]
                    .GetProperty("parse_state").GetString() == "size-limit",
                "Project byte cap is explicit while other useful observations survive");
        var repeatedRoot = Zip(
            [("sample.nuspec", Metadata("sample.library", "")),
             .. Enumerable.Range(0, 128).Select(index => ($"scripts/{index}.js", script))]);
        var repeatedSource = Zip(Enumerable.Range(0, 128).Select(index =>
            (prefix + "src/" + new string('x', 160) + index + ".js", script)).ToArray());
        var outputRootPin = pins[0] with { Sha256 = Catalog.Digest(repeatedRoot) };
        var outputSourcePin = pins[1] with { Sha256 = Catalog.Digest(repeatedSource) };
        Reject(() => PackageEvidenceInspection.Run([outputRootPin, outputSourcePin],
            new Dictionary<string, CheckedInput>
            {
                ["package"] = new(outputRootPin, repeatedRoot),
                ["source-archive"] = new(outputSourcePin, repeatedSource)
            }), "The measured serialized-output limit rejects rather than clipping matches",
            "Evidence observation output exceeds 2 MiB; no clipped packet was produced.");
        var path = Path.Combine(directory, "inspection-request.json");
        foreach (var input in inputs.Values)
            File.WriteAllBytes(Path.Combine(directory, input.Identity.Path), input.Content.ToArray());
        var request = new JsonObject
        {
            ["schema_version"] = 1,
            ["inputs"] = new JsonArray(pins.Select(pin => (JsonNode)new JsonObject
            {
                ["role"] = pin.Role, ["path"] = pin.Path, ["sha256"] = pin.Sha256
            }).ToArray())
        };
        File.WriteAllText(path, request.ToJsonString());
        Check(Requests.Inspect(path).SequenceEqual(output), "Installed request admission preserves exact checked observations");
        foreach (var mutation in new Action<JsonNode>[]
        {
            value => value["inputs"]![0]!["sha256"] = new string('0', 64),
            value => value["inputs"]![0]!["path"] = "../escape",
            value => value["inputs"]!.AsArray().Add(value["inputs"]![0]!.DeepClone()),
            value => value["inputs"]![1]!["role"] = "source-observation",
            value => value["schema_version"] = 2,
            value => value["inputs"] = null,
            value => value["inputs"] = new JsonArray(Enumerable.Range(0, 67)
                .Select(_ => request["inputs"]![0]!.DeepClone()).ToArray()),
            value => value["expected"] = new JsonObject(),
        })
        {
            var invalid = request.DeepClone();
            mutation(invalid);
            File.WriteAllText(path, invalid.ToJsonString());
            Reject(() => Requests.Inspect(path), "Malformed, changed or authority-shaped inspection input rejected");
        }
        File.WriteAllText(path, """{"schema_version":1,"schema_version":1,"inputs":[]}""");
        Reject(() => Requests.Inspect(path), "Duplicate top-level fields rejected");
        File.Delete(path);
        foreach (var pin in pins) File.Delete(Path.Combine(directory, pin.Path));
        Console.WriteLine("Evidence inspection: retained Razor/import, literal license/source notices, per-PE identity/signing observations, exact matches, dependency declarations, limits and strict input bindings passed.");
    }

    private static byte[] Metadata(string id, string dependencies) => Encoding.UTF8.GetBytes($$"""
        <package><metadata><id>{{id}}</id><version>1.0.0</version><license type="expression">MIT</license>
        <repository type="git" url="https://github.com/example/sample" commit="1234567890123456789012345678901234567890"/>
        <dependencies><group targetFramework="net8.0">{{dependencies}}</group></dependencies></metadata></package>
        """);

    private static byte[] Zip(params (string Path, byte[] Bytes)[] entries)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, true))
            foreach (var entry in entries)
            {
                using var stream = archive.CreateEntry(entry.Path).Open();
                stream.Write(entry.Bytes);
            }
        return output.ToArray();
    }

    private static void Reject(Action action, string message, string? expectedError = null)
    {
        try { action(); }
        catch (Exception error) when (error is InvalidDataException or JsonException or IOException)
        {
            if (expectedError is not null) Check(error.Message == expectedError, message);
            return;
        }
        throw new Exception(message);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }
}
