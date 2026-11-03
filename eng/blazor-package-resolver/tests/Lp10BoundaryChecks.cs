using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using BlazorPackageResolver;

internal static class Lp10BoundaryChecks
{
    private static readonly JsonSerializerOptions FixtureJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static void Run(Registry registry, string fixture)
    {
        var suite = JsonSerializer.Deserialize<CaseSuite>(File.ReadAllBytes(fixture), FixtureJson)
            ?? throw new InvalidDataException("Missing LP-10 cases.");
        var directory = Path.GetDirectoryName(fixture)!;
        var ids = new[]
        {
            "lp10-upper-js", "lp10-inline-task", "lp10-compiled-plus-js",
            "lp10-nuspec-comment-decoy", "lp10-build-comment-decoy",
            "lp10-per-entry-at-limit", "lp10-per-entry-over-limit",
            "lp10-total-at-limit", "lp10-total-over-limit",
            "lp10-msbuild-xml-at-limit", "lp10-msbuild-xml-over-limit",
            "lp10-import-count-at-limit", "lp10-import-count-over-limit"
        };
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            foreach (var culture in new[] { "tr-TR", "ar-SA" })
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
                foreach (var id in ids)
                {
                    var item = suite.Cases.Single(item => item.CaseId == id);
                    var identity = item.Inputs.Single();
                    var content = File.ReadAllBytes(Path.Combine(directory, identity.Path));
                    Check(Catalog.Digest(content) == identity.Sha256, "Pinned boundary input bytes");
                    var relocated = identity with { Path = "unavailable/but-pinned.nupkg" };
                    var input = new ResolverCase(id, "LP-10", [relocated],
                        new Dictionary<string, CheckedInput>
                            { ["package"] = new(relocated, content) });
                    var actual = registry.Dispatch(input);
                    Check(Canonical.Write((actual with { Inputs = item.Inputs }).Write)
                        .SequenceEqual(Canonical.Write(item.Expected.Write)),
                        $"LP-10 {id} under {culture} consumes only checked bytes");
                    if (id.StartsWith("lp10-per-entry-", StringComparison.Ordinal) ||
                        id.StartsWith("lp10-total-", StringComparison.Ordinal))
                    {
                        using var archive = new ZipArchive(new MemoryStream(content), ZipArchiveMode.Read);
                        var lengths = archive.Entries.Where(entry => !entry.FullName.EndsWith(
                            ".nuspec", StringComparison.OrdinalIgnoreCase)).Select(entry => entry.Length);
                        var expected = id.StartsWith("lp10-per-entry-", StringComparison.Ordinal)
                            ? 8L * 1024 * 1024 : 32L * 1024 * 1024;
                        var observed = id.StartsWith("lp10-per-entry-", StringComparison.Ordinal)
                            ? lengths.Max() : lengths.Sum();
                        Check(observed == expected + (id.EndsWith("over-limit", StringComparison.Ordinal) ? 1 : 0),
                            $"LP-10 {id} tests the measured uncompressed ceiling");
                    }
                }
            }
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
        Console.WriteLine($"LP-10 supplemental checked-byte, culture and resource checks: {ids.Length * 2} cases passed.");
        CheckCrcCorruption(registry);
        CheckOracleProbes(registry, suite);
        CheckProvenance(registry);
        CheckRetained(registry, Path.Combine(directory, "acceptance.json"));
    }

    private sealed record OracleProbe(string Name, string Path, string Text, string Branch,
        string? Kind = null, string? Reason = null, string? FirstLocator = null,
        int LocatorCount = 0, string? LocatorsSha256 = null, string? Source = null);

    private static void CheckOracleProbes(Registry registry, CaseSuite suite)
    {
        const string property = "$([System.IO.File]::ReadAllText('a'))";
        const string props = "build/Task.props";
        const string emptyLocators = "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570";
        const string unsupported = "unsupported-executable-content";
        const string text = "text-code-attribution-unverified";
        const string incomplete = "incomplete-inventory";
        const string noCode = "no-code-payload";
        const string msbuildUnsupported = "msbuild-unsupported";
        const string msbuildActive = "msbuild-active";
        var probes = new[]
        {
            new OracleProbe("node-comment", props,
                $"<Project><PropertyGroup><Foo><!--c-->{property}</Foo></PropertyGroup></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/PropertyGroup[1]/Foo[1]#property-function", 1,
                "af360726ff2a071c3d41459bf850ddc2e127fbf75e4864f8eddf9e266c9ba46c"),
            new OracleProbe("node-pi", props,
                $"<Project><PropertyGroup><Foo><?pi x?>{property}</Foo></PropertyGroup></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/PropertyGroup[1]/Foo[1]#property-function", 1,
                "af360726ff2a071c3d41459bf850ddc2e127fbf75e4864f8eddf9e266c9ba46c"),
            new OracleProbe("node-cdata-whitespace", props,
                $"<Project><PropertyGroup><Foo> \n<!--c--><![CDATA[{property}]]></Foo></PropertyGroup></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/PropertyGroup[1]/Foo[1]#property-function", 1,
                "d22213db33b8c20c84990ee406c61babbd133dc8ca4805e599eedbb4083e17cd"),
            new OracleProbe("metadata-comment", props,
                $"<Project><ItemGroup><I Include=\"x\"><M><!--c-->{property}</M></I></ItemGroup></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/ItemGroup[1]/I[1]/M[1]#property-function", 1,
                "099e1d8713b7e96aa639071a0e0acdecf5e6b8ae6624ecf6b84e4b096d4a58e7"),
            new OracleProbe("tail-comment-pi-cdata", props,
                $"<Project><PropertyGroup><A/><!--c--><?pi x?><![CDATA[{property}]]><B/></PropertyGroup></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/PropertyGroup[1]/A[1]#tail-function", 1,
                "0b3b2ac8e82335c6da7f0ecaa98e01a36db4dfa7dd3da524794777a1e582fa6e"),
            new OracleProbe("tail-concatenated-text", props,
                $"<Project><PropertyGroup><A/>prefix<!--c-->{property}<?pi x?>suffix<B/></PropertyGroup></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/PropertyGroup[1]/A[1]#tail-function", 1,
                "f7950ecd8ec64318a38fc8fee1c2dff41dc75811a9e6470e10c69a41b8069923"),
            new OracleProbe("command-comment", props,
                "<Project><PropertyGroup><PreBuildEvent><!--c-->echo sample</PreBuildEvent></PropertyGroup></Project>",
                text, "text", msbuildActive,
                "Project[1]/PropertyGroup[1]/PreBuildEvent[1]#text", 1,
                "768f2e4bbe0dc916efc4cf7ac5624536bb3e37f558cd131112e347642c363030"),
            new OracleProbe("command-concatenated-text", props,
                "<Project><PropertyGroup><PreBuildEvent>echo <!--c-->sample</PreBuildEvent></PropertyGroup></Project>",
                text, "text", msbuildActive,
                "Project[1]/PropertyGroup[1]/PreBuildEvent[1]#text", 1,
                "768f2e4bbe0dc916efc4cf7ac5624536bb3e37f558cd131112e347642c363030"),
            new OracleProbe("command-cdata", props,
                "<Project><PropertyGroup><PreBuildEvent><![CDATA[echo sample]]></PreBuildEvent></PropertyGroup></Project>",
                text, "text", msbuildActive,
                "Project[1]/PropertyGroup[1]/PreBuildEvent[1]#text", 1,
                "768f2e4bbe0dc916efc4cf7ac5624536bb3e37f558cd131112e347642c363030"),
            new OracleProbe("inline-task-comment-cdata", props,
                $"<Project><UsingTask TaskName=\"T\" TaskFactory=\"RoslynCodeTaskFactory\"><Task><!--c--><![CDATA[{property}]]></Task></UsingTask></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/UsingTask[1]/Task[1]#property-function", 2,
                "be5cc76fb30f45686684a61f8a99406f01ca2278750d816d656b1fdb511d89a4"),
            new OracleProbe("inline-task-concatenated-text", props,
                $"<Project><UsingTask TaskName=\"T\" TaskFactory=\"RoslynCodeTaskFactory\"><Task>prefix<!--c-->{property}</Task></UsingTask></Project>",
                unsupported, "unsupported", msbuildUnsupported,
                "Project[1]/UsingTask[1]/Task[1]#property-function", 2,
                "8d505d73b88a3d0c0999b276381e24baacf6a27bf3e1d3f6846308184b75760c"),
            new OracleProbe("inline-code-source-comment", props,
                "<Project><UsingTask TaskName=\"T\" TaskFactory=\"RoslynCodeTaskFactory\"><Task><Code Source=\"$(MSBuildThisFileDirectory)src.txt\"><!--c-->return 1;</Code></Task></UsingTask></Project>",
                text, "text", msbuildActive,
                "Project[1]/UsingTask[1]/Task[1]/Code[1]#text", 2,
                "99f0db0aaeae1526c69e37f40d9d659c70e6fc5fcb193592794342ae143da637",
                "passive text"),
            new OracleProbe("uppercase-xml-pi", "build/run.txt",
                "<?XML version=\"1.0\"?>\n<Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("uppercase-xml-pi-over-limit", "build/run.txt",
                "<?XML version=\"1.0\"?>\n<!--" + new string('x', 262144) +
                "--><Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-prolog", "build/run.txt",
                "<?xml version=\"1.0\"?>\u001c<Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-1d-prolog", "build/run.txt",
                "<?xml version=\"1.0\"?>\u001d<Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-1e-prolog", "build/run.txt",
                "<?xml version=\"1.0\"?>\u001e<Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-1f-prolog", "build/run.txt",
                "<?xml version=\"1.0\"?>\u001f<Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-root-boundary", "build/run.txt",
                "<Project\u001c><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-1c-doctype", "build/run.txt",
                "<!\u001cDOCTYPE Project><Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-1d-doctype", "build/run.txt",
                "<!\u001dDOCTYPE Project><Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-1e-doctype", "build/run.txt",
                "<!\u001eDOCTYPE Project><Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("unicode-control-1f-doctype", "build/run.txt",
                "<!\u001fDOCTYPE Project><Project><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></Project>",
                incomplete),
            new OracleProbe("non-ascii-first-prefix", "build/run.txt",
                "<\u0394:Project xmlns:\u0394=\"http://schemas.microsoft.com/developer/msbuild/2003\"><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></\u0394:Project>",
                noCode),
            new OracleProbe("ascii-first-unicode-prefix", "build/run.txt",
                "<A\u00e9:Project xmlns:A\u00e9=\"http://schemas.microsoft.com/developer/msbuild/2003\"><A\u00e9:Target Name=\"Go\"><A\u00e9:Exec Command=\"echo sample\"/></A\u00e9:Target></A\u00e9:Project>",
                text, "text", msbuildActive,
                "Project[1]/Target[1]/Exec[1]@Command", 1,
                "7fb8fe33ee4ace317fd79d4b33f5b36583b5261ea9d257197e51941b7d64c434"),
            new OracleProbe("python-word-numeric-prefix", "build/run.txt",
                "<A\u2160:Project xmlns:A\u2160=\"http://schemas.microsoft.com/developer/msbuild/2003\"><Target Name=\"Go\"><Exec Command=\"echo sample\"/></Target></A\u2160:Project>",
                incomplete),
            new OracleProbe("property-function-comment-pi-decoy", props,
                $"<Project><PropertyGroup><Foo><!--{property}--><?pi {property}?></Foo></PropertyGroup></Project>",
                noCode),
            new OracleProbe("bom-lib-xml-doc", "lib/net8.0/Sample.xml",
                "\ufeff<?xml version=\"1.0\"?><doc/>", noCode)
        };
        foreach (var probe in probes)
        {
            var raw = Encoding.UTF8.GetBytes(probe.Text);
            var bytes = OraclePackage(probe.Path, raw, probe.Source);
            var identity = new PinnedInput("package", "unavailable/but-pinned.nupkg",
                Catalog.Digest(bytes));
            var input = new ResolverCase(probe.Name, "LP-10", [identity],
                new Dictionary<string, CheckedInput> { ["package"] = new(identity, bytes) });
            var actual = registry.Dispatch(input);
            var expected = suite.Cases.First(item => item.Expected.BranchId == probe.Branch).Expected;
            Check(actual.BranchId == probe.Branch &&
                actual.Decision == expected.Decision &&
                actual.Applicability == expected.Applicability &&
                actual.EvidenceReferences.SequenceEqual(expected.EvidenceReferences) &&
                actual.Finding == expected.Finding &&
                actual.MissingFact == expected.MissingFact &&
                actual.RequiredInput == expected.RequiredInput &&
                actual.NextCategory == expected.NextCategory,
                $"Oracle-derived branch/result contract: {probe.Name}");
            if (probe.Kind is null)
            {
                Check(actual.EvidenceContract == expected.EvidenceContract,
                    $"Oracle-derived no-code/structural evidence: {probe.Name}");
                continue;
            }
            const string prefix = "Checked code candidates (exact bytes hashed; locator snippets are display-only): ";
            const string suffix = ". These checked bytes do not establish ownership, release-commit correspondence or upstream.";
            var contract = actual.EvidenceContract ??
                throw new InvalidDataException($"Missing LP-10 candidate evidence: {probe.Name}");
            Check(contract.StartsWith(prefix, StringComparison.Ordinal) &&
                contract.EndsWith(suffix, StringComparison.Ordinal),
                $"Oracle-derived candidate contract shape: {probe.Name}");
            using var json = JsonDocument.Parse(contract[prefix.Length..^suffix.Length]);
            var candidates = json.RootElement;
            Check(candidates.GetArrayLength() == (probe.Source is null ? 1 : 2),
                $"Oracle-derived candidate count: {probe.Name}");
            CheckCandidate(candidates[0], probe.Path, raw, probe.Kind, probe.Reason!,
                probe.FirstLocator, probe.LocatorCount, probe.LocatorsSha256!, probe.Name);
            if (probe.Source is not null)
                CheckCandidate(candidates[1], "build/src.txt", Encoding.UTF8.GetBytes(probe.Source),
                    "text", "promoted-in-package-code-source", null, 0, emptyLocators, probe.Name);
        }
        Console.WriteLine($"LP-10 oracle-derived XML/text boundary checks: {probes.Length} cases passed.");
    }

    private static byte[] OraclePackage(string path, byte[] payload, string? source)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Add(string name, byte[] content)
            {
                using var output = zip.CreateEntry(name, CompressionLevel.NoCompression).Open();
                output.Write(content);
            }
            Add("Sample.nuspec", "<package><metadata><id>X</id><version>1.0</version></metadata></package>"u8.ToArray());
            Add(path, payload);
            if (source is not null)
                Add("build/src.txt", Encoding.UTF8.GetBytes(source));
        }
        return buffer.ToArray();
    }

    private static void CheckCandidate(JsonElement actual, string path, byte[] raw,
        string kind, string reason, string? first, int count, string locatorsSha, string probe)
    {
        Check(actual.EnumerateObject().Count() == 8 &&
            actual.GetProperty("path").GetString() == path &&
            actual.GetProperty("sha256").GetString() == Catalog.Digest(raw) &&
            actual.GetProperty("size_bytes").GetInt32() == raw.Length &&
            actual.GetProperty("classification").GetString() == kind &&
            actual.GetProperty("reason").GetString() == reason &&
            actual.GetProperty("first_locator").GetString() == first &&
            actual.GetProperty("locator_count").GetInt32() == count &&
            actual.GetProperty("locators_sha256").GetString() == locatorsSha,
            $"Oracle-derived exact entry/locator inventory: {probe}/{path}");
    }

    private static void CheckCrcCorruption(Registry registry)
    {
        const string nuspec = "<package><metadata><id>Sample</id><version>1.0</version></metadata></package>";
        const string script = "console.log(1)";
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, value) in new[]
            {
                ("Sample.nuspec", nuspec), ("wwwroot/code.js", script)
            })
            {
                using var output = zip.CreateEntry(name, CompressionLevel.NoCompression).Open();
                output.Write(Encoding.UTF8.GetBytes(value));
            }
        }
        var archive = buffer.ToArray();
        foreach (var payload in new[] { nuspec, script })
        {
            var bytes = (byte[])archive.Clone();
            var marker = Encoding.UTF8.GetBytes(payload);
            var position = bytes.AsSpan().IndexOf(marker);
            Check(position > 0, "CRC probe must locate uncompressed entry bytes.");
            bytes[position + marker.Length - 1] ^= 1;
            using (var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read))
                Check(zip.Entries.Count == 2, "CRC probe must retain a readable central directory.");
            var pinned = new PinnedInput("package", "pinned-but-absent.nupkg", Catalog.Digest(bytes));
            var input = new ResolverCase("crc-mismatch", "LP-10", [pinned],
                new Dictionary<string, CheckedInput> { ["package"] = new(pinned, bytes) });
            var result = registry.Dispatch(input);
            Check(result.BranchId == "unreadable-package" && result.Applicability == "unknown" &&
                result.RequiredInput == "valid-nupkg" && result.EvidenceContract is null,
                "A damaged nuspec or code-entry CRC cannot yield an inventory.");
        }
    }

    private static void CheckRetained(Registry registry, string fixture)
    {
        var syncfusion = Environment.GetEnvironmentVariable("LP10_SYNCFUSION_NUPKG");
        var infragistics = Environment.GetEnvironmentVariable("LP10_INFRAGISTICS_NUPKG");
        if (syncfusion is null && infragistics is null)
            return;
        if (string.IsNullOrWhiteSpace(syncfusion) || string.IsNullOrWhiteSpace(infragistics))
            throw new InvalidDataException("Both LP-10 retained package bindings are required.");
        var suite = JsonSerializer.Deserialize<CaseSuite>(File.ReadAllBytes(fixture), FixtureJson)
            ?? throw new InvalidDataException("Missing LP-10 retained expectations.");
        Check(suite.Cases.Count == 2, "Two frozen retained LP-10 results");
        foreach (var (item, path, candidateCount) in new[]
        {
            (suite.Cases[0], syncfusion, 24), (suite.Cases[1], infragistics, 10)
        })
        {
            var identity = item.Inputs.Single();
            var bytes = File.ReadAllBytes(path);
            Check(Catalog.Digest(bytes) == identity.Sha256, "Exact retained LP-10 package hash");
            var input = new ResolverCase(item.CaseId, "LP-10", item.Inputs,
                new Dictionary<string, CheckedInput> { ["package"] = new(identity, bytes) });
            var result = registry.Dispatch(input);
            Check(Canonical.Write(result.Write).SequenceEqual(Canonical.Write(item.Expected.Write)) &&
                Canonical.Write(result.Write).SequenceEqual(Canonical.Write(registry.Dispatch(input).Write)),
                $"Frozen retained LP-10 replay: {item.CaseId}");
            var contract = result.EvidenceContract!;
            var candidates = contract["Checked code candidates (exact bytes hashed; locator snippets are display-only): ".Length..];
            candidates = candidates[..candidates.IndexOf(". These checked bytes", StringComparison.Ordinal)];
            using var json = JsonDocument.Parse(candidates);
            Check(json.RootElement.GetArrayLength() == candidateCount &&
                json.RootElement.EnumerateArray().Count(record =>
                    record.GetProperty("classification").GetString() == "compiled") == 3 &&
                json.RootElement.EnumerateArray().Count(record =>
                    record.GetProperty("classification").GetString() == "text") == candidateCount - 3,
                $"Exact retained LP-10 candidate inventory: {item.CaseId}");
            Console.WriteLine($"LP-10 {item.CaseId}: {candidateCount} pinned candidates; mixed escalation matched.");
        }
    }

    internal static void CheckProvenance(Registry registry, string? reReviewGroup = null)
    {
        const string commit = "1111111111111111111111111111111111111111";
        const string repoUrl = "https://github.com/example/controls";
        var nuspec = Encoding.UTF8.GetBytes(
            "<package><metadata><id>Example.Controls</id><version>1.0.0</version>" +
            $"<repository type=\"git\" url=\"{repoUrl}\" commit=\"{commit}\"/></metadata></package>");
        var matchedJs = "export const x = 1;"u8.ToArray();
        var builtJs = "export const built = 2;"u8.ToArray();

        static byte[] BuildZip(params (string Name, byte[] Bytes)[] entries)
        {
            using var ms = new MemoryStream();
            using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var (name, content) in entries)
                {
                    using var stream = zip.CreateEntry(name, CompressionLevel.NoCompression).Open();
                    stream.Write(content);
                }
            }
            return ms.ToArray();
        }

        var pkgBytes = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("wwwroot/matched.js", matchedJs),
            ("staticwebassets/built.js", builtJs),
            (".signature.p7s", "nuget-repository-signature"u8.ToArray()));
        var releaseBytes = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("wwwroot/matched.js", matchedJs),
            ("staticwebassets/built.js", builtJs),
            (".signature.p7s", "author-release-signature"u8.ToArray()));
        var sourceBytes = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/wwwroot/matched.js", matchedJs),
            ($"controls-{commit}/wwwroot/built.js", builtJs),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\"}"u8.ToArray()),
            ($"controls-{commit}/package-lock.json", "{\"name\":\"controls\",\"lockfileVersion\":3}"u8.ToArray()),
            ($"controls-{commit}/src/index.ts", "export const built: number = 2;"u8.ToArray()));

        var releaseSha = Catalog.Digest(releaseBytes);
        var statementJson = JsonSerializer.Serialize(new
        {
            _type = "https://in-toto.io/Statement/v1",
            subject = new[] { new { name = "Example.Controls.1.0.0.nupkg", digest = new { sha256 = releaseSha } } },
            predicateType = "https://slsa.dev/provenance/v1",
            predicate = new
            {
                buildDefinition = new
                {
                    buildType = "https://actions.github.io/buildtypes/workflow/v1",
                    externalParameters = new
                    {
                        workflow = new { repository = repoUrl, path = ".github/workflows/release.yml", @ref = "refs/heads/main" }
                    },
                    internalParameters = new { github = new { event_name = "workflow_dispatch", runner_environment = "github-hosted" } },
                    resolvedDependencies = new[]
                    {
                        new { uri = $"git+{repoUrl}@refs/heads/main", digest = new { gitCommit = commit } }
                    }
                },
                runDetails = new
                {
                    builder = new
                    {
                        id = "https://github.com/example/controls/.github/workflows/release.yml@refs/heads/main",
                        version = new { runner_environment = "github-hosted" }
                    }
                }
            }
        });
        var bundleBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            mediaType = "application/vnd.dev.sigstore.bundle.v0.3+json",
            verificationMaterial = new
            {
                certificate = new { rawBytes = "dGVzdA==" },
                tlogEntries = new[] { new { logIndex = "12345" } }
            },
            dsseEnvelope = new
            {
                payloadType = "application/vnd.in-toto+json",
                payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(statementJson)),
                signatures = new[] { new { sig = "dGVzdA==" } }
            }
        }));

        byte[] BuildAttestation(byte[] pkg, byte[] rel, byte[] bnd, byte[] src,
            string runnerEnv = "github-hosted", string certCommit = commit)
        {
            using var stmtDoc = JsonDocument.Parse(statementJson.Replace(releaseSha, Catalog.Digest(rel), StringComparison.Ordinal));
            var raw = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                schema_version = 1,
                producer = "lp10-gh-attestation-verify/1.0.0",
                package_sha256 = Catalog.Digest(pkg),
                release_package_sha256 = Catalog.Digest(rel),
                provenance_bundle_sha256 = Catalog.Digest(bnd),
                source_archive_sha256 = Catalog.Digest(src),
                verification = new[]
                {
                    new
                    {
                        verificationResult = new
                        {
                            mediaType = "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
                            verifiedTimestamps = new[] { new { type = "Tlog", timestamp = "2026-01-01T00:00:00Z" } },
                            signature = new
                            {
                                certificate = new
                                {
                                    issuer = "https://token.actions.githubusercontent.com",
                                    runnerEnvironment = runnerEnv,
                                    sourceRepositoryVisibilityAtSigning = "public",
                                    sourceRepositoryURI = repoUrl,
                                    sourceRepositoryDigest = certCommit,
                                    buildConfigDigest = certCommit,
                                    buildConfigURI = $"{repoUrl}/.github/workflows/release.yml@refs/heads/main"
                                }
                            },
                            statement = stmtDoc.RootElement
                        }
                    }
                }
            }));
            return ProvenanceTestAdmission.Sign(raw, src, repoUrl, commit);
        }

        CaseResult Dispatch(byte[] pkg, byte[] rel, byte[] bnd, byte[] att, byte[] src, bool dropSource = false)
        {
            var roles = new List<(string Role, string Path, byte[] Bytes)>
            {
                ("package", "package.nupkg", pkg),
                ("release-package", "release.nupkg", rel),
                ("provenance-bundle", "bundle.json", bnd),
                ("provenance-attestation", "attestation.json", att)
            };
            if (!dropSource)
                roles.Add(("source-archive", "source.zip", src));
            var pins = roles.Select(r => new PinnedInput(r.Role, r.Path, Catalog.Digest(r.Bytes))).ToList();
            var map = roles.ToDictionary(r => r.Role, r => new CheckedInput(
                new PinnedInput(r.Role, r.Path, Catalog.Digest(r.Bytes)), r.Bytes), StringComparer.Ordinal);
            return registry.Dispatch(new ResolverCase("lp10-provenance-check", "LP-10", pins, map));
        }

        var validAtt = BuildAttestation(pkgBytes, releaseBytes, bundleBytes, sourceBytes);
        Check(Dispatch(pkgBytes, releaseBytes, bundleBytes, ProvenanceTestAdmission.Payload(validAtt), sourceBytes)
            .BranchId == "provenance-unverified", "B7 caller-authored gh receipt cannot verify without helper binding");
        var noAcquisition = ProvenanceTestAdmission.Sign(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                schema_version = 1, producer = "lp10-gh-attestation-verify/1.0.0",
                package_sha256 = Catalog.Digest(pkgBytes), release_package_sha256 = releaseSha,
                provenance_bundle_sha256 = Catalog.Digest(bundleBytes),
                source_archive_sha256 = Catalog.Digest(sourceBytes),
                verification = JsonDocument.Parse(ProvenanceTestAdmission.Payload(validAtt)).RootElement.GetProperty("verification")
            })), sourceBytes, repoUrl, commit, acquired: false);
        Check(Dispatch(pkgBytes, releaseBytes, bundleBytes, noAcquisition, sourceBytes).BranchId == "provenance-unverified",
            "B1 signed helper admission without trusted exact-commit source acquisition must fail closed");
        var positive = Dispatch(pkgBytes, releaseBytes, bundleBytes, validAtt, sourceBytes);
        Check(positive.BranchId == "provenance-attributed" &&
            positive.Decision == "deterministic" &&
            positive.Applicability == "applicable" &&
            positive.Finding is not null &&
            positive.Finding.Contains("SLSA v1 build provenance and source correspondence verified", StringComparison.Ordinal),
            $"Valid SLSA v1 provenance inputs must resolve to provenance-attributed (got {positive.BranchId}: {positive.MissingFact}).");

        var missingRole = Dispatch(pkgBytes, releaseBytes, bundleBytes, validAtt, sourceBytes, dropSource: true);
        Check(missingRole.BranchId == "provenance-unverified" && missingRole.Decision == "escalated",
            "Missing provenance role must fail closed to provenance-unverified.");

        var selfHosted = Dispatch(pkgBytes, releaseBytes, bundleBytes,
            BuildAttestation(pkgBytes, releaseBytes, bundleBytes, sourceBytes, runnerEnv: "self-hosted"), sourceBytes);
        Check(selfHosted.BranchId == "provenance-unverified" && selfHosted.Decision == "escalated",
            "Self-hosted runner provenance must fail closed to provenance-unverified.");

        var wrongCommit = Dispatch(pkgBytes, releaseBytes, bundleBytes,
            BuildAttestation(pkgBytes, releaseBytes, bundleBytes, sourceBytes, certCommit: new string('2', 40)), sourceBytes);
        Check(wrongCommit.BranchId == "provenance-unverified" && wrongCommit.Decision == "escalated",
            "Mismatched certificate commit must fail closed to provenance-unverified.");

        var tamperedRelease = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("wwwroot/matched.js", "export const x = 999;"u8.ToArray()),
            ("staticwebassets/built.js", builtJs));
        var payloadDiff = Dispatch(pkgBytes, tamperedRelease, bundleBytes,
            BuildAttestation(pkgBytes, tamperedRelease, bundleBytes, sourceBytes), sourceBytes);
        Check(payloadDiff.BranchId == "provenance-unverified" && payloadDiff.Decision == "escalated",
            "Release package payload mismatch must fail closed to provenance-unverified.");

        var sourceMissingWorkflow = BuildZip(
            ($"controls-{commit}/Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/wwwroot/matched.js", matchedJs),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\"}"u8.ToArray()),
            ($"controls-{commit}/package-lock.json", "{\"name\":\"controls\",\"lockfileVersion\":3}"u8.ToArray()),
            ($"controls-{commit}/src/index.ts", "export const built: number = 2;"u8.ToArray()));
        var missingWorkflow = Dispatch(pkgBytes, releaseBytes, bundleBytes,
            BuildAttestation(pkgBytes, releaseBytes, bundleBytes, sourceMissingWorkflow), sourceMissingWorkflow);
        Check(missingWorkflow.BranchId == "provenance-unverified" && missingWorkflow.Decision == "escalated",
            "Source archive missing the attested workflow file must fail closed to provenance-unverified.");

        var sourceMissingLockfile = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/wwwroot/matched.js", matchedJs),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\"}"u8.ToArray()),
            ($"controls-{commit}/src/index.ts", "export const built: number = 2;"u8.ToArray()));
        var missingLockfile = Dispatch(pkgBytes, releaseBytes, bundleBytes,
            BuildAttestation(pkgBytes, releaseBytes, bundleBytes, sourceMissingLockfile), sourceMissingLockfile);
        Check(missingLockfile.BranchId == "provenance-unverified" && missingLockfile.Decision == "escalated",
            "B2 generic web tree without a per-asset source match must fail closed to provenance-unverified.");

        var unmatchedWithLock = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/Controls.csproj", "<Project/>"u8.ToArray()),
            ($"controls-{commit}/wwwroot/matched.js", matchedJs),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\"}"u8.ToArray()),
            ($"controls-{commit}/package-lock.json", "{}"u8.ToArray()),
            ($"controls-{commit}/src/index.ts", "export const unrelated = 0;"u8.ToArray()));
        Check(Dispatch(pkgBytes, releaseBytes, bundleBytes,
            BuildAttestation(pkgBytes, releaseBytes, bundleBytes, unmatchedWithLock), unmatchedWithLock)
            .BranchId == "provenance-unverified", "B2 unmatched JS with package/lock/source tree cannot be attributed");

        using var rootZip = new ZipArchive(new MemoryStream(sourceBytes), ZipArchiveMode.Read);
        var casedSource = BuildZip(rootZip.Entries.Select(e =>
        {
            using var stream = e.Open();
            using var memory = new MemoryStream();
            stream.CopyTo(memory);
            return (e.FullName.Replace("controls-", "Controls-", StringComparison.Ordinal), memory.ToArray());
        }).ToArray());
        Check(Dispatch(pkgBytes, releaseBytes, bundleBytes,
            BuildAttestation(pkgBytes, releaseBytes, bundleBytes, casedSource), casedSource)
            .BranchId == "provenance-attributed", "S3 validated root uses archive's actual casing for workflow lookup");

        var metadata = new System.Reflection.Metadata.Ecma335.MetadataBuilder();
        metadata.AddModule(0, metadata.GetOrAddString("Example.Controls.dll"),
            metadata.GetOrAddGuid(new Guid("11111111-2222-3333-4444-555555555555")), default, default);
        metadata.AddAssembly(metadata.GetOrAddString("Example.Controls"), new Version(1, 0, 0, 0),
            default, default, 0, default);
        metadata.AddTypeDefinition(System.Reflection.TypeAttributes.NotPublic, default,
            metadata.GetOrAddString("<Module>"), default,
            System.Reflection.Metadata.Ecma335.MetadataTokens.FieldDefinitionHandle(1),
            System.Reflection.Metadata.Ecma335.MetadataTokens.MethodDefinitionHandle(1));
        var peBuilder = new System.Reflection.PortableExecutable.ManagedPEBuilder(
            new System.Reflection.PortableExecutable.PEHeaderBuilder(imageCharacteristics:
                System.Reflection.PortableExecutable.Characteristics.ExecutableImage |
                System.Reflection.PortableExecutable.Characteristics.Dll),
            new System.Reflection.Metadata.Ecma335.MetadataRootBuilder(metadata),
            new System.Reflection.Metadata.BlobBuilder(),
            flags: System.Reflection.PortableExecutable.CorFlags.ILOnly);
        var peBlob = new System.Reflection.Metadata.BlobBuilder();
        peBuilder.Serialize(peBlob);
        var assemblyPackage = BuildZip(("Example.Controls.nuspec", nuspec),
            ("lib/net10.0/Example.Controls.dll", peBlob.ToArray()));
        var assemblyBundleNode = System.Text.Json.Nodes.JsonNode.Parse(bundleBytes)!;
        assemblyBundleNode["dsseEnvelope"]!["payload"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            statementJson.Replace(releaseSha, Catalog.Digest(assemblyPackage), StringComparison.Ordinal)));
        var assemblyBundle = Encoding.UTF8.GetBytes(assemblyBundleNode.ToJsonString());
        var wrongProjectSource = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/Unrelated.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"/>"u8.ToArray()));
        Check(Dispatch(assemblyPackage, assemblyPackage, assemblyBundle,
            BuildAttestation(assemblyPackage, assemblyPackage, assemblyBundle, wrongProjectSource), wrongProjectSource)
            .BranchId == "provenance-unverified", "B2 DLL with no matching source project cannot pass on absence of contradictory metadata");
        var matchingProjectSource = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/Unrelated.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Project>"u8.ToArray()));
        Check(Dispatch(assemblyPackage, assemblyPackage, assemblyBundle,
            BuildAttestation(assemblyPackage, assemblyPackage, assemblyBundle, matchingProjectSource), matchingProjectSource)
            .BranchId == "provenance-attributed", "B2 literal source AssemblyName must match shipped filename and CLR identity");

        var failures = new List<string>();
        void Reject(string name, Func<CaseResult> dispatch)
        {
            try
            {
                var result = dispatch();
                Console.WriteLine($"Re-review {name}: {result.BranchId}");
                if (result.BranchId != "provenance-unverified")
                    failures.Add(name + ": " + result.BranchId);
            }
            catch (Exception ex)
            {
                failures.Add(name + ": threw " + ex.GetType().Name);
            }
        }

        if (reReviewGroup is null or "assembly")
        {
            var prefix = $"controls-{commit}/";
            foreach (var (label, file, xml) in new[]
            {
                ("target-nested", "Unrelated.csproj",
                    "<Project><Target Name=\"NeverInvoked\"><PropertyGroup><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Target></Project>"),
                ("item-group-nested", "Unrelated.csproj",
                    "<Project><ItemGroup><AssemblyName>Example.Controls</AssemblyName></ItemGroup></Project>"),
                ("item-group-property-group", "Unrelated.csproj",
                    "<Project><ItemGroup><PropertyGroup><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></ItemGroup></Project>"),
                ("target-direct", "Unrelated.csproj",
                    "<Project><Target Name=\"NeverInvoked\"><AssemblyName>Example.Controls</AssemblyName></Target></Project>"),
                ("project-direct", "Unrelated.csproj",
                    "<Project><AssemblyName>Example.Controls</AssemblyName></Project>"),
                ("conditional-group", "Unrelated.csproj",
                    "<Project><PropertyGroup Condition=\"'$(Never)' == 'true'\"><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Project>"),
                ("conditional-property", "Unrelated.csproj",
                    "<Project><PropertyGroup><AssemblyName Condition=\"'$(Never)' == 'true'\">Example.Controls</AssemblyName></PropertyGroup></Project>"),
                ("unsupported-name-forbids-filename-fallback", "Example.Controls.csproj",
                    "<Project><Target Name=\"NeverInvoked\"><PropertyGroup><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Target></Project>"),
                ("mixed-supported-unsupported-names", "Example.Controls.csproj",
                    "<Project><PropertyGroup><AssemblyName>Example.Controls</AssemblyName></PropertyGroup><Target Name=\"NeverInvoked\"><PropertyGroup><AssemblyName>Other</AssemblyName></PropertyGroup></Target></Project>"),
                ("lowercase-condition-group", "Unrelated.csproj",
                    "<Project><PropertyGroup condition=\"'$(Never)' == 'true'\"><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Project>"),
                ("lowercase-assemblyname-fallback-bypass", "Example.Controls.csproj",
                    "<Project><PropertyGroup><assemblyname>Other</assemblyname></PropertyGroup></Project>"),
                ("lowercase-assemblyname-conflict", "Unrelated.csproj",
                    "<Project><PropertyGroup><AssemblyName>Example.Controls</AssemblyName><assemblyname>Other</assemblyname></PropertyGroup></Project>"),
                ("conditional-root-filename-fallback", "Example.Controls.csproj",
                    "<Project Condition=\"'$(Never)' == 'true'\"/>"),
                ("foreign-namespace-project", "Example.Controls.csproj",
                    "<Project xmlns=\"urn:not-msbuild\"/>"),
                ("foreign-namespace-literal-project", "Unrelated.csproj",
                    "<Project xmlns=\"urn:not-msbuild\"><PropertyGroup><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Project>"),
                ("target-lowercase-assemblyname-fallback", "Example.Controls.csproj",
                    "<Project><Target Name=\"NeverInvoked\"><PropertyGroup><assemblyname>Other</assemblyname></PropertyGroup></Target></Project>"),
                ("uppercase-assemblyname", "Example.Controls.csproj",
                    "<Project><PropertyGroup><ASSEMBLYNAME>Other</ASSEMBLYNAME></PropertyGroup></Project>"),
                ("lowercase-root-condition", "Example.Controls.csproj",
                    "<Project condition=\"'$(Never)' == 'true'\"/>"),
                ("mixed-case-group-condition", "Unrelated.csproj",
                    "<Project><PropertyGroup cOnDiTiOn=\"false\"><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Project>"),
                ("foreign-namespace-lowercase-name", "Example.Controls.csproj",
                    "<Project xmlns:x=\"urn:other\"><PropertyGroup><x:assemblyname>Other</x:assemblyname></PropertyGroup></Project>"),
                ("namespaced-condition-group", "Unrelated.csproj",
                    "<Project xmlns:x=\"urn:other\"><PropertyGroup x:condition=\"false\"><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Project>")
            })
            {
                var projectBytes = Encoding.UTF8.GetBytes(xml);
                var files = new Dictionary<string, byte[]> { [prefix + file] = projectBytes };
                if (Lp10BinaryAttributionResolver.HasMatchingProject("lib/net10.0/Example.Controls.dll",
                    peBlob.ToArray(), files, prefix))
                    failures.Add("AssemblyName direct " + label);
                var source = BuildZip(
                    (prefix + ".github/workflows/release.yml", "name: release\n"u8.ToArray()),
                    (prefix + file, projectBytes));
                Reject("AssemblyName integration " + label, () => Dispatch(assemblyPackage, assemblyPackage,
                    assemblyBundle, BuildAttestation(assemblyPackage, assemblyPackage, assemblyBundle, source), source));
            }
            Check(Lp10BinaryAttributionResolver.HasMatchingProject("lib/net10.0/Example.Controls.dll",
                peBlob.ToArray(), new Dictionary<string, byte[]>
                {
                    [prefix + "Example.Controls.csproj"] = "<Project/>"u8.ToArray()
                }, prefix), "Re-review filename fallback remains valid only without any AssemblyName");
            foreach (var xml in new[]
            {
                "<Project xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\"/>",
                "<Project xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\"><PropertyGroup><AssemblyName>Example.Controls</AssemblyName></PropertyGroup></Project>"
            })
            {
                var source = BuildZip((prefix + ".github/workflows/release.yml", "name: release\n"u8.ToArray()),
                    (prefix + "Example.Controls.csproj", Encoding.UTF8.GetBytes(xml)));
                Check(Dispatch(assemblyPackage, assemblyPackage, assemblyBundle,
                    BuildAttestation(assemblyPackage, assemblyPackage, assemblyBundle, source), source)
                    .BranchId == "provenance-attributed", "Delta canonical MSBuild-2003 literal/default-name control");
            }
        }

        if (reReviewGroup is null or "json")
        {
            foreach (var field in new[] { "payload", "hmac_sha256" })
            {
                var envelope = Encoding.UTF8.GetBytes("{\"payload\":\"e30=\",\"hmac_sha256\":\"00\"}".Replace(
                    field == "payload" ? "\"e30=\"" : "\"00\"", "\"\\uD800\"", StringComparison.Ordinal));
                Check(HelperAdmission.Open(envelope) is null, "Delta helper envelope surrogate " + field);
                Reject("helper envelope surrogate " + field,
                    () => Dispatch(pkgBytes, releaseBytes, bundleBytes, envelope, sourceBytes));
            }
            foreach (var field in new[] { "path", "name", "version" })
            {
                var manifest = "{\"schema_version\":1,\"assets\":[{\"path\":\"staticwebassets/built.js\"," +
                    "\"sha256\":\"" + Catalog.Digest(builtJs) + "\",\"inputs\":[{\"path\":\"src/input.ts\",\"sha256\":\"" +
                    Catalog.Digest(matchedJs) + "\"}],\"components\":[{\"name\":\"example\",\"version\":\"1.0.0\"}]}]}";
                var original = field == "path" ? "staticwebassets/built.js" : field == "name" ? "example" : "1.0.0";
                manifest = manifest.Replace("\"" + original + "\"", "\"\\uD800\"", StringComparison.Ordinal);
                Check(!Lp10BinaryAttributionResolver.TryBundlerAsset(
                    new Dictionary<string, byte[]> { ["readiness-bundler-manifest.json"] = Encoding.UTF8.GetBytes(manifest) },
                    new Dictionary<string, byte[]> { [$"controls-{commit}/src/input.ts"] = matchedJs },
                    $"controls-{commit}/", "staticwebassets/built.js", Catalog.Digest(builtJs), out _),
                    "Delta bundler manifest surrogate " + field);
            }
            foreach (var scalar in new[] { "1", "2147483648", "1.5", "\"1\"", "null", "true", "{}", "[]" })
            {
                var manifest = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema_version = JsonSerializer.Deserialize<JsonElement>(scalar),
                    assets = new[] { new { path = "staticwebassets/built.js", sha256 = Catalog.Digest(builtJs),
                        inputs = new[] { new { path = "src/index.ts",
                            sha256 = Catalog.Digest("export const unrelated = 0;"u8.ToArray()) } },
                        components = new[] { new { name = "example", version = "1.0.0" } } } }
                });
                var package = BuildZip(("Example.Controls.nuspec", nuspec), ("wwwroot/matched.js", matchedJs),
                    ("staticwebassets/built.js", builtJs), ("readiness-bundler-manifest.json", manifest));
                var bundleNode = System.Text.Json.Nodes.JsonNode.Parse(bundleBytes)!;
                bundleNode["dsseEnvelope"]!["payload"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                    statementJson.Replace(releaseSha, Catalog.Digest(package), StringComparison.Ordinal)));
                var bundle = Encoding.UTF8.GetBytes(bundleNode.ToJsonString());
                if (scalar == "1")
                {
                    Check(Dispatch(package, package, bundle, BuildAttestation(package, package, bundle, unmatchedWithLock),
                        unmatchedWithLock).BranchId == "provenance-attributed", "Re-review valid bound bundler manifest control");
                    continue;
                }
                Reject("manifest schema " + scalar, () => Dispatch(package, package, bundle,
                    BuildAttestation(package, package, bundle, unmatchedWithLock), unmatchedWithLock));

                foreach (var field in new[] { "schema_version", "archive_size", "http_status" })
                {
                    var receipt = System.Text.Json.Nodes.JsonNode.Parse(ProvenanceTestAdmission.Payload(validAtt))!;
                    var container = field == "schema_version" ? receipt :
                        field == "archive_size" ? receipt["source_acquisition"]! :
                        receipt["source_acquisition"]!["retrieval_attempt"]!;
                    container[field] = System.Text.Json.Nodes.JsonNode.Parse(scalar);
                    var attestation = ProvenanceTestAdmission.Sign(Encoding.UTF8.GetBytes(receipt.ToJsonString()),
                        sourceBytes, repoUrl, commit, acquired: false);
                    Reject("admission " + field + " " + scalar,
                        () => Dispatch(pkgBytes, releaseBytes, bundleBytes, attestation, sourceBytes));
                }
            }
            static byte[] WithMember(byte[] json, string member)
            {
                var text = Encoding.UTF8.GetString(json);
                return Encoding.UTF8.GetBytes(text.Insert(text.LastIndexOf('}'), "," + member));
            }
            byte[] BundleFor(byte[] package, string? statementMember = null)
            {
                var statement = Encoding.UTF8.GetBytes(statementJson.Replace(releaseSha, Catalog.Digest(package),
                    StringComparison.Ordinal));
                if (statementMember is not null) statement = WithMember(statement, statementMember);
                var node = System.Text.Json.Nodes.JsonNode.Parse(bundleBytes)!;
                node["dsseEnvelope"]!["payload"] = Convert.ToBase64String(statement);
                return Encoding.UTF8.GetBytes(node.ToJsonString());
            }
            void UnicodeDispatch(string label, bool valid, Func<CaseResult> dispatch)
            {
                if (valid)
                    Check(dispatch().BranchId == "provenance-attributed", "Unicode paired-surrogate control " + label);
                else
                    Reject("Unicode ignored/unvisited " + label, dispatch);
            }
            foreach (var (label, member, valid) in new[]
            {
                ("string", "\"ignored\":\"\\uD800\"", false),
                ("name", "\"\\uD800\":null", false),
                ("nested array", "\"ignored\":[null,false,42,{\"value\":\"\\uDC00\"}]", false),
                ("valid pair", "\"ignored\":[{\"\\uD83D\\uDE00\":\"\\uD83D\\uDE00\"}]", true)
            })
            {
                foreach (var surface in new[] { "envelope", "payload" })
                {
                    var receipt = surface == "envelope" ? WithMember(validAtt, member) :
                        ProvenanceTestAdmission.SignPayload(WithMember(ProvenanceTestAdmission.Payload(validAtt), member));
                    using var opened = HelperAdmission.Open(receipt);
                    if ((opened is not null) != valid) failures.Add("Unicode direct helper " + surface + " " + label);
                    UnicodeDispatch("helper " + surface + " " + label, valid,
                        () => Dispatch(pkgBytes, releaseBytes, bundleBytes, receipt, sourceBytes));
                }

                var manifest = WithMember(JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema_version = 1,
                    assets = new[] { new { path = "staticwebassets/built.js", sha256 = Catalog.Digest(builtJs),
                        inputs = new[] { new { path = "src/index.ts",
                            sha256 = Catalog.Digest("export const unrelated = 0;"u8.ToArray()) } },
                        components = new[] { new { name = "example", version = "1.0.0" } } } }
                }), member);
                var package = BuildZip(("Example.Controls.nuspec", nuspec), ("wwwroot/matched.js", matchedJs),
                    ("staticwebassets/built.js", builtJs), ("readiness-bundler-manifest.json", manifest));
                var bundle = BundleFor(package);
                if (Lp10BinaryAttributionResolver.TryBundlerAsset(
                    new Dictionary<string, byte[]> { ["readiness-bundler-manifest.json"] = manifest },
                    new Dictionary<string, byte[]> { [$"controls-{commit}/src/index.ts"] = "export const unrelated = 0;"u8.ToArray() },
                    $"controls-{commit}/", "staticwebassets/built.js", Catalog.Digest(builtJs), out _) != valid)
                    failures.Add("Unicode direct manifest " + label);
                UnicodeDispatch("manifest " + label, valid, () => Dispatch(package, package, bundle,
                    BuildAttestation(package, package, bundle, unmatchedWithLock), unmatchedWithLock));

                foreach (var surface in new[] { "bundle", "statement" })
                {
                    var alteredBundle = surface == "bundle" ? WithMember(bundleBytes, member) :
                        BundleFor(releaseBytes, member);
                    UnicodeDispatch(surface + " " + label, valid, () => Dispatch(pkgBytes, releaseBytes, alteredBundle,
                        BuildAttestation(pkgBytes, releaseBytes, alteredBundle, sourceBytes), sourceBytes));
                }
            }
            foreach (var (label, json, valid) in new[]
            {
                ("identical root", "{\"key\":1,\"key\":1}", false),
                ("conflicting root", "{\"key\":1,\"key\":2}", false),
                ("decoded escaped name", "{\"key\":1,\"\\u006bey\":2}", false),
                ("nested array", "{\"ignored\":[{\"key\":1,\"key\":2}]}", false),
                ("case-distinct", "{\"key\":1,\"Key\":2}", true),
                ("independent objects", "[{\"key\":1},{\"key\":2}]", true)
            })
            {
                using var document = JsonDocument.Parse(json);
                if (JsonStringValidation.IsWellFormed(document.RootElement) != valid)
                    failures.Add("Duplicate JSON direct " + label);
            }
            const string duplicateMember = "\"ignored\":[{\"key\":1,\"key\":2}]";
            foreach (var surface in new[] { "envelope", "payload" })
            {
                var receipt = surface == "envelope" ? WithMember(validAtt, duplicateMember) :
                    ProvenanceTestAdmission.SignPayload(WithMember(ProvenanceTestAdmission.Payload(validAtt), duplicateMember));
                using var opened = HelperAdmission.Open(receipt);
                if (opened is not null) failures.Add("Duplicate JSON direct helper " + surface);
                Reject("duplicate JSON helper " + surface,
                    () => Dispatch(pkgBytes, releaseBytes, bundleBytes, receipt, sourceBytes));
            }
            foreach (var member in new[] { "\"schema_version\":1", duplicateMember })
            {
                var manifest = WithMember(JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema_version = 1,
                    assets = new[] { new { path = "staticwebassets/built.js", sha256 = Catalog.Digest(builtJs),
                        inputs = new[] { new { path = "src/index.ts",
                            sha256 = Catalog.Digest("export const unrelated = 0;"u8.ToArray()) } },
                        components = new[] { new { name = "example", version = "1.0.0" } } } }
                }), member);
                var package = BuildZip(("Example.Controls.nuspec", nuspec), ("wwwroot/matched.js", matchedJs),
                    ("staticwebassets/built.js", builtJs), ("readiness-bundler-manifest.json", manifest));
                var bundle = BundleFor(package);
                if (Lp10BinaryAttributionResolver.TryBundlerAsset(
                    new Dictionary<string, byte[]> { ["readiness-bundler-manifest.json"] = manifest },
                    new Dictionary<string, byte[]> { [$"controls-{commit}/src/index.ts"] = "export const unrelated = 0;"u8.ToArray() },
                    $"controls-{commit}/", "staticwebassets/built.js", Catalog.Digest(builtJs), out _))
                    failures.Add("Duplicate JSON direct manifest " + member);
                Reject("duplicate JSON manifest " + member, () => Dispatch(package, package, bundle,
                    BuildAttestation(package, package, bundle, unmatchedWithLock), unmatchedWithLock));
            }
            foreach (var surface in new[] { "bundle", "statement" })
            {
                var bundle = surface == "bundle" ? WithMember(bundleBytes, duplicateMember) :
                    BundleFor(releaseBytes, duplicateMember);
                Reject("duplicate JSON " + surface, () => Dispatch(pkgBytes, releaseBytes, bundle,
                    BuildAttestation(pkgBytes, releaseBytes, bundle, sourceBytes), sourceBytes));
            }
        }
        Check(failures.Count == 0, "Re-review fail-closed regressions: " + string.Join("; ", failures));
        Console.WriteLine("LP-10 strict helper/source/per-entry provenance regressions passed.");
    }

    private static void Check(bool success, string reason)
    {
        if (!success)
            throw new InvalidDataException(reason);
    }
}
