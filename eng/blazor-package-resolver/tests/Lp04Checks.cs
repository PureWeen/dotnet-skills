using System.IO.Compression;
using System.Text;
using BlazorPackageResolver;

internal static class Lp04Checks
{
    private const string Nuspec = "<package><metadata><id>Sample</id><version>1.0.0</version></metadata></package>";

    internal static void Run(Registry registry, Catalog catalog, string fixture)
    {
        _ = catalog;
        var assertions = 0;
        void Check(bool condition, string label)
        {
            assertions++;
            if (!condition) throw new InvalidOperationException("LP-04 D-lite: " + label);
        }
        byte[] Package((string Path, byte[] Content)[] files, string nuspec = Nuspec)
        {
            using var bytes = new MemoryStream();
            using (var zip = new ZipArchive(bytes, ZipArchiveMode.Create, true))
            {
                foreach (var (path, content) in new[] { ("Sample.nuspec", Encoding.UTF8.GetBytes(nuspec)) }.Concat(files))
                {
                    var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
                    entry.LastWriteTime = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
                    using var output = entry.Open();
                    output.Write(content);
                }
            }
            return bytes.ToArray();
        }
        CaseResult Resolve(byte[]? package, string? role = null, byte[]? extra = null)
        {
            var pins = new List<PinnedInput>();
            var inputs = new Dictionary<string, CheckedInput>(StringComparer.Ordinal);
            void Add(string name, byte[] content)
            {
                var pin = new PinnedInput(name, name + ".bin", Catalog.Digest(content));
                pins.Add(pin);
                inputs.Add(name, new(pin, content));
            }
            if (package is not null) Add("package", package);
            if (role is not null) Add(role, extra ?? Encoding.UTF8.GetBytes("{}"));
            var input = new ResolverCase("dlite", "LP-04", pins, inputs);
            var result = registry.Dispatch(input);
            result.Validate(input);
            Check(result.ResolverVersion == "2.0.0" && result.Decision == "escalated" &&
                result.Applicability == "unknown" && result.Finding is null &&
                !string.IsNullOrWhiteSpace(result.RequiredInput) && !string.IsNullOrWhiteSpace(result.MissingFact),
                "only unresolved, substantive outcomes");
            Check(Encoding.UTF8.GetByteCount(result.MissingFact!) <= 4096, "bounded observation without truncation");
            return result;
        }
        void Branch(byte[] package, string branch) =>
            Check(Resolve(package).BranchId == branch, branch);
        Check(Resolve(null).BranchId == "missing-package", "missing package");
        var empty = Package([]);
        var emptyResult = Resolve(empty);
        Check(emptyResult.BranchId == "no-supported-layout-assets" &&
            emptyResult.MissingFact!.Contains(
                "No JS/CSS assets detected in the supported package layouts; other representations were not assessed.",
                StringComparison.Ordinal), "empty surface is not universal N/A: " + emptyResult.BranchId + " " + emptyResult.MissingFact);
        Check(emptyResult.BundledWebAssets is { Assets.Count: 0, UnsupportedCandidates.Count: 0 },
            "empty checked inventory retained");

        var syncfusion = Enumerable.Range(1, 21).Select(index =>
            ($"staticwebassets/scripts/{index:00}.js", Encoding.UTF8.GetBytes($"script{index}")))
            .Append(("staticwebassets/styles/theme.css", new byte[2723500])).ToArray();
        var sync = Resolve(Package(syncfusion));
        Check(sync.BranchId == "origin-review-missing" && sync.BundledWebAssets!.Assets.Count == 22 &&
            sync.MissingFact!.Contains(".js=21") && sync.MissingFact.Contains(".css=1") &&
            sync.BundledWebAssets.Assets.Sum(asset => asset.Length) == syncfusion.Sum(file => (long)file.Item2.Length),
            "Syncfusion-like 21 JS and large CSS");
        var files = new (string, byte[])[]
        {
            ("contentFiles/any/net8.0/wwwroot/x.css", [1]),
            ("wwwroot/lib/x.min.js", []),
            ("STATICWEBASSETS/a.MJS", [2]),
            ("WwWrOoT/b.CjS", [3]),
            ("ContentFILES/cs/NET9.0/WWWROOT/isolated.styles.CSS", [4]),
            ("staticwebassets/a.js.MAP", Encoding.UTF8.GetBytes("{\"sourcesContent\":[\"x\"]}")),
            ("staticwebassets/orphan.map", [5]),
            ("contentFiles/any/net9.0/wwwroot/x.css", [1])
        };
        var multiPackage = Package(files);
        var multi = Resolve(multiPackage);
        var inventory = multi.BundledWebAssets!;
        Check(multi.BranchId == "origin-review-missing" && inventory.Assets.Count == files.Length,
            "all layouts/suffixes, case-insensitive, empty/minified/generated/maps/all TFMs");
        Check(inventory.Assets.Select(asset => asset.Path).SequenceEqual(
            files.Select(file => file.Item1).Order(StringComparer.Ordinal)), "ordinal paths preserved");
        Check(inventory.Assets.All(asset => asset.Length == files.Single(file => file.Item1 == asset.Path).Item2.Length &&
            asset.Sha256 == Catalog.Digest(files.Single(file => file.Item1 == asset.Path).Item2)), "exact lengths and hashes");
        var expectedCanonical = "bundled-web-assets/1\n" + string.Concat(files.OrderBy(file => file.Item1, StringComparer.Ordinal)
            .Select(file => file.Item1 + "\t" + file.Item2.Length + "\t" + Catalog.Digest(file.Item2) + "\n"));
        Check(inventory.InventorySha256 == Catalog.Digest(Encoding.UTF8.GetBytes(expectedCanonical)),
            "independent canonical digest");
        Check(Resolve(Package(files.Reverse().ToArray())).BundledWebAssets!.InventorySha256 == inventory.InventorySha256,
            "ZIP order does not change inventory digest");
        Check(Canonical.Write(multi.Write).SequenceEqual(Canonical.Write(Resolve(multiPackage).Write)),
            "deterministic complete result");
        foreach (var path in new[] { "tools/x.js", "lib/net8.0/x.CSS", "other/wwwroot/x.js",
            "staticwebassets/x.js.gz", "wwwroot/x.CSS.BR", "x.map.gz", "contentFiles/any/wwwroot/x.css",
            "wwwroot.js", "staticwebassets-extra/x.js" })
        {
            var result = Resolve(Package([(path, [1])]));
            Check(result.BranchId == "surface-unsupported" &&
                result.BundledWebAssets!.UnsupportedCandidates.SequenceEqual([path]), "unsupported: " + path);
        }
        var mixed = Resolve(Package([("wwwroot/ok.js", [1]), ("tools/outside.css", [2])]));
        Check(mixed.BranchId == "surface-unsupported" && mixed.BundledWebAssets!.Assets.Count == 1 &&
            mixed.BundledWebAssets.UnsupportedCandidates.Count == 1, "unsupported guard retains selected inventory");
        Branch(Package([("wwwroot/readme.txt", [1]), ("lib/net8.0/a.dll", [2])]), "no-supported-layout-assets");
        foreach (var role in new[] { "assessment", "notice-coverage", "admission", "dependency-inventory",
            "asset-inventory", "obligation-reviews", "notice-mapping", "dependency-001", "asset-001",
            "entry-001", "reference-001" })
            Check(Resolve(empty, role).BranchId == "legacy-protocol", "retired role: " + role);
        Check(Resolve(empty, "notice-coverage", Encoding.UTF8.GetBytes("{\"protocol\":\"notice-coverage-v1\"}"))
            .BranchId == "legacy-protocol", "v1 packet refused, not converted");
        Check(Resolve(empty, "unknown").BranchId == "input-invalid", "unknown role");
        foreach (var path in new[] { "../escape.js", "/wwwroot/x.js", "wwwroot/../x.js",
            "wwwroot\\x.js", "wwwroot/CON.js", "wwwroot/x.js ", "wwwroot/x.js." })
            Branch(Package([(path, [1])]), "input-invalid");
        Branch(Package([("wwwroot/x.js", [1]), ("wwwroot/x.js", [1])]), "input-invalid");
        Branch(Package([("wwwroot/x.js", [1]), ("WWWROOT/X.JS", [1])]), "input-invalid");
        Branch(Package([("wwwroot/ß.js", [1]), ("wwwroot/ss.js", [1])]), "input-invalid");
        Branch(Package([("wwwroot/bad/", [1])]), "input-invalid");
        var link = Package([("wwwroot/x.js", [1])]);
        using (var zip = new ZipArchive(new MemoryStream(link), ZipArchiveMode.Update))
            zip.GetEntry("wwwroot/x.js")!.ExternalAttributes = 0xa000 << 16;
        Branch(link, "input-invalid");
        foreach (var xml in new[]
        {
            "<package><metadata><id>Sample</id><id>Other</id><version>1.0.0</version></metadata></package>",
            "<package><metadata><id>Sample</id><version>1.*</version></metadata></package>",
            "<!DOCTYPE package [<!ENTITY x SYSTEM 'file:///forbidden'>]><package><metadata>&x;</metadata></package>",
            "<package><metadata><id xmlns='foreign'>Sample</id><version>1.0.0</version></metadata></package>",
            "<package>"
        }) Branch(Package([], xml), "input-invalid");
        Branch(Package([("Other.nuspec", Encoding.UTF8.GetBytes(Nuspec))]), "input-invalid");
        Branch(Package([], Nuspec.Replace("<package>",
            "<package xmlns='http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'>")),
            "no-supported-layout-assets");

        var expanded = Package([("wwwroot/first.js", [1]), ("payload.bin", new byte[64 * 1024 * 1024])]);
        var streamed = 0;
        Check(Lp04PackageEvidence.Read(expanded, () => streamed++) is null && streamed == 0,
            "expanded limit rejected before CRC streaming or selected hashing");
        Branch(expanded, "input-invalid");
        var tooMany = Package(Enumerable.Range(0, 513).Select(index => ($"wwwroot/{index:000}.js", Array.Empty<byte>())).ToArray());
        Check(Lp04PackageEvidence.Read(tooMany, () => streamed++) is null && streamed == 0,
            "selected-asset limit before streaming");
        Branch(tooMany, "input-invalid");
        var max = Resolve(Package(Enumerable.Range(0, 512).Select(index =>
            ($"wwwroot/{index:000}-" + new string('x', 90) + ".js", new byte[] { 1 })).ToArray()));
        Check(max.BundledWebAssets!.Assets.Count == 512 && max.MissingFact!.Contains("512 assets") &&
            Encoding.UTF8.GetByteCount(max.MissingFact) <= 4096 &&
            Canonical.Write(max.Write).Length > 4096, "512 assets retained, only observation bounded");
        var tooManyEntries = Package(Enumerable.Range(0, 4096).Select(index => ($"data/{index}", Array.Empty<byte>())).ToArray());
        Branch(tooManyEntries, "input-invalid");
        Branch(new byte[8 * 1024 * 1024 + 1], "input-invalid");
        var crc = (byte[])multiPackage.Clone();
        var central = crc.AsSpan().IndexOf(new byte[] { 0x50, 0x4b, 0x01, 0x02 });
        crc[14] ^= 1;
        crc[central + 16] ^= 1;
        Branch(crc, "input-invalid");
        Branch(multiPackage[..^1], "input-invalid");
        Branch([1, 2, 3], "input-invalid");
        var badPin = new PinnedInput("package", "package.nupkg", new string('0', 64));
        var mismatch = new Lp04NoticeCoverageResolver().Resolve(new("bad", "LP-04", [badPin],
            new Dictionary<string, CheckedInput> { ["package"] = new(badPin, empty) }));
        Check(mismatch.BranchId == "input-invalid", "digest mismatch");
        Replay.Run(Path.Combine(fixture, "cases.json"), registry);
        Console.WriteLine($"LP-04 D-lite: {assertions} assertions and frozen v2 result replays passed; v1 deciding tests retired.");
    }
}
