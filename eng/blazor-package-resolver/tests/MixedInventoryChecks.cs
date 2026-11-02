using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BlazorPackageResolver;

internal static class MixedInventoryChecks
{
    internal static void Run(Registry registry, Dictionary<string, CheckedInput> baseline)
    {
        var checks = 0;
        void Check(bool value, string label)
        {
            if (!value) throw new InvalidOperationException("Mixed inventory: " + label);
            checks++;
        }
        InventoryComponent Component(string id, string ecosystem = "nuget") =>
            new("SPDXRef-" + id.Replace('/', '-').Replace('@', '-'), id, "1.0.0", "", ecosystem);
        Check(Lp02PublicSourceResolver.SafeSourceMemberPath("repo/src/Comparer$1.ts") &&
            !Lp02PublicSourceResolver.SafePath("repo/src/Comparer$1.ts"), "Dollar allowance is source-only");
        var ordered = Spdx22InventoryAdmission.Ordered([
            Component("foo1"), Component("@scope/foo", "npm"), Component("foo"), Component("foo", "npm")]);
        Check(ordered.Select(c => c.Ecosystem + ":" + c.Key).SequenceEqual(
            ["nuget:foo/1.0.0", "nuget:foo1/1.0.0", "npm:@scope/foo/1.0.0", "npm:foo/1.0.0"]),
            "Historical id/version comparator, NuGet first; prefix IDs and mixed ecosystems");
        foreach (var purl in new[] { "pkg:npm/@scope/foo@1.0.0", "pkg:npm/%40scope/foo@1.0.0",
            "pkg:npm/foo@1.0.0-beta.1+build.2" })
            Check(NpmPackageIdentity.TryParsePurl(purl, out _, out _), purl);
        foreach (var purl in new string?[] { null, "pkg:npm/@scope%2ffoo@1.0.0", "pkg:npm/%2540scope/foo@1.0.0",
            "pkg:npm/@scope/../foo@1.0.0", "pkg:npm/foo@^1.0.0", "pkg:npm/foo@latest",
            "pkg:npm/foo@1.0.0?x=y", "pkg:npm/foo@1.0.0#x", "pkg:npm/foo@01.0.0",
            "pkg:npm/foo@1.0.0-01", "pkg:npm/@scope\\foo@1.0.0", "pkg:npm/foo@1.0.0@evil" })
            Check(!NpmPackageIdentity.TryParsePurl(purl, out _, out _), "Reject " + purl);

        Dictionary<string, CheckedInput> Packet(string license = "MIT", bool archive = true)
        {
            var inputs = new Dictionary<string, CheckedInput>(baseline, StringComparer.Ordinal);
            var sbom = JsonNode.Parse(inputs["sbom"].Content.Span)!;
            var npm = sbom["packages"]![2]!.DeepClone();
            npm["name"] = "@scope/foo";
            npm["SPDXID"] = "SPDXRef-Npm";
            npm["externalRefs"]![0]!["referenceLocator"] = "pkg:npm/@scope/foo@1.0.0";
            sbom["packages"]!.AsArray().Add(npm);
            sbom["relationships"]!.AsArray().Add(Edge("SPDXRef-Product", "SPDXRef-Npm"));
            SetSbom(inputs, sbom);
            if (archive)
            {
                var bytes = Tarball(license);
                Replace(inputs, "dependency-001", bytes);
                var manifest = new JsonObject
                {
                    ["schema_version"] = 1, ["basis"] = "caller-designated-exact-npm-archives/1",
                    ["root_sha256"] = inputs["package"].Identity.Sha256,
                    ["sbom_sha256"] = inputs["sbom"].Identity.Sha256,
                    ["archives"] = new JsonArray(new JsonObject
                    {
                        ["purl"] = "pkg:npm/@scope/foo@1.0.0", ["path"] = "npm.tgz",
                        ["sha256"] = Catalog.Digest(bytes)
                    })
                };
                Replace(inputs, "npm-archives", Encoding.UTF8.GetBytes(manifest.ToJsonString()));
            }
            return inputs;
        }
        CaseResult Resolve(Dictionary<string, CheckedInput> inputs) => registry.Dispatch(
            new("mixed-native", "LP-03", inputs.Values.Select(i => i.Identity).ToArray(), inputs));
        foreach (var (license, branch) in new[] { ("MIT", "dependencies-policy-satisfied"),
            ("GPL-3.0-only", "incompatible-dependency-license"), ("NOASSERTION", "license-evidence-unresolved"),
            ("SEE LICENSE IN LICENSE", "license-evidence-unresolved") })
        {
            // These deliberately forged-but-self-consistent bytes must not imply publisher authenticity.
            var result = Resolve(Packet(license));
            Check(result.BranchId == branch, license + ": " + result.BranchId);
            Check((result.Finding ?? result.MissingFact)!.Contains(Lp03DependencyLicensesResolver.NpmTrust,
                StringComparison.Ordinal), "Canonical trust qualification for " + branch);
        }
        var missing = Resolve(Packet(archive: false));
        Check(missing.BranchId == "dependency-bytes-missing" &&
            missing.MissingFact!.Contains(Lp03DependencyLicensesResolver.NpmTrust, StringComparison.Ordinal), "Missing archive qualification");
        var conflict = Packet();
        Replace(conflict, "dependency-001", Tarball("BSD-3-Clause"));
        Check(Resolve(conflict).BranchId == "binding-conflict", "Caller hash mismatch");
        conflict = Packet();
        var wrongIdentity = Tarball(json: "{\"name\":\"@scope/other\",\"version\":\"1.0.0\",\"license\":\"MIT\"}");
        Replace(conflict, "dependency-001", wrongIdentity);
        var selfConsistent = JsonNode.Parse(conflict["npm-archives"].Content.Span)!;
        selfConsistent["archives"]![0]!["sha256"] = Catalog.Digest(wrongIdentity);
        Replace(conflict, "npm-archives", Encoding.UTF8.GetBytes(selfConsistent.ToJsonString()));
        Check(Resolve(conflict).BranchId == "binding-conflict", "Self-consistent hash cannot substitute another exact npm identity");
        conflict = Packet();
        Replace(conflict, "dependency-002", Tarball());
        Check(Resolve(conflict).BranchId == "binding-conflict", "Extra member role");
        conflict = Packet();
        var manifestConflict = JsonNode.Parse(conflict["npm-archives"].Content.Span)!;
        manifestConflict["root_sha256"] = new string('0', 64);
        Replace(conflict, "npm-archives", Encoding.UTF8.GetBytes(manifestConflict.ToJsonString()));
        Check(Resolve(conflict).BranchId == "binding-conflict", "Wrong manifest root binding");
        foreach (var schema in new[] { "1.5", "999999999999999999999", "\"1\"", "null" })
        {
            conflict = Packet();
            var manifest = Encoding.UTF8.GetString(conflict["npm-archives"].Content.Span)
                .Replace("\"schema_version\":1", "\"schema_version\":" + schema, StringComparison.Ordinal);
            Replace(conflict, "npm-archives", Encoding.UTF8.GetBytes(manifest));
            Check(Resolve(conflict).BranchId == "binding-conflict", "Malformed npm manifest schema " + schema);
        }
        conflict = Packet();
        var rawSbom = JsonNode.Parse(conflict["sbom"].Content.Span)!;
        rawSbom["packages"]![0]!["externalRefs"]![0]!["referenceLocator"] =
            "pkg:swid/Example/spdx.org/example.controls@1.0.0?tag_id=11111111-1111-1111-1111-111111111111";
        SetSbom(conflict, rawSbom);
        Check(Resolve(conflict).BranchId == "binding-conflict", "Product-as-root cannot coexist with NuGet root");
        foreach (var count in new[] { 65, 128, 129 })
        {
            var inputs = new Dictionary<string, CheckedInput>(baseline, StringComparer.Ordinal);
            var sbom = JsonNode.Parse(inputs["sbom"].Content.Span)!;
            for (var index = 1; index < count; index++)
            {
                var node = sbom["packages"]![2]!.DeepClone();
                node["name"] = "d" + index;
                node["SPDXID"] = "SPDXRef-D" + index;
                node["externalRefs"]![0]!["referenceLocator"] = "pkg:nuget/d" + index + "@1.0.0";
                sbom["packages"]!.AsArray().Add(node);
                sbom["relationships"]!.AsArray().Add(Edge("SPDXRef-Product", "SPDXRef-D" + index));
            }
            SetSbom(inputs, sbom);
            var admission = Spdx22InventoryAdmission.Admit(inputs);
            Check(count <= 128 ? admission.Inventory?.Dependencies.Length == count :
                admission.Code == "closure-unresolved", "Bounded inventory " + count);
        }
        var good = Tarball();
        Check(NpmPackageEvidence.ChecksumsMatch(good, [new("SHA256", Catalog.Digest(good))]) &&
            !NpmPackageEvidence.ChecksumsMatch(good, [new("SHA256", new string('0', 64))]), "Exact archive checksum enforcement");
        Check(NpmPackageEvidence.Read(good) is { Id: "@scope/foo", License: "MIT" }, "Exact tarball package.json");
        Check(NpmPackageEvidence.Read(Tarball(root: "foo")) is { Id: "@scope/foo", License: "MIT" },
            "Single named root binds scoped package basename");
        Check(NpmPackageEvidence.Read(Tarball(root: "foo",
            json: "{\"name\":\"foo\",\"version\":\"1.0.0\",\"license\":\"MIT\"}")) is { Id: "foo" },
            "Single named root binds unscoped package");
        Check(NpmPackageEvidence.Read(Tarball(root: "trusted-types",
            rootDirectory: true,
            json: "{\"name\":\"@types/trusted-types\",\"version\":\"2.0.7\",\"license\":\"MIT\"}")) is
            { Id: "@types/trusted-types", Version: "2.0.7", License: "MIT" }, "DefinitelyTyped named-root layout");
        Check(NpmPackageEvidence.Read(Tarball(root: "other")) is null, "Named root disagrees with manifest identity");
        Check(NpmPackageEvidence.Read(Tarball(root: "foo", extra: "package/README")) is null, "Mixed archive roots");
        Check(NpmPackageEvidence.Read(Tarball(root: "foo", extra: "FOO/README")) is null, "Case-aliased archive roots");
        Check(NpmPackageEvidence.Read(Tarball(root: "foo", extra: "foo/PACKAGE.json")) is null, "Named-root case collision");
        Check(NpmPackageEvidence.Read(Tarball(root: "foo", extra: "foo/../escape")) is null, "Named-root traversal");
        var timestamps = Unzip(Tarball(root: "foo"));
        Encoding.ASCII.GetBytes("14526766570\0").CopyTo(timestamps, 476);
        Encoding.ASCII.GetBytes("14526766570\0").CopyTo(timestamps, 488);
        FixChecksum(timestamps);
        Check(NpmPackageEvidence.Read(Gzip(timestamps)) is { Id: "@scope/foo" },
            "node-tar short-prefix octal timestamps");
        timestamps[476] = (byte)'x';
        FixChecksum(timestamps);
        Check(NpmPackageEvidence.Read(Gzip(timestamps)) is null, "Malformed node-tar timestamp");
        Check(NpmPackageEvidence.Read(Tarball(extra:
            "package/" + new string('a', 80) + "/" + new string('b', 55) + "/tail")) is not null,
            "Full USTAR prefix is not confused with timestamps");
        Check(NpmPackageEvidence.Read((byte[])[.. good, 42]) is null, "Trailing gzip data");
        Check(NpmPackageEvidence.Read((byte[])[.. good, .. good]) is null, "Concatenated gzip members");
        Check(NpmPackageEvidence.Read(good.AsMemory(0, good.Length - 1)) is null, "Truncated gzip footer");
        var badSize = good.ToArray();
        badSize[^4] ^= 1;
        Check(NpmPackageEvidence.Read(badSize) is null, "Gzip ISIZE");
        var flags = good.ToArray();
        flags[3] = 8;
        Check(NpmPackageEvidence.Read(flags) is null, "Unsupported gzip filename header");
        var badCrc = good.ToArray();
        badCrc[^8] ^= 1;
        Check(NpmPackageEvidence.Read(badCrc) is null, "Gzip CRC");
        foreach (var name in new[] { "package/../package.json", "package\\package.json",
            "/package/package.json", "package/CON.txt", "package/a:stream", "package/a$/x" })
            Check(NpmPackageEvidence.Read(Tarball(extra: name)) is null, "TAR path " + name);
        foreach (var type in new[] { TarEntryType.SymbolicLink, TarEntryType.HardLink,
            TarEntryType.CharacterDevice, TarEntryType.BlockDevice, TarEntryType.Fifo })
            Check(NpmPackageEvidence.Read(Tarball(type: type)) is null, "TAR type " + type);
        Check(NpmPackageEvidence.Read(Tarball(pax: true)) is null, "PAX path override/metadata refuses before effective-name parsing");
        Check(NpmPackageEvidence.Read(Tarball(extraEntries: 4096)) is null, "TAR 4097-entry cap");
        var tar = Unzip(good);
        tar[25] = 65;
        tar[26] = 0;
        FixChecksum(tar);
        Check(NpmPackageEvidence.Read(Gzip(tar)) is null, "Raw-header/effective name disagreement after NUL");
        tar = Unzip(good);
        tar[156] = (byte)'S';
        FixChecksum(tar);
        Check(NpmPackageEvidence.Read(Gzip(tar)) is null, "GNU sparse representation");
        Check(NpmPackageEvidence.Read(Tarball(extra: "package/PACKAGE.json")) is null, "Case collision");
        Check(NpmPackageEvidence.Read(new byte[NpmPackageEvidence.ArchiveLimit + 1]) is null, "Compressed cap");
        Check(NpmPackageEvidence.Read(Gzip(new byte[NpmPackageEvidence.ExpandedLimit + 1])) is null, "Expanded metadata/padding cap");
        Check(NpmPackageEvidence.Read(Tarball(json: "{\"name\":\"@scope/foo\",\"version\":\"1.0.0\",\"license\":\"MIT\",\"license\":\"GPL-3.0-only\"}")) is null,
            "Duplicate license property");
        Check(NpmPackageEvidence.Read(Tarball(json: new string('x', 1024 * 1024 + 1))) is null, "package.json size cap");
        Check(NpmPackageEvidence.Read(Tarball(json: "{\"name\":\"@scope/foo\",\"version\":\"1.0.0\",\"nested\":" +
            new string('[', 17) + "0" + new string(']', 17) + "}")) is null, "package.json depth cap");
        Retained(registry, Check);
        RetainedNpm(Check);
        Console.WriteLine($"Mixed inventory/source/npm: {checks} safety, trust, bounds and retained checks passed.");
    }

    private static void RetainedNpm(Action<bool, string> check)
    {
        var path = Environment.GetEnvironmentVariable("READINESS_NPM_ARCHIVES_MANIFEST");
        if (path is null) { Console.WriteLine("Real npm checks: skipped; explicit archive manifest not supplied."); return; }
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(path));
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        foreach (var member in manifest.RootElement.GetProperty("archives").EnumerateArray())
        {
            var relative = member.GetProperty("path").GetString()!;
            check(Lp02PublicSourceResolver.SafePath(relative), "Retained npm checked path");
            var bytes = File.ReadAllBytes(Path.Combine(directory, relative));
            check(Catalog.Digest(bytes) == member.GetProperty("sha256").GetString(), "Retained npm digest");
            check(NpmPackageIdentity.TryParsePurl(member.GetProperty("purl").GetString()!,
                out var name, out var version), "Retained npm exact identity");
            var package = NpmPackageEvidence.Read(bytes);
            check(package is not null && package.Id == name && package.Version == version &&
                package.License is { Length: > 0 }, "Real npm archive and own declaration: " + name);
            Console.WriteLine($"Real npm {name}@{version}: {package!.License}");
        }
    }

    private static void Retained(Registry registry, Action<bool, string> check)
    {
        var f = Environment.GetEnvironmentVariable("READINESS_RETAINED_EVIDENCE_ROOT");
        if (f is null) { Console.WriteLine("Mixed retained IG/SF checks: skipped; explicit evidence root not supplied."); return; }
        foreach (var vendor in new[] { "infragistics", "syncfusion" })
        {
            var inputs = Path.Combine(f, vendor == "infragistics" ?
                @"infragistics-network-v1\report\eleven-0001\inputs" : @"nuspec-namespace-fix-v1\inputs");
            var values = new Dictionary<string, CheckedInput>(StringComparer.Ordinal);
            foreach (var (role, file) in new[] { ("package", "package.nupkg"), ("sbom", "release.spdx.json"), ("assessment", "lp-03-scope.json") })
                Replace(values, role, File.ReadAllBytes(Path.Combine(inputs, file)));
            var admission = Spdx22InventoryAdmission.Admit(values);
            check(admission.Inventory is not null, vendor + " real SBOM admission: " + admission.Detail);
            var inventory = admission.Inventory!;
            check(inventory.Dependencies.Length == (vendor == "infragistics" ? 65 : 57), vendor + " complete member count");
            if (vendor == "syncfusion")
            {
                using var old = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(inputs, "sbom-admission.json")));
                var before = old.RootElement.GetProperty("admission").GetProperty("inventory").GetProperty("dependencies")
                    .EnumerateArray().Select((c, i) => new { role = $"dependency-{i:D3}", id = c.GetProperty("id").GetString(),
                        version = c.GetProperty("version").GetString() }).ToArray();
                var after = inventory.Dependencies.Select((c, i) => new { role = $"dependency-{i:D3}", id = (string?)c.Id,
                    version = (string?)c.Version }).ToArray();
                check(JsonSerializer.SerializeToUtf8Bytes(before).SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(after)),
                    "SF all 57 role assignments byte-identical to retained pre-change admission");
                foreach (var role in new[] { "policy", "corpus" })
                    Replace(values, role, File.ReadAllBytes(Path.Combine(inputs, role + ".json")));
                for (var index = 0; index < 57; index++)
                    Replace(values, $"dependency-{index:D3}", File.ReadAllBytes(Path.Combine(inputs, $"dependency-{index:D3}.nupkg")));
                var result = registry.Dispatch(new("retained-sf-complete", "LP-03",
                    values.Values.Select(v => v.Identity).ToArray(), values));
                check(result.BranchId == "dependencies-policy-satisfied", "SF exact 57-member licensing stays verified");
            }
            else check(inventory.Dependencies.Count(c => c.Ecosystem == "npm") == 12, "IG exactly 12 npm members");
        }
        var source = File.ReadAllBytes(Path.Combine(f, @"infragistics-network-v1\downloads\source-9995aef.zip"));
        check(Lp02PublicSourceResolver.TryArchive(source, out var files,
            "9995aef5bf771beb94551e4ebabfe6d90c7a4488", sourceMembers: true), "Real IG source profile");
        check(files.Keys.Count(p => p.Contains('$')) == 18, "All 18 literal dollar paths retained");
        check(!Lp02PublicSourceResolver.TryArchive(source, out _), "Default package profile remains strict");
    }

    private static JsonObject Edge(string from, string to) => new()
        { ["relationshipType"] = "DEPENDS_ON", ["spdxElementId"] = from, ["relatedSpdxElement"] = to };
    private static void SetSbom(Dictionary<string, CheckedInput> values, JsonNode sbom)
    {
        Replace(values, "sbom", Encoding.UTF8.GetBytes(sbom.ToJsonString()));
        var scope = JsonNode.Parse(values["assessment"].Content.Span)!;
        scope["sbom_sha256"] = values["sbom"].Identity.Sha256;
        scope["designation"]!["sbom_sha256"] = values["sbom"].Identity.Sha256;
        Replace(values, "assessment", Encoding.UTF8.GetBytes(scope.ToJsonString()));
    }
    private static void Replace(Dictionary<string, CheckedInput> values, string role, byte[] bytes)
    {
        var pin = new PinnedInput(role, role + ".bin", Catalog.Digest(bytes));
        values[role] = new(pin, bytes);
    }
    private static byte[] Tarball(string license = "MIT", string? extra = null,
        TarEntryType? type = null, bool pax = false, string? json = null, int extraEntries = 0,
        string root = "package", bool rootDirectory = false)
    {
        using var buffer = new MemoryStream();
        using (var writer = new TarWriter(buffer, leaveOpen: true))
        {
            if (rootDirectory) writer.WriteEntry(new UstarTarEntry(TarEntryType.Directory, root + "/"));
            var bytes = Encoding.UTF8.GetBytes(json ?? JsonSerializer.Serialize(new { name = "@scope/foo", version = "1.0.0", license }));
            TarEntry entry = pax ? new PaxTarEntry(TarEntryType.RegularFile, root + "/package.json",
                [new KeyValuePair<string, string>("path", "../escape")]) :
                new UstarTarEntry(TarEntryType.RegularFile, root + "/package.json");
            entry.DataStream = new MemoryStream(bytes);
            writer.WriteEntry(entry);
            for (var index = 0; index < extraEntries; index++)
                writer.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, root + "/entry-" + index));
            if (extra is not null || type is not null)
            {
                var item = new UstarTarEntry(type ?? TarEntryType.RegularFile, extra ?? "package/unsafe");
                if (type is TarEntryType.SymbolicLink or TarEntryType.HardLink) item.LinkName = "../escape";
                if (type is null) item.DataStream = new MemoryStream([1]);
                writer.WriteEntry(item);
            }
        }
        return Gzip(buffer.ToArray());
    }
    private static byte[] Gzip(byte[] bytes)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, true)) gzip.Write(bytes);
        return output.ToArray();
    }
    private static byte[] Unzip(byte[] bytes)
    {
        using var input = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
        using var output = new MemoryStream();
        input.CopyTo(output);
        return output.ToArray();
    }
    private static void FixChecksum(byte[] tar)
    {
        Array.Fill(tar, (byte)' ', 148, 8);
        var value = Convert.ToString(tar.Take(512).Sum(b => (int)b), 8)!.PadLeft(6, '0') + "\0 ";
        Encoding.ASCII.GetBytes(value).CopyTo(tar, 148);
    }
}
