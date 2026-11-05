using System.IO.Compression;
using System.Text;
using System.Text.Json;
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
            Check(result.ResolverVersion == "2.1.0" && result.Decision == "escalated" &&
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
        CheckProvenance(registry, Check);
        Replay.Run(Path.Combine(fixture, "cases.json"), registry);
        Console.WriteLine($"LP-04 D-lite: {assertions} assertions and frozen v2 result replays passed; v1 deciding tests retired.");
    }

    private static void CheckProvenance(Registry registry, Action<bool, string> check)
    {
        const string commit = "1111111111111111111111111111111111111111";
        const string repoUrl = "https://github.com/example/controls";
        var nuspec = Encoding.UTF8.GetBytes(
            "<package><metadata><id>Example.Controls</id><version>1.0.0</version>" +
            $"<repository type=\"git\" url=\"{repoUrl}\" commit=\"{commit}\"/></metadata></package>");
        var licenseBytes = Encoding.UTF8.GetBytes(
            "The MIT License (MIT)\n\nCopyright (c) 2026 Example Corp.\n\nAll rights reserved.\n\n" +
            CanonicalLicenseBody.Clauses("MIT"));
        var scriptBytes =
            "// Copyright (c) 2026 Example Corp.\n// SPDX-License-Identifier: MIT\n/*! component helper section */\nexport function greet() { return 'hi'; }\n"u8.ToArray();
        var bundleCssBytes = "/* _content/Example.Controls/Components/Button.razor.rz.scp.css */\ndiv[b-1234567890] { color: red; }\n"u8.ToArray();

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

        static (byte[] Bundle, byte[] Attestation) MakeProvenance(byte[] pkg, byte[] rel, byte[] src)
        {
            var relSha = Catalog.Digest(rel);
            var stmtJson = JsonSerializer.Serialize(new
            {
                _type = "https://in-toto.io/Statement/v1",
                subject = new[] { new { name = "Example.Controls.1.0.0.nupkg", digest = new { sha256 = relSha } } },
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
                    }
                }
            });
            var bnd = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
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
                    payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(stmtJson)),
                    signatures = new[] { new { sig = "dGVzdA==" } }
                }
            }));
            using var stmtDoc = JsonDocument.Parse(stmtJson);
            var att = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                schema_version = 1,
                producer = "lp10-gh-attestation-verify/1.0.0",
                package_sha256 = Catalog.Digest(pkg),
                release_package_sha256 = relSha,
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
                                    runnerEnvironment = "github-hosted",
                                    sourceRepositoryVisibilityAtSigning = "public",
                                    sourceRepositoryURI = repoUrl,
                                    sourceRepositoryDigest = commit,
                                    buildConfigDigest = commit,
                                    buildConfigURI = $"{repoUrl}/.github/workflows/release.yml@refs/heads/main"
                                }
                            },
                            statement = stmtDoc.RootElement
                        }
                    }
                }
            }));
            return (bnd, ProvenanceTestAdmission.Sign(att, src, repoUrl, commit));
        }

        CaseResult Dispatch5(byte[] pkg, byte[] rel, byte[] bnd, byte[] att, byte[] src)
        {
            var roles = new (string Role, string Path, byte[] Bytes)[]
            {
                ("package", "package.nupkg", pkg),
                ("release-package", "release.nupkg", rel),
                ("provenance-bundle", "bundle.json", bnd),
                ("provenance-attestation", "attestation.json", att),
                ("source-archive", "source.zip", src)
            };
            var pins = roles.Select(r => new PinnedInput(r.Role, r.Path, Catalog.Digest(r.Bytes))).ToList();
            var checkedMap = roles.ToDictionary(
                r => r.Role,
                r => new CheckedInput(new PinnedInput(r.Role, r.Path, Catalog.Digest(r.Bytes)), r.Bytes),
                StringComparer.Ordinal);
            return registry.Dispatch(new ResolverCase("lp04-prov", "LP-04", pins, checkedMap));
        }

        // Mode B positive: zero runtime npm dependencies, exact first-party source matches (with duplicate in tests/vendor/), Razor scoped CSS bundle headers, and dev-only lockfile
        var modeBPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", scriptBytes),
            ("staticwebassets/Example.Controls.abc123.bundle.scp.css", bundleCssBytes));
        var modeBSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/LICENSE.txt", licenseBytes),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/tests/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/tests/vendor/app.js", scriptBytes),
            ($"controls-{commit}/src/Components/Button.razor.css", "div { color: red; }\n"u8.ToArray()),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\",\"scripts\":{\"lint\":\"eslint .\"},\"devDependencies\":{\"eslint\":\"^9.0.0\"}}"u8.ToArray()),
            ($"controls-{commit}/package-lock.json",
                "{\"name\":\"controls\",\"lockfileVersion\":3,\"packages\":{\"\":{\"devDependencies\":{\"eslint\":\"^9.0.0\"}},\"node_modules/eslint\":{\"version\":\"9.0.0\",\"dev\":true}}}"u8.ToArray()));
        var (modeBBnd, modeBAtt) = MakeProvenance(modeBPkg, modeBPkg, modeBSrc);
        var modeBRes = Dispatch5(modeBPkg, modeBPkg, modeBBnd, modeBAtt, modeBSrc);
        check(modeBRes.BranchId == "provenance-notices-verified" && modeBRes.Decision == "deterministic" &&
            modeBRes.BundledWebAssets!.Assets.Count == 2,
            "LP-04 Mode B exact first-party source + Razor CSS bundle + dev-only lockfile verified");

        // Mode B positive: compound banner with 'All rights reserved. | Licensed under MIT'
        var compoundValidJs = "/*! Copyright (c) 2026 Example Corp. All rights reserved. | Licensed under MIT */\nexport const x = 1;\n"u8.ToArray();
        var compoundValidPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", compoundValidJs));
        var compoundValidSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", compoundValidJs));
        var (compoundValidBnd, compoundValidAtt) = MakeProvenance(compoundValidPkg, compoundValidPkg, compoundValidSrc);
        var compoundValidRes = Dispatch5(compoundValidPkg, compoundValidPkg, compoundValidBnd, compoundValidAtt, compoundValidSrc);
        check(compoundValidRes.BranchId == "provenance-notices-verified" && compoundValidRes.Decision == "deterministic",
            "LP-04 Mode B accepts compound first-party 'All rights reserved. | Licensed under MIT' banner");

        // Mode B positive & negative: .NET Foundation 'Licensed to the .NET Foundation under one or more agreements.' header
        var dotnetHeaderJs =
            "// Licensed to the .NET Foundation under one or more agreements.\n// The .NET Foundation licenses this file to you under the MIT license.\nexport const x = 1;\n"u8.ToArray();
        var dotnetLicenseBytes = Encoding.UTF8.GetBytes(
            "The MIT License (MIT)\nCopyright (c) .NET Foundation and Contributors\n\n" + CanonicalLicenseBody.Clauses("MIT"));
        var dotnetValidPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", dotnetLicenseBytes), ("staticwebassets/scripts/app.js", dotnetHeaderJs));
        var dotnetValidSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/LICENSE.txt", dotnetLicenseBytes),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", dotnetHeaderJs));
        var (dotnetValidBnd, dotnetValidAtt) = MakeProvenance(dotnetValidPkg, dotnetValidPkg, dotnetValidSrc);
        var dotnetValidRes = Dispatch5(dotnetValidPkg, dotnetValidPkg, dotnetValidBnd, dotnetValidAtt, dotnetValidSrc);
        check(dotnetValidRes.BranchId == "provenance-notices-verified" && dotnetValidRes.Decision == "deterministic",
            "LP-04 Mode B accepts standard .NET Foundation header when root LICENSE attributes .NET Foundation");

        var theAuthorsLicenseBytes = Encoding.UTF8.GetBytes(
            "The MIT License (MIT)\nCopyright (c) 2026 The Authors\n\n" + CanonicalLicenseBody.Clauses("MIT"));
        var dotnetMismatchPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", theAuthorsLicenseBytes), ("staticwebassets/scripts/app.js", dotnetHeaderJs));
        var dotnetMismatchSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/LICENSE.txt", theAuthorsLicenseBytes),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", dotnetHeaderJs));
        var (dotnetMismatchBnd, dotnetMismatchAtt) = MakeProvenance(dotnetMismatchPkg, dotnetMismatchPkg, dotnetMismatchSrc);
        var dotnetMismatchRes = Dispatch5(dotnetMismatchPkg, dotnetMismatchPkg, dotnetMismatchBnd, dotnetMismatchAtt, dotnetMismatchSrc);
        check(dotnetMismatchRes.BranchId == "provenance-notices-unverified" &&
            dotnetMismatchRes.MissingFact!.Contains("inline copyright holder '.NET Foundation' is not covered", StringComparison.Ordinal),
            "LP-04 Mode B extracts '.NET Foundation' (not 'the') and rejects when root LICENSE only attributes 'The Authors'");

        // Mode B negative: truncated root LICENSE.txt
        var truncatedLicensePkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", "MIT License\nCopyright (c) 2026 Example Corp.\nPermission is hereby granted..."u8.ToArray()),
            ("staticwebassets/scripts/app.js", scriptBytes));
        var (truncLicBnd, truncLicAtt) = MakeProvenance(truncatedLicensePkg, truncatedLicensePkg, modeBSrc);
        var truncLicRes = Dispatch5(truncatedLicensePkg, truncatedLicensePkg, truncLicBnd, truncLicAtt, modeBSrc);
        check(truncLicRes.BranchId == "provenance-notices-unverified" &&
            truncLicRes.MissingFact!.Contains("lacks a complete canonical license body", StringComparison.Ordinal),
            "LP-04 Mode B rejects truncated root LICENSE.txt");

        // Mode B negative: foreign @license or yearless (c) banner in shipped JS
        var foreignJs = "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\nexport const x = 1;\n"u8.ToArray();
        var badModeBPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", foreignJs));
        var badModeBSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/.github/THIRD-PARTY-NOTICES.md", "# Notices\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", foreignJs));
        var (badModeBBnd, badModeBAtt) = MakeProvenance(badModeBPkg, badModeBPkg, badModeBSrc);
        var badModeBRes = Dispatch5(badModeBPkg, badModeBPkg, badModeBBnd, badModeBAtt, badModeBSrc);
        check(badModeBRes.BranchId == "provenance-notices-unverified" && badModeBRes.Decision == "escalated" &&
            badModeBRes.MissingFact!.Contains("inline copyright holder 'OpenJS Foundation and other contributors'", StringComparison.Ordinal),
            "LP-04 Mode B rejects foreign yearless (c) banner");

        // Mode B negative: 'Copyright (c) 2026 by ThirdParty Inc. All rights reserved.' banner
        var byHolderJs = "/* Copyright (c) 2026 by ThirdParty Inc. All rights reserved. */\nexport const x = 1;\n"u8.ToArray();
        var byHolderPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", byHolderJs));
        var byHolderSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", byHolderJs));
        var (byHolderBnd, byHolderAtt) = MakeProvenance(byHolderPkg, byHolderPkg, byHolderSrc);
        var byHolderRes = Dispatch5(byHolderPkg, byHolderPkg, byHolderBnd, byHolderAtt, byHolderSrc);
        check(byHolderRes.BranchId == "provenance-notices-unverified" &&
            byHolderRes.MissingFact!.Contains("inline copyright holder 'ThirdParty Inc'", StringComparison.Ordinal),
            "LP-04 Mode B rejects 'Copyright (c) YYYY by Holder All rights reserved' foreign notice");

        // Mode B negative: first-party copyright holder with mismatched inline license (BSD-3-Clause vs MIT root LICENSE)
        var mismatchLicJs = "/* Copyright (c) 2026 Example Corp. | Licensed under BSD-3-Clause */\nexport const x = 1;\n"u8.ToArray();
        var mismatchLicPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", mismatchLicJs));
        var mismatchLicSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", mismatchLicJs));
        var (mismatchLicBnd, mismatchLicAtt) = MakeProvenance(mismatchLicPkg, mismatchLicPkg, mismatchLicSrc);
        var mismatchLicRes = Dispatch5(mismatchLicPkg, mismatchLicPkg, mismatchLicBnd, mismatchLicAtt, mismatchLicSrc);
        check(mismatchLicRes.BranchId == "provenance-notices-unverified" &&
            mismatchLicRes.MissingFact!.Contains("declares license 'BSD-3-Clause' which does not match root license 'MIT'", StringComparison.Ordinal),
            "LP-04 Mode B rejects first-party holder comment declaring non-matching license");

        // Mode B negative: compound SPDX-License-Identifier with uncovered license token or unattributed normalize.css banner in second comment block
        var compoundSpdxJs = "// SPDX-License-Identifier: MIT OR GPL-3.0-only\nexport const x = 1;\n"u8.ToArray();
        var compoundSpdxPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", compoundSpdxJs));
        var compoundSpdxSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", compoundSpdxJs));
        var (compoundSpdxBnd, compoundSpdxAtt) = MakeProvenance(compoundSpdxPkg, compoundSpdxPkg, compoundSpdxSrc);
        var compoundSpdxRes = Dispatch5(compoundSpdxPkg, compoundSpdxPkg, compoundSpdxBnd, compoundSpdxAtt, compoundSpdxSrc);
        check(compoundSpdxRes.BranchId == "provenance-notices-unverified" &&
            compoundSpdxRes.MissingFact!.Contains("inline SPDX identifier 'GPL-3.0-only' does not match root license 'MIT'", StringComparison.Ordinal),
            "LP-04 Mode B rejects compound SPDX-License-Identifier with uncovered token");

        var unattributedBannerJs =
            "// Copyright (c) 2026 Example Corp.\n/*! normalize.css v8.0.1 | MIT License | github.com/necolas/normalize.css */\nexport const x = 1;\n"u8.ToArray();
        var unattributedBannerPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", unattributedBannerJs));
        var unattributedBannerSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", unattributedBannerJs));
        var (unattributedBnd, unattributedAtt) = MakeProvenance(unattributedBannerPkg, unattributedBannerPkg, unattributedBannerSrc);
        var unattributedRes = Dispatch5(unattributedBannerPkg, unattributedBannerPkg, unattributedBnd, unattributedAtt, unattributedBannerSrc);
        check(unattributedRes.BranchId == "provenance-notices-unverified" &&
            unattributedRes.MissingFact!.Contains("lacks an explicit first-party copyright holder in the same comment block", StringComparison.Ordinal),
            "LP-04 Mode B rejects normalize.css MIT License banner without copyright holder in that comment block");

        var unattributedSpdxJs =
            "// Copyright (c) 2026 Example Corp.\n/*! SPDX-License-Identifier: MIT */\nexport const x = 1;\n"u8.ToArray();
        var unattributedSpdxPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", unattributedSpdxJs));
        var unattributedSpdxSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", unattributedSpdxJs));
        var (unattributedSpdxBnd, unattributedSpdxAtt) = MakeProvenance(unattributedSpdxPkg, unattributedSpdxPkg, unattributedSpdxSrc);
        var unattributedSpdxRes = Dispatch5(unattributedSpdxPkg, unattributedSpdxPkg, unattributedSpdxBnd, unattributedSpdxAtt, unattributedSpdxSrc);
        check(unattributedSpdxRes.BranchId == "provenance-notices-unverified" &&
            unattributedSpdxRes.MissingFact!.Contains("lacks an explicit first-party copyright holder in the same comment block", StringComparison.Ordinal),
            "LP-04 Mode B rejects standalone SPDX-License-Identifier comment block without copyright holder in that block");

        var apacheProseJs =
            "/*\n * Copyright (c) 2026 Example Corp.\n * Licensed under the Apache License, Version 2.0.\n */\nexport const x = 1;\n"u8.ToArray();
        var apacheProsePkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", apacheProseJs));
        var apacheProseSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", apacheProseJs));
        var (apacheProseBnd, apacheProseAtt) = MakeProvenance(apacheProsePkg, apacheProsePkg, apacheProseSrc);
        var apacheProseRes = Dispatch5(apacheProsePkg, apacheProsePkg, apacheProseBnd, apacheProseAtt, apacheProseSrc);
        check(apacheProseRes.BranchId == "provenance-notices-unverified" &&
            apacheProseRes.MissingFact!.Contains("declares license 'Apache-2.0' which does not match root license 'MIT'", StringComparison.Ordinal),
            "LP-04 Mode B rejects 'Apache License, Version 2.0' prose comment under MIT root license");

        var mplBoilerplateJs =
            "/* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.\n * If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/. */\nexport const x = 1;\n"u8.ToArray();
        var mplBoilerplatePkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", mplBoilerplateJs));
        var mplBoilerplateSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", mplBoilerplateJs));
        var (mplBnd, mplAtt) = MakeProvenance(mplBoilerplatePkg, mplBoilerplatePkg, mplBoilerplateSrc);
        var mplRes = Dispatch5(mplBoilerplatePkg, mplBoilerplatePkg, mplBnd, mplAtt, mplBoilerplateSrc);
        check(mplRes.BranchId == "provenance-notices-unverified" &&
            mplRes.MissingFact!.Contains("declares license 'MPL-2.0' which does not match root license 'MIT'", StringComparison.Ordinal),
            "LP-04 Mode B rejects MPL-2.0 boilerplate comment under MIT root license");

        var unknownLicJs =
            "/* Copyright (c) 2026 Example Corp. | Licensed under the CustomFoo License */\nexport const x = 1;\n"u8.ToArray();
        var unknownLicPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", unknownLicJs));
        var unknownLicSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", unknownLicJs));
        var (unknownLicBnd, unknownLicAtt) = MakeProvenance(unknownLicPkg, unknownLicPkg, unknownLicSrc);
        var unknownLicRes = Dispatch5(unknownLicPkg, unknownLicPkg, unknownLicBnd, unknownLicAtt, unknownLicSrc);
        check(unknownLicRes.BranchId == "provenance-notices-unverified" &&
            unknownLicRes.MissingFact!.Contains("inline comment contains an unrecognized license declaration", StringComparison.Ordinal),
            "LP-04 Mode B rejects unrecognized 'Licensed under ...' comment");

        var mixedSpdxAndUnknownJs =
            "/*\n * Copyright (c) 2026 Example Corp.\n * SPDX-License-Identifier: MIT\n * Licensed under the CustomFoo License\n */\nexport const x = 1;\n"u8.ToArray();
        var mixedSpdxAndUnknownPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", mixedSpdxAndUnknownJs));
        var mixedSpdxAndUnknownSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", mixedSpdxAndUnknownJs));
        var (mixedSpdxBnd, mixedSpdxAtt) = MakeProvenance(mixedSpdxAndUnknownPkg, mixedSpdxAndUnknownPkg, mixedSpdxAndUnknownSrc);
        var mixedSpdxRes = Dispatch5(mixedSpdxAndUnknownPkg, mixedSpdxAndUnknownPkg, mixedSpdxBnd, mixedSpdxAtt, mixedSpdxAndUnknownSrc);
        check(mixedSpdxRes.BranchId == "provenance-notices-unverified" &&
            mixedSpdxRes.MissingFact!.Contains("inline comment contains an unrecognized license declaration", StringComparison.Ordinal),
            "LP-04 Mode B rejects unrecognized 'Licensed under ...' even when SPDX-License-Identifier is in the same block");

        var pipeSecondUnknownJs =
            "/* Copyright (c) 2026 Example Corp. | Licensed under MIT | Released under the CustomFoo License */\nexport const x = 1;\n"u8.ToArray();
        var pipeSecondUnknownPkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", pipeSecondUnknownJs));
        var pipeSecondUnknownSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", pipeSecondUnknownJs));
        var (pipeSecondBnd, pipeSecondAtt) = MakeProvenance(pipeSecondUnknownPkg, pipeSecondUnknownPkg, pipeSecondUnknownSrc);
        var pipeSecondRes = Dispatch5(pipeSecondUnknownPkg, pipeSecondUnknownPkg, pipeSecondBnd, pipeSecondAtt, pipeSecondUnknownSrc);
        check(pipeSecondRes.BranchId == "provenance-notices-unverified" &&
            pipeSecondRes.MissingFact!.Contains("inline comment contains an unrecognized license declaration", StringComparison.Ordinal),
            "LP-04 Mode B rejects pipe-separated second unrecognized license clause on same line");

        var pipeAtLicenseUnknownJs =
            "/* Copyright (c) 2026 Example Corp. | @license MIT | @license CustomFoo */\nexport const x = 1;\n"u8.ToArray();
        var pipeAtLicensePkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", pipeAtLicenseUnknownJs));
        var pipeAtLicenseSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", pipeAtLicenseUnknownJs));
        var (pipeAtBnd, pipeAtAtt) = MakeProvenance(pipeAtLicensePkg, pipeAtLicensePkg, pipeAtLicenseSrc);
        var pipeAtRes = Dispatch5(pipeAtLicensePkg, pipeAtLicensePkg, pipeAtBnd, pipeAtAtt, pipeAtLicenseSrc);
        check(pipeAtRes.BranchId == "provenance-notices-unverified" &&
            pipeAtRes.MissingFact!.Contains("inline comment contains an unrecognized license declaration", StringComparison.Ordinal),
            "LP-04 Mode B rejects pipe-separated second unrecognized @license clause on same line");

        var wrappedAtLicenseUnknownJs =
            "/*\n * Copyright (c) 2026 Example Corp.\n * Licensed under MIT\n * @license\n * CustomFoo\n */\nexport const x = 1;\n"u8.ToArray();
        var wrappedAtLicensePkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", wrappedAtLicenseUnknownJs));
        var wrappedAtLicenseSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", wrappedAtLicenseUnknownJs));
        var (wrappedAtBnd, wrappedAtAtt) = MakeProvenance(wrappedAtLicensePkg, wrappedAtLicensePkg, wrappedAtLicenseSrc);
        var wrappedAtRes = Dispatch5(wrappedAtLicensePkg, wrappedAtLicensePkg, wrappedAtBnd, wrappedAtAtt, wrappedAtLicenseSrc);
        check(wrappedAtRes.BranchId == "provenance-notices-unverified" &&
            wrappedAtRes.MissingFact!.Contains("inline comment contains an unrecognized license declaration", StringComparison.Ordinal),
            "LP-04 Mode B rejects wrapped @license declaration even when another recognized clause is present");

        var commonsClauseJs =
            "/* Copyright (c) 2026 Example Corp. | Licensed under the MIT License with Commons Clause */\nexport const x = 1;\n"u8.ToArray();
        var commonsClausePkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", commonsClauseJs));
        var commonsClauseSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", commonsClauseJs));
        var (commonsBnd, commonsAtt) = MakeProvenance(commonsClausePkg, commonsClausePkg, commonsClauseSrc);
        var commonsRes = Dispatch5(commonsClausePkg, commonsClausePkg, commonsBnd, commonsAtt, commonsClauseSrc);
        check(commonsRes.BranchId == "provenance-notices-unverified" &&
            commonsRes.MissingFact!.Contains("inline comment contains an unrecognized license declaration", StringComparison.Ordinal),
            "LP-04 Mode B rejects 'Licensed under the MIT License with Commons Clause'");

        var jsCookieBannerJs =
            "// Copyright (c) 2026 Example Corp.\n/*! js-cookie v3.0.5 | MIT */\nexport const x = 1;\n"u8.ToArray();
        var jsCookiePkg = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE.txt", licenseBytes), ("staticwebassets/scripts/app.js", jsCookieBannerJs));
        var jsCookieSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", jsCookieBannerJs));
        var (jsCookieBnd, jsCookieAtt) = MakeProvenance(jsCookiePkg, jsCookiePkg, jsCookieSrc);
        var jsCookieRes = Dispatch5(jsCookiePkg, jsCookiePkg, jsCookieBnd, jsCookieAtt, jsCookieSrc);
        check(jsCookieRes.BranchId == "provenance-notices-unverified" &&
            jsCookieRes.MissingFact!.Contains("lacks an explicit first-party copyright holder in the same comment block", StringComparison.Ordinal),
            "LP-04 Mode B rejects '/*! js-cookie v3.0.5 | MIT */' banner without copyright holder in that block");

        // Mode B negative: shipping package.json with bundler script or devDependencies bundler, or source map with third-party/remote/scheme sourceRoot/sources
        var bundlerScriptSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/src/Components/Button.razor.css", "div { color: red; }\n"u8.ToArray()),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\",\"scripts\":{\"build\":\"esbuild src/app.js --bundle --outfile=src/wwwroot/scripts/app.js\"}}"u8.ToArray()));
        var (bundlerScriptBnd, bundlerScriptAtt) = MakeProvenance(modeBPkg, modeBPkg, bundlerScriptSrc);
        var bundlerScriptRes = Dispatch5(modeBPkg, modeBPkg, bundlerScriptBnd, bundlerScriptAtt, bundlerScriptSrc);
        check(bundlerScriptRes.BranchId == "provenance-notices-unverified" &&
            bundlerScriptRes.MissingFact!.Contains("declares a bundler script while declaring zero runtime dependencies", StringComparison.Ordinal),
            "LP-04 Mode B rejects shipping package.json with bundler script");

        var bundlerDevDepSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/src/Components/Button.razor.css", "div { color: red; }\n"u8.ToArray()),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\",\"devDependencies\":{\"vite\":\"^5.0.0\"}}"u8.ToArray()));
        var (bundlerDevDepBnd, bundlerDevDepAtt) = MakeProvenance(modeBPkg, modeBPkg, bundlerDevDepSrc);
        var bundlerDevDepRes = Dispatch5(modeBPkg, modeBPkg, bundlerDevDepBnd, bundlerDevDepAtt, bundlerDevDepSrc);
        check(bundlerDevDepRes.BranchId == "provenance-notices-unverified" &&
            bundlerDevDepRes.MissingFact!.Contains("declares a bundler script while declaring zero runtime dependencies", StringComparison.Ordinal),
            "LP-04 Mode B rejects shipping package.json with bundler in devDependencies");

        var badMapBytes = "{\"version\":3,\"sourceRoot\":\"../node_modules/\",\"sources\":[\"pkg/index.js\"]}\n"u8.ToArray();
        var badMapPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", scriptBytes),
            ("staticwebassets/scripts/app.js.map", badMapBytes));
        var badMapSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/src/wwwroot/scripts/app.js.map", badMapBytes));
        var (badMapBnd, badMapAtt) = MakeProvenance(badMapPkg, badMapPkg, badMapSrc);
        var badMapRes = Dispatch5(badMapPkg, badMapPkg, badMapBnd, badMapAtt, badMapSrc);
        check(badMapRes.BranchId == "provenance-notices-unverified" &&
            badMapRes.MissingFact!.Contains("source map staticwebassets/scripts/app.js.map references third-party or invalid sources", StringComparison.Ordinal),
            "LP-04 Mode B rejects source map with node_modules in sourceRoot");

        var remoteMapBytes = "{\"version\":3,\"sourceRoot\":\"https://unpkg.com/normalize.css@8.0.1/\",\"sources\":[\"normalize.css\"]}\n"u8.ToArray();
        var remoteMapPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", scriptBytes),
            ("staticwebassets/scripts/app.js.map", remoteMapBytes));
        var remoteMapSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/src/wwwroot/scripts/app.js.map", remoteMapBytes));
        var (remoteMapBnd, remoteMapAtt) = MakeProvenance(remoteMapPkg, remoteMapPkg, remoteMapSrc);
        var remoteMapRes = Dispatch5(remoteMapPkg, remoteMapPkg, remoteMapBnd, remoteMapAtt, remoteMapSrc);
        check(remoteMapRes.BranchId == "provenance-notices-unverified" &&
            remoteMapRes.MissingFact!.Contains("source map staticwebassets/scripts/app.js.map references third-party or invalid sources", StringComparison.Ordinal),
            "LP-04 Mode B rejects source map with external URL in sourceRoot");

        var dataUriMapBytes = "{\"version\":3,\"sources\":[\"data:text/javascript,export%20const%20x%3D1\"]}\n"u8.ToArray();
        var dataUriMapPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", scriptBytes),
            ("staticwebassets/scripts/app.js.map", dataUriMapBytes));
        var dataUriMapSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/src/wwwroot/scripts/app.js.map", dataUriMapBytes));
        var (dataUriMapBnd, dataUriMapAtt) = MakeProvenance(dataUriMapPkg, dataUriMapPkg, dataUriMapSrc);
        var dataUriMapRes = Dispatch5(dataUriMapPkg, dataUriMapPkg, dataUriMapBnd, dataUriMapAtt, dataUriMapSrc);
        check(dataUriMapRes.BranchId == "provenance-notices-unverified" &&
            dataUriMapRes.MissingFact!.Contains("source map staticwebassets/scripts/app.js.map references third-party or invalid sources", StringComparison.Ordinal),
            "LP-04 Mode B rejects source map with data: URI in sources");

        var driveLetterMapBytes = "{\"version\":3,\"sources\":[\"C:\\\\src\\\\app.js\"]}\n"u8.ToArray();
        var driveLetterMapPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", scriptBytes),
            ("staticwebassets/scripts/app.js.map", driveLetterMapBytes));
        var driveLetterMapSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/src/wwwroot/scripts/app.js.map", driveLetterMapBytes));
        var (driveMapBnd, driveMapAtt) = MakeProvenance(driveLetterMapPkg, driveLetterMapPkg, driveLetterMapSrc);
        var driveMapRes = Dispatch5(driveLetterMapPkg, driveLetterMapPkg, driveMapBnd, driveMapAtt, driveLetterMapSrc);
        check(driveMapRes.BranchId == "provenance-notices-unverified" &&
            driveMapRes.MissingFact!.Contains("source map staticwebassets/scripts/app.js.map references third-party or invalid sources", StringComparison.Ordinal),
            "LP-04 Mode B rejects source map with Windows drive-letter path in sources");

        // Mode B negative: unrelated CSS smuggled in .bundle.scp.css or referencing missing .razor.css
        var smuggledCssPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", scriptBytes),
            ("staticwebassets/Example.Controls.abc123.bundle.scp.css", "body[b-1234567890] { display: flex; }\n"u8.ToArray()));
        var (smuggledBnd, smuggledAtt) = MakeProvenance(smuggledCssPkg, smuggledCssPkg, modeBSrc);
        var smuggledRes = Dispatch5(smuggledCssPkg, smuggledCssPkg, smuggledBnd, smuggledAtt, modeBSrc);
        check(smuggledRes.BranchId == "provenance-notices-unverified" && smuggledRes.Decision == "escalated" &&
            smuggledRes.MissingFact!.Contains("scoped CSS bundle", StringComparison.Ordinal),
            "LP-04 Mode B rejects .bundle.scp.css that does not match source .razor.css");

        var missingRazorCssPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE.txt", licenseBytes),
            ("staticwebassets/scripts/app.js", scriptBytes),
            ("staticwebassets/Example.Controls.abc123.bundle.scp.css",
                "/* _content/Example.Controls/Components/Missing.razor.rz.scp.css */\ndiv[b-1234567890] { color: red; }\n"u8.ToArray()));
        var (missingRazorBnd, missingRazorAtt) = MakeProvenance(missingRazorCssPkg, missingRazorCssPkg, modeBSrc);
        var missingRazorRes = Dispatch5(missingRazorCssPkg, missingRazorCssPkg, missingRazorBnd, missingRazorAtt, modeBSrc);
        check(missingRazorRes.BranchId == "provenance-notices-unverified" &&
            missingRazorRes.MissingFact!.Contains("scoped CSS bundle", StringComparison.Ordinal),
            "LP-04 Mode B rejects .bundle.scp.css section whose .razor.css is absent from source");

        // Mode B negative: source match inside vendor directory or non-dev lockfile entry
        var vendorSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/vendor/app.js", scriptBytes),
            ($"controls-{commit}/src/Components/Button.razor.css", "div { color: red; }\n"u8.ToArray()));
        var (vendorBnd, vendorAtt) = MakeProvenance(modeBPkg, modeBPkg, vendorSrc);
        var vendorRes = Dispatch5(modeBPkg, modeBPkg, vendorBnd, vendorAtt, vendorSrc);
        check(vendorRes.BranchId == "provenance-notices-unverified" &&
            vendorRes.MissingFact!.Contains("matches a vendor or third-party source path", StringComparison.Ordinal),
            "LP-04 Mode B rejects source match under vendor directory");

        var nonDevLockSrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/wwwroot/scripts/app.js", scriptBytes),
            ($"controls-{commit}/src/Components/Button.razor.css", "div { color: red; }\n"u8.ToArray()),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\",\"devDependencies\":{\"eslint\":\"^9.0.0\"}}"u8.ToArray()),
            ($"controls-{commit}/package-lock.json",
                "{\"name\":\"controls\",\"lockfileVersion\":3,\"packages\":{\"\":{},\"node_modules/forgotten-lib\":{\"version\":\"1.0.0\"}}}"u8.ToArray()));
        var (nonDevLockBnd, nonDevLockAtt) = MakeProvenance(modeBPkg, modeBPkg, nonDevLockSrc);
        var nonDevLockRes = Dispatch5(modeBPkg, modeBPkg, nonDevLockBnd, nonDevLockAtt, nonDevLockSrc);
        check(nonDevLockRes.BranchId == "provenance-notices-unverified" &&
            nonDevLockRes.MissingFact!.Contains("shipping lockfile", StringComparison.Ordinal),
            "LP-04 Mode B rejects package-lock.json entry without dev: true");

        // Mode A positive: bundled npm web build with full THIRD-PARTY-LICENSES.md covering lock closure
        var tplBytes = Encoding.UTF8.GetBytes(
            "# Licenses\n\n## lit-html - 3.3.3 (BSD-3-Clause)\n\n" +
            "Copyright 2017 Google LLC\n" +
            "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n" +
            "1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.\n" +
            "2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.\n" +
            "3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.\n" +
            "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. " +
            "IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) " +
            "HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n");
        var bundledScript = "/** @license Copyright 2017 Google LLC */\nexport const y = 2;\n"u8.ToArray();
        var sourceScript = "export const y: number = 2;\n"u8.ToArray();
        byte[] Manifest(byte[] script) => JsonSerializer.SerializeToUtf8Bytes(new
        {
            schema_version = 1,
            assets = new[] { new { path = "staticwebassets/bundle.js", sha256 = Catalog.Digest(script),
                inputs = new[] { new { path = "src/index.ts", sha256 = Catalog.Digest(sourceScript) } },
                components = new[] { new { name = "lit-html", version = "3.3.3" } } } }
        });
        var modeAPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", tplBytes),
            ("staticwebassets/bundle.js", bundledScript),
            ("readiness-bundler-manifest.json", Manifest(bundledScript)));
        var modeASrc = BuildZip(
            ($"controls-{commit}/.github/workflows/release.yml", "name: release\n"u8.ToArray()),
            ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
            ($"controls-{commit}/src/index.ts", sourceScript),
            ($"controls-{commit}/src/output.js", bundledScript),
            ($"controls-{commit}/package.json", "{\"name\":\"controls\",\"dependencies\":{\"lit-html\":\"^3.3.3\"}}"u8.ToArray()),
            ($"controls-{commit}/package-lock.json",
                "{\"name\":\"controls\",\"lockfileVersion\":3,\"packages\":{\"\":{\"dependencies\":{\"lit-html\":\"^3.3.3\"}},\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\"}}}"u8.ToArray()));
        var (modeABnd, modeAAtt) = MakeProvenance(modeAPkg, modeAPkg, modeASrc);
        var modeARes = Dispatch5(modeAPkg, modeAPkg, modeABnd, modeAAtt, modeASrc);
        check(modeARes.BranchId == "provenance-notices-verified" && modeARes.Decision == "deterministic" &&
            modeARes.BundledWebAssets!.Assets.Count == 1,
            "LP-04 Mode A bundled npm notice coverage verified");

        using var jsonSourceZip = new ZipArchive(new MemoryStream(modeASrc), ZipArchiveMode.Read);
        var sourceEntries = jsonSourceZip.Entries.Select(entry =>
        {
            using var stream = entry.Open();
            using var memory = new MemoryStream();
            stream.CopyTo(memory);
            return (Name: entry.FullName, Bytes: memory.ToArray());
        }).ToArray();
        var mitNoticePackage = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", Encoding.UTF8.GetBytes("# Licenses\n\n## lit-html - 3.3.3 (MIT)\n\n" +
                "Copyright 2017 Google LLC\n" + CanonicalLicenseBody.Clauses("MIT"))),
            ("staticwebassets/bundle.js", bundledScript),
            ("readiness-bundler-manifest.json", Manifest(bundledScript)));
        var licenseOutcomes = new List<(bool Success, string Label)>();
        foreach (var (label, license, positive) in new (string, string?, bool)[]
        {
            ("matching MIT", "\"MIT\"", true),
            ("GPL-3.0-only versus MIT notice", "\"GPL-3.0-only\"", false),
            ("BSD-3-Clause versus MIT notice", "\"BSD-3-Clause\"", false),
            ("missing", null, false), ("null", "null", false), ("boolean", "true", false),
            ("number", "1", false), ("object", "{}", false), ("array", "[]", false),
            ("OR expression", "\"MIT OR Apache-2.0\"", false),
            ("AND expression", "\"MIT AND Apache-2.0\"", false),
            ("WITH expression", "\"MIT WITH Classpath-exception-2.0\"", false),
            ("parenthesized", "\"(MIT)\"", false), ("case mismatch", "\"mit\"", false),
            ("padded", "\" MIT\"", false), ("empty", "\"\"", false),
            ("duplicate conflict", "\"GPL-3.0-only\",\"license\":\"MIT\"", false),
            ("same-component matching", "\"MIT\"", true),
            ("same-component conflicting", "\"GPL-3.0-only\"", false)
        })
        {
            const string rootLockEntry = "\"\":{\"dependencies\":{\"lit-html\":\"^3.3.3\"}},";
            var text = "{\"packages\":{" + rootLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\"" +
                (license is null ? "" : ",\"license\":" + license) + "}}}";
            if (label.StartsWith("same-component ", StringComparison.Ordinal))
                text = "{\"packages\":{" + rootLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"MIT\"," +
                    "\"dependencies\":{\"lit-html\":\"3.3.3\"}},\"node_modules/lit-html/node_modules/lit-html\":" +
                    "{\"version\":\"3.3.3\",\"license\":" + license + "}}}";
            var source = BuildZip(sourceEntries.Select(entry => (entry.Name,
                entry.Name.EndsWith("/package-lock.json", StringComparison.Ordinal) ?
                    Encoding.UTF8.GetBytes(text) : entry.Bytes)).ToArray());
            var (bundle, attestation) = MakeProvenance(mitNoticePackage, mitNoticePackage, source);
            var result = Dispatch5(mitNoticePackage, mitNoticePackage, bundle, attestation, source);
            var expected = positive ? "provenance-notices-verified" : "provenance-notices-unverified";
            licenseOutcomes.Add((result.BranchId == expected, label + ": " + result.BranchId));
            Console.WriteLine("Notice/lock license " + label + ": " + result.BranchId);
        }
        var licenseFailures = string.Join("; ", licenseOutcomes.Where(value => !value.Success).Select(value => value.Label));
        foreach (var outcome in licenseOutcomes)
            check(outcome.Success, "Notice/lock license regressions: " + licenseFailures);

        var jsonOutcomes = new List<(bool Success, string Label)>();
        void JsonCase(string label, string member, string text, bool positive = false, byte[]? package = null)
        {
            package ??= modeAPkg;
            var source = BuildZip(sourceEntries.Select(entry => (entry.Name,
                entry.Name.EndsWith("/" + member, StringComparison.Ordinal) ? Encoding.UTF8.GetBytes(text) : entry.Bytes)).ToArray());
            try
            {
                var (bundle, attestation) = MakeProvenance(package, package, source);
                var result = Dispatch5(package, package, bundle, attestation, source);
                var expected = positive ? "provenance-notices-verified" : "provenance-notices-unverified";
                jsonOutcomes.Add((result.BranchId == expected, label + ": " + result.BranchId));
                Console.WriteLine("Delta LP-04 JSON " + label + ": " + result.BranchId);
            }
            catch (Exception ex)
            {
                jsonOutcomes.Add((false, label + ": threw " + ex.GetType().Name));
            }
        }
        const string dependencyJson = "\"dependencies\":{\"lit-html\":\"^3.3.3\"}";
        const string mitEntry = "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"MIT\"}";
        const string gplEntry = "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"GPL-3.0-only\"}";
        foreach (var (label, first, second) in new[]
        {
            ("GPL then MIT", gplEntry, mitEntry), ("MIT then GPL", mitEntry, gplEntry)
        })
        {
            JsonCase("duplicate lock package path " + label, "package-lock.json",
                "{\"packages\":{" + first + "," + second + "}}", package: mitNoticePackage);
            JsonCase("duplicate lock packages property " + label, "package-lock.json",
                "{\"packages\":{" + first + "},\"packages\":{" + second + "}}", package: mitNoticePackage);
        }
        JsonCase("duplicate package dependency key", "package.json",
            "{\"dependencies\":{\"lit-html\":\"^3.3.3\",\"lit-html\":\"^3.3.3\"}}");
        JsonCase("duplicate package dependencies property", "package.json",
            "{" + dependencyJson + "," + dependencyJson + "}");
        JsonCase("duplicate package ignored key", "package.json",
            "{" + dependencyJson + ",\"description\":1,\"description\":2}");
        JsonCase("duplicate package escaped key", "package.json",
            "{" + dependencyJson + ",\"description\":1,\"\\u0064escription\":2}");
        JsonCase("duplicate package nested array key", "package.json",
            "{" + dependencyJson + ",\"ignored\":[{\"same\":1,\"same\":2}]}");
        const string rootDepsLockEntry = "\"\":{\"dependencies\":{\"lit-html\":\"^3.3.3\"}},";
        const string bsdEntry = rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\"}";
        JsonCase("duplicate lock ignored key", "package-lock.json",
            "{\"packages\":{" + bsdEntry + "},\"ignored\":1,\"ignored\":2}");
        JsonCase("duplicate lock nested array key", "package-lock.json",
            "{\"packages\":{" + bsdEntry + "},\"ignored\":[{\"same\":1,\"same\":2}]}");
        JsonCase("duplicate lock unvisited key", "package-lock.json",
            "{\"packages\":{" + bsdEntry + ",\"node_modules/dev-only\":{\"version\":\"1\",\"version\":\"2\"}}}");
        JsonCase("duplicate lock version", "package-lock.json",
            "{\"packages\":{" + rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\"}}}");
        JsonCase("duplicate lock identical license", "package-lock.json",
            "{\"packages\":{" + rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",\"license\":\"BSD-3-Clause\"}}}");
        JsonCase("ordinal package distinct keys", "package.json",
            "{" + dependencyJson + ",\"ignored\":{\"same\":1,\"Same\":2}}", positive: true);
        JsonCase("package independent object keys", "package.json",
            "{" + dependencyJson + ",\"ignored\":[{\"same\":1},{\"same\":2}]}", positive: true);
        JsonCase("lock independent and ordinal keys", "package-lock.json",
            "{\"packages\":{" + bsdEntry + "},\"ignored\":[{\"same\":1,\"Same\":2},{\"same\":3}]}", positive: true);
        JsonCase("package surrogate dependency name", "package.json", "{\"dependencies\":{\"\\uD800\":\"1.0.0\"}}");
        JsonCase("package surrogate dependency value", "package.json", "{\"dependencies\":{\"lit-html\":\"\\uD800\"}}");
        JsonCase("lock surrogate version", "package-lock.json",
            "{\"packages\":{" + rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"\\uD800\",\"license\":\"BSD-3-Clause\"}}}");
        JsonCase("lock surrogate dependency name", "package-lock.json",
            "{\"packages\":{" + rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",\"dependencies\":{\"\\uD800\":\"1.0.0\"}}}}");
        foreach (var field in new[] { "bundleDependencies", "bundledDependencies", "optionalDependencies" })
        {
            foreach (var value in new[] { "true", "null", "0", "\"\"", "{}", "[]", "false" })
            {
                var supported = field == "optionalDependencies" ? value == "{}" : value is "[]" or "false";
                JsonCase("package " + field + "=" + value, "package.json",
                    "{" + dependencyJson + ",\"" + field + "\":" + value + "}", supported);
            }
            JsonCase("package nonempty " + field, "package.json", "{" + dependencyJson + ",\"" + field +
                "\":" + (field == "optionalDependencies" ? "{\"other\":\"1.0.0\"}" : "[\"lit-html\"]") + "}");
        }
        foreach (var field in new[] { "dependencies", "optionalDependencies" })
        {
            foreach (var value in new[] { "true", "false", "null", "0", "\"\"", "[]", "{}" })
                JsonCase("lock " + field + "=" + value, "package-lock.json",
                    "{\"packages\":{" + rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",\"" + field + "\":" + value + "}}}",
                    positive: value == "{}");
            JsonCase("lock root malformed " + field, "package-lock.json",
                "{\"packages\":{\"\":{\"" + field + "\":false},\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\"}}}");
            JsonCase("lock unvisited malformed " + field, "package-lock.json",
                "{\"packages\":{" + rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\"},\"node_modules/dev-only\":{\"version\":\"1.0.0\",\"" +
                field + "\":[]}}}");
        }
        JsonCase("lock surrogate dependency value", "package-lock.json",
            "{\"packages\":{" + rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",\"dependencies\":{\"other\":\"\\uD800\"}}}}");
        foreach (var (escaped, valid) in new[]
        {
            ("\\uD800", false), ("\\uDC00", false), ("\\uD800x", false),
            ("\\uDC00\\uD800", false), ("\\uD83D\\uDE00", true)
        })
        {
            JsonCase("package ignored string " + escaped, "package.json",
                "{" + dependencyJson + ",\"description\":\"" + escaped + "\"}", valid);
            JsonCase("package ignored name " + escaped, "package.json",
                "{" + dependencyJson + ",\"" + escaped + "\":null}", valid);
            JsonCase("package nested array string " + escaped, "package.json",
                "{" + dependencyJson + ",\"ignored\":[null,false,42,{\"value\":\"" + escaped + "\"}]}", valid);
            JsonCase("package nested array name " + escaped, "package.json",
                "{" + dependencyJson + ",\"ignored\":[{\"" + escaped + "\":null}]}", valid);
            const string runtimePackage = rootDepsLockEntry + "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\"}";
            JsonCase("lock unvisited version " + escaped, "package-lock.json",
                "{\"packages\":{" + runtimePackage + ",\"node_modules/dev-only\":{\"version\":\"" + escaped + "\"}}}", valid);
            JsonCase("lock ignored string " + escaped, "package-lock.json",
                "{\"packages\":{" + runtimePackage + "},\"ignored\":\"" + escaped + "\"}", valid);
            JsonCase("lock ignored name " + escaped, "package-lock.json",
                "{\"packages\":{" + runtimePackage + "},\"" + escaped + "\":null}", valid);
            JsonCase("lock nested array string " + escaped, "package-lock.json",
                "{\"packages\":{" + runtimePackage + "},\"ignored\":[{\"value\":\"" + escaped + "\"}]}", valid);
            JsonCase("lock unvisited name " + escaped, "package-lock.json",
                "{\"packages\":{" + runtimePackage + ",\"node_modules/dev-only\":{\"version\":\"1.0.0\",\"" + escaped + "\":null}}}", valid);
        }
        var jsonFailures = string.Join("; ", jsonOutcomes.Where(value => !value.Success).Select(value => value.Label));
        foreach (var outcome in jsonOutcomes)
            check(outcome.Success, "Delta JSON regressions: " + jsonFailures);

        var unmappedPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec), ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", tplBytes), ("staticwebassets/bundle.js", bundledScript));
        var (unmappedBnd, unmappedAtt) = MakeProvenance(unmappedPkg, unmappedPkg, modeASrc);
        check(Dispatch5(unmappedPkg, unmappedPkg, unmappedBnd, unmappedAtt, modeASrc).BranchId ==
            "provenance-notices-unverified", "B8 Mode A complete dependency notices without a per-asset map must not verify");

        foreach (var id in new[] { "MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "0BSD" })
        {
            var clauses = CanonicalLicenseBody.Clauses(id)!;
            var full = id == "Apache-2.0" ? clauses : "Copyright 2026 Example\n" + clauses;
            check(CanonicalLicenseBody.Matches(id, full), "B3 complete canonical " + id);
            check(!CanonicalLicenseBody.Matches(id, full[..^40]), "B3 truncated canonical " + id);
            check(!CanonicalLicenseBody.Matches(id == "MIT" ? "BSD-2-Clause" : "MIT", full),
                "B3 mismatched declared SPDX " + id);
            if (id != "Apache-2.0")
            {
                var earlyGrant = string.Join(" ", clauses.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Take(5));
                check(!CanonicalLicenseBody.Matches(id, "Copyright 2026 Example\n" + earlyGrant +
                    "\nAdditional terms hidden before the real grant.\n" + clauses),
                    "Re-review an early grant phrase must not hide a noncanonical preamble for " + id);
            }
        }
        var incompleteBsd = "Copyright 2017 Google LLC\n" + CanonicalLicenseBody.BsdGrant.Split("1.")[0] +
            "\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.";
        check(!CanonicalLicenseBody.Matches("BSD-3-Clause", incompleteBsd),
            "B3 old greater-than-180-character BSD fixture without canonical conditions must fail closed");

        var hiddenPreambleTpl = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(tplBytes).Replace(
            "Copyright 2017 Google LLC\n", "Copyright 2017 Google LLC\nRedistribution and use in source\n" +
            "Additional terms hidden before the real grant.\n", StringComparison.Ordinal));
        var hiddenPreamblePackage = BuildZip(("Example.Controls.nuspec", nuspec), ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", hiddenPreambleTpl), ("staticwebassets/bundle.js", bundledScript),
            ("readiness-bundler-manifest.json", Manifest(bundledScript)));
        var (hiddenPreambleBundle, hiddenPreambleAttestation) =
            MakeProvenance(hiddenPreamblePackage, hiddenPreamblePackage, modeASrc);
        check(Dispatch5(hiddenPreamblePackage, hiddenPreamblePackage, hiddenPreambleBundle,
            hiddenPreambleAttestation, modeASrc).BranchId == "provenance-notices-unverified",
            "Re-review Mode A must reject an early grant phrase hiding noncanonical license terms");

        using var sourceZip = new ZipArchive(new MemoryStream(modeASrc), ZipArchiveMode.Read);
        var ssrSource = BuildZip(sourceZip.Entries.Select(e =>
        {
            using var stream = e.Open();
            using var memory = new MemoryStream();
            stream.CopyTo(memory);
            var bytes = memory.ToArray();
            if (e.FullName.EndsWith("package-lock.json", StringComparison.Ordinal))
                bytes = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace(
                    "\"version\":\"3.3.3\"", "\"version\":\"3.3.3\",\"dependencies\":{\"@lit-labs/ssr-dom-shim\":\"1.0.0\"}") .Replace(
                    "\"node_modules/lit-html\":", "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.0.0\",\"license\":\"MIT\"},\"node_modules/lit-html\":"));
            return (e.FullName, bytes);
        }).ToArray());
        var (ssrBnd, ssrAtt) = MakeProvenance(modeAPkg, modeAPkg, ssrSource);
        check(Dispatch5(modeAPkg, modeAPkg, ssrBnd, ssrAtt, ssrSource).BranchId == "provenance-notices-unverified",
            "B4 SSR dependency without a notice cannot be excluded by absent package-name text");

        // Mode A negative: truncated one-liner license stub in THIRD-PARTY-LICENSES.md
        var stubTpl = "# Licenses\n\n## lit-html - 3.3.3 (BSD-3-Clause)\n\nCopyright 2017 Google LLC\nRedistribution and use...\n"u8.ToArray();
        var stubModeAPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", stubTpl),
            ("staticwebassets/bundle.js", bundledScript),
            ("readiness-bundler-manifest.json", Manifest(bundledScript)));
        var (stubModeABnd, stubModeAAtt) = MakeProvenance(stubModeAPkg, stubModeAPkg, modeASrc);
        var stubModeARes = Dispatch5(stubModeAPkg, stubModeAPkg, stubModeABnd, stubModeAAtt, modeASrc);
        check(stubModeARes.BranchId == "provenance-notices-unverified" && stubModeARes.Decision == "escalated",
            "LP-04 Mode A rejects truncated license stub in THIRD-PARTY-LICENSES.md");

        // Mode A negative: missing dependency entry in THIRD-PARTY-LICENSES.md
        var incompleteTpl = "# Licenses\n\n## other-pkg - 1.0.0 (MIT)\n\nCopyright 2026 Other\nPermission is hereby granted...\n"u8.ToArray();
        var badModeAPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", incompleteTpl),
            ("staticwebassets/bundle.js", bundledScript),
            ("readiness-bundler-manifest.json", Manifest(bundledScript)));
        var (badModeABnd, badModeAAtt) = MakeProvenance(badModeAPkg, badModeAPkg, modeASrc);
        var badModeARes = Dispatch5(badModeAPkg, badModeAPkg, badModeABnd, badModeAAtt, modeASrc);
        check(badModeARes.BranchId == "provenance-notices-unverified" && badModeARes.Decision == "escalated",
            "LP-04 Mode A rejects incomplete THIRD-PARTY-LICENSES.md");

        // Attested Vite build.license Mode A positive & negative boundary checks
        const string viteConfig =
            "import { defineConfig } from 'vite';\n" +
            "import { cpSync } from 'node:fs';\n" +
            "const outDir = 'wwwroot';\n" +
            "const entries = { index: 'assets/index.ts' };\n" +
            "cpSync('node_modules/lit-html/themes', `${outDir}/themes`);\n" +
            "export default defineConfig({\n" +
            "  build: {\n" +
            "    outDir,\n" +
            "    license: { fileName: 'THIRD-PARTY-LICENSES.md' },\n" +
            "    rolldownOptions: {\n" +
            "      input: entries,\n" +
            "      output: {\n" +
            "        entryFileNames: '[name].[hash].bundle.js',\n" +
            "        chunkFileNames: '[name].[hash].bundle.js',\n" +
            "        codeSplitting: { groups: [{ name: 'lit', test: /lit/ }] }\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "});\n";
        const string viteWorkflow =
            "name: release\njobs:\n  build:\n    runs-on: ubuntu-latest\n" +
            "    defaults:\n      run:\n        working-directory: ./src\n" +
            "    steps:\n      - run: npm ci\n      - run: npm run build\n      - run: dotnet pack\n";
        var viteCss = "/* theme css */\n.igx-button { color: red; }\n"u8.ToArray();
        var viteTplBytes = Encoding.UTF8.GetBytes(
            "# Licenses\n\nThe app bundles dependencies which contain the following licenses:\n\n" +
            Encoding.UTF8.GetString(tplBytes)["# Licenses\n\n".Length..]);
        var vitePkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", viteTplBytes),
            ("staticwebassets/index.a1b2c3d4.bundle.js", bundledScript),
            ("staticwebassets/themes/light/bootstrap.css", viteCss));
        var viteLockWithExcluded =
            "{\"name\":\"controls\",\"lockfileVersion\":3,\"packages\":{" +
            "\"\":{\"dependencies\":{\"lit-html\":\"^3.3.3\"}}," +
            "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",\"dependencies\":{\"@types/trusted-types\":\"^2.0.0\",\"@lit-labs/ssr-dom-shim\":\"^1.6.0\"}}," +
            "\"node_modules/@types/trusted-types\":{\"version\":\"2.0.7\",\"license\":\"MIT\"}," +
            "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"}}}";
        byte[] BuildViteSource(string lockJson, string configText = viteConfig, (string Name, byte[] Bytes)? extraEntry = null)
        {
            var entries = new List<(string, byte[])>
            {
                ($"controls-{commit}/.github/workflows/release.yml", Encoding.UTF8.GetBytes(viteWorkflow)),
                ($"controls-{commit}/src/Example.Controls.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Razor\"/>"u8.ToArray()),
                ($"controls-{commit}/src/assets/index.ts", sourceScript),
                ($"controls-{commit}/src/vite.config.ts", Encoding.UTF8.GetBytes(configText)),
                ($"controls-{commit}/src/tsconfig.json", "{\"compilerOptions\":{\"outDir\":\"wwwroot\"}}"u8.ToArray()),
                ($"controls-{commit}/src/package.json", "{\"name\":\"controls\",\"scripts\":{\"build\":\"vite build && tsc\"},\"dependencies\":{\"lit-html\":\"^3.3.3\"}}"u8.ToArray()),
                ($"controls-{commit}/src/package-lock.json", Encoding.UTF8.GetBytes(lockJson))
            };
            if (extraEntry is { } extra)
                entries.Add(extra);
            return BuildZip(entries.ToArray());
        }
        var viteSrcPos = BuildViteSource(viteLockWithExcluded);
        var (viteBndPos, viteAttPos) = MakeProvenance(vitePkg, vitePkg, viteSrcPos);
        var viteResPos = Dispatch5(vitePkg, vitePkg, viteBndPos, viteAttPos, viteSrcPos);
        check(viteResPos.BranchId == "provenance-notices-verified" && viteResPos.Decision == "deterministic" &&
            viteResPos.Finding!.Contains("@lit-labs/ssr-dom-shim@1.6.0, @types/trusted-types@2.0.7", StringComparison.Ordinal),
            $"LP-04 Vite build.license Mode A positive failed: {viteResPos.BranchId} ({viteResPos.MissingFact})");

        // Negative 1: extra notice section not in lockfile closure (noticeSections subset-of closure check)
        var extraSectionTpl = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(viteTplBytes) +
            "\n\n## unrelated-pkg - 1.0.0 (MIT)\n\nCopyright 2026 Other\n" +
            CanonicalLicenseBody.Clauses("MIT"));
        var extraSectionPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", extraSectionTpl),
            ("staticwebassets/index.a1b2c3d4.bundle.js", bundledScript),
            ("staticwebassets/themes/light/bootstrap.css", viteCss));
        var (extraSecBnd, extraSecAtt) = MakeProvenance(extraSectionPkg, extraSectionPkg, viteSrcPos);
        var extraSecRes = Dispatch5(extraSectionPkg, extraSectionPkg, extraSecBnd, extraSecAtt, viteSrcPos);
        check(extraSecRes.BranchId == "provenance-notices-unverified" &&
            extraSecRes.MissingFact!.Contains("unrelated-pkg@1.0.0", StringComparison.Ordinal),
            "LP-04 rejects notice sections not present in runtime closure");

        // Negative 2: excluded @types/* package with non-canonical / copyleft license (e.g. GPL-3.0-only, LicenseRef-Custom, lowercase mit)
        foreach (var badExcludedLicense in new[] { "GPL-3.0-only", "LicenseRef-Custom", "mit" })
        {
            var badLock = viteLockWithExcluded.Replace("\"version\":\"2.0.7\",\"license\":\"MIT\"",
                $"\"version\":\"2.0.7\",\"license\":\"{badExcludedLicense}\"", StringComparison.Ordinal);
            var badSrc = BuildViteSource(badLock);
            var (badBnd, badAtt) = MakeProvenance(vitePkg, vitePkg, badSrc);
            var badRes = Dispatch5(vitePkg, vitePkg, badBnd, badAtt, badSrc);
            check(badRes.BranchId == "provenance-notices-unverified" &&
                badRes.MissingFact!.Contains("@types/trusted-types@2.0.7", StringComparison.Ordinal),
                $"LP-04 rejects excluded @types package with {badExcludedLicense} license");
        }

        // Negative 3: @lit-labs/ssr-dom-shim with dependencies, main, exports, optionalDependencies, or peerDependencies in package-lock.json
        var ssrWithResolvableSubdepLock = viteLockWithExcluded.Replace(
            "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"}",
            "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\",\"dependencies\":{\"other\":\"1.0.0\"}}," +
            "\"node_modules/other\":{\"version\":\"1.0.0\",\"license\":\"MIT\"}",
            StringComparison.Ordinal);
        var ssrWithSubdepTpl = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(viteTplBytes) +
            "\n\n## other - 1.0.0 (MIT)\n\nCopyright 2026 Other\n" +
            CanonicalLicenseBody.Clauses("MIT"));
        var ssrWithSubdepPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", ssrWithSubdepTpl),
            ("staticwebassets/index.a1b2c3d4.bundle.js", bundledScript),
            ("staticwebassets/themes/light/bootstrap.css", viteCss));
        var ssrSubdepSrc = BuildViteSource(ssrWithResolvableSubdepLock);
        var (ssrSubdepBnd, ssrSubdepAtt) = MakeProvenance(ssrWithSubdepPkg, ssrWithSubdepPkg, ssrSubdepSrc);
        var ssrSubdepRes = Dispatch5(ssrWithSubdepPkg, ssrWithSubdepPkg, ssrSubdepBnd, ssrSubdepAtt, ssrSubdepSrc);
        check(ssrSubdepRes.BranchId == "provenance-notices-unverified" &&
            ssrSubdepRes.MissingFact!.Contains("@lit-labs/ssr-dom-shim@1.6.0", StringComparison.Ordinal),
            "LP-04 rejects @lit-labs/ssr-dom-shim when it declares sub-dependencies");

        foreach (var extraField in new[]
        {
            "\"main\":\"index.js\"",
            "\"exports\":{\".\":\"./index.js\"}",
            "\"optionalDependencies\":{}",
            "\"peerDependencies\":{}"
        })
        {
            var badSsrLock = viteLockWithExcluded.Replace(
                "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"}",
                "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"," + extraField + "}",
                StringComparison.Ordinal);
            var badSsrSrc = BuildViteSource(badSsrLock);
            var (badSsrBnd, badSsrAtt) = MakeProvenance(vitePkg, vitePkg, badSsrSrc);
            var badSsrRes = Dispatch5(vitePkg, vitePkg, badSsrBnd, badSsrAtt, badSsrSrc);
            check(badSsrRes.BranchId == "provenance-notices-unverified" &&
                badSsrRes.MissingFact!.Contains("@lit-labs/ssr-dom-shim@1.6.0", StringComparison.Ordinal),
                $"LP-04 rejects @lit-labs/ssr-dom-shim with {extraField}");
        }

        foreach (var malformedDepsField in new[]
        {
            "\"dependencies\":[]",
            "\"dependencies\":\"x\"",
            "\"dependencies\":null"
        })
        {
            var badSsrLock = viteLockWithExcluded.Replace(
                "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"}",
                "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"," + malformedDepsField + "}",
                StringComparison.Ordinal);
            var badSsrSrc = BuildViteSource(badSsrLock);
            var (badSsrBnd, badSsrAtt) = MakeProvenance(vitePkg, vitePkg, badSsrSrc);
            var badSsrRes = Dispatch5(vitePkg, vitePkg, badSsrBnd, badSsrAtt, badSsrSrc);
            check(badSsrRes.BranchId == "provenance-notices-unverified",
                $"LP-04 rejects @lit-labs/ssr-dom-shim with malformed {malformedDepsField}");
        }

        // Negative 4: unmapped CSS file outside declared cpSync destination
        var unmappedCssPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", viteTplBytes),
            ("staticwebassets/index.a1b2c3d4.bundle.js", bundledScript),
            ("staticwebassets/unmapped/other.css", viteCss));
        var (unmappedCssBnd, unmappedCssAtt) = MakeProvenance(unmappedCssPkg, unmappedCssPkg, viteSrcPos);
        check(Dispatch5(unmappedCssPkg, unmappedCssPkg, unmappedCssBnd, unmappedCssAtt, viteSrcPos).BranchId ==
            "provenance-notices-unverified", "LP-04 rejects CSS outside declared cpSync target directory");

        // Negative 5: THIRD-PARTY-LICENSES.md committed in source archive (by path or normalized text, including >512 KiB)
        var committedNoticeByPathOnlySrc = BuildViteSource(viteLockWithExcluded,
            extraEntry: ($"controls-{commit}/docs/THIRD-PARTY-LICENSES.md", "# Unrelated placeholder\n"u8.ToArray()));
        var (committedPathBnd, committedPathAtt) = MakeProvenance(vitePkg, vitePkg, committedNoticeByPathOnlySrc);
        check(Dispatch5(vitePkg, vitePkg, committedPathBnd, committedPathAtt, committedNoticeByPathOnlySrc).BranchId ==
            "provenance-notices-unverified", "LP-04 rejects nested static */THIRD-PARTY-LICENSES.md path in source archive");

        var largePadding = new string('x', 530 * 1024);
        var largeViteTplLf = Encoding.UTF8.GetString(viteTplBytes).Replace(
            "Copyright 2026 Google LLC",
            $"Copyright 2026 Google LLC ({largePadding})",
            StringComparison.Ordinal);
        var largeViteTplBytes = Encoding.UTF8.GetBytes(largeViteTplLf);
        var largeViteTplCrlfBytes = Encoding.UTF8.GetBytes(largeViteTplLf.Replace("\n", "\r\n", StringComparison.Ordinal));
        var largeVitePkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", largeViteTplBytes),
            ("staticwebassets/index.a1b2c3d4.bundle.js", bundledScript),
            ("staticwebassets/themes/light/bootstrap.css", viteCss));
        var committedLargeNoticeSrc = BuildViteSource(viteLockWithExcluded,
            extraEntry: ($"controls-{commit}/docs/STATIC-NOTICE-COPY.txt", largeViteTplCrlfBytes));
        var (committedBnd, committedAtt) = MakeProvenance(largeVitePkg, largeVitePkg, committedLargeNoticeSrc);
        check(Dispatch5(largeVitePkg, largeVitePkg, committedBnd, committedAtt, committedLargeNoticeSrc).BranchId ==
            "provenance-notices-unverified", "LP-04 rejects >512 KiB static notice file matching normalized text under a different filename");

        // Negative 6: Mode A inline prose @license / Released under / yearless (c) holder not covered by license or notices
        foreach (var (inlineLabel, inlineBanner) in new[]
        {
            ("uncovered @license GPL-3.0-only", "/*! @license GPL-3.0-only */\nexport const v = 1;\n"),
            ("uncovered Released under MPL-2.0", "/*! Released under the MPL-2.0 License */\nexport const v = 1;\n"),
            ("uncovered yearless (c) holder", "/*! (c) Uncovered Third Party Corp. */\nexport const v = 1;\n"),
            ("uncovered holder matching MIT template body word Software", "/*! Copyright (c) 2024 Software */\nexport const v = 1;\n"),
            ("uncovered holder starting with License", "/*! Copyright (c) 2026 LicenseTools Ltd. */\nexport const v = 1;\n"),
            ("uncovered holder starting with Owner", "/*! Copyright (c) 2026 OwnerSoft Inc. */\nexport const v = 1;\n"),
            ("uncovered holder starting with Notice", "/*! Copyright (c) 2026 Notice Labs LLC */\nexport const v = 1;\n"),
            ("uncovered holder starting with Holder", "/*! Copyright (c) 2026 Holder Corp. */\nexport const v = 1;\n"),
            ("uncovered untitled canonical ISC license body in comment",
                "/*\n * Permission to use, copy, modify, and/or distribute this software for any\n * purpose with or without fee is hereby granted, provided that the above\n * copyright notice and this permission notice appear in all copies.\n *\n * THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH\n * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY\n * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,\n * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM\n * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR\n * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR\n * PERFORMANCE OF THIS SOFTWARE.\n */\nexport const v = 1;\n"),
            ("unrecognized @license banner", "/*! @license Custom-Proprietary-1.0 */\nexport const v = 1;\n"),
            ("inline @license followed by Copyright line with no identified license",
                "/**\n * @license\n * Copyright (c) 2017 Google LLC\n */\nexport const v = 1;\n")
        })
        {
            var badInlineBytes = Encoding.UTF8.GetBytes(inlineBanner);
            var badInlinePkg = BuildZip(
                ("Example.Controls.nuspec", nuspec),
                ("LICENSE", licenseBytes),
                ("THIRD-PARTY-LICENSES.md", viteTplBytes),
                ("staticwebassets/index.a1b2c3d4.bundle.js", badInlineBytes),
                ("staticwebassets/themes/light/bootstrap.css", viteCss));
            var (badInlineBnd, badInlineAtt) = MakeProvenance(badInlinePkg, badInlinePkg, viteSrcPos);
            var badInlineRes = Dispatch5(badInlinePkg, badInlinePkg, badInlineBnd, badInlineAtt, viteSrcPos);
            check(badInlineRes.BranchId == "provenance-notices-unverified",
                $"LP-04 Mode A rejects {inlineLabel} (got {badInlineRes.BranchId})");
        }

        var yearlessLicBytes = Encoding.UTF8.GetBytes("MIT License\n\ncopyright Acme Corporation\n\n" + CanonicalLicenseBody.Mit);
        var yearlessInlineBytes = "/*! Copyright Acme Corporation | MIT License */\nexport const v = 1;\n"u8.ToArray();
        var yearlessPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", yearlessLicBytes),
            ("THIRD-PARTY-LICENSES.md", viteTplBytes),
            ("staticwebassets/index.a1b2c3d4.bundle.js", yearlessInlineBytes),
            ("staticwebassets/themes/light/bootstrap.css", viteCss));
        var (yearlessBnd, yearlessAtt) = MakeProvenance(yearlessPkg, yearlessPkg, viteSrcPos);
        check(Dispatch5(yearlessPkg, yearlessPkg, yearlessBnd, yearlessAtt, viteSrcPos).BranchId == "provenance-notices-verified",
            "LP-04 Mode A accepts yearless symbol-less 'copyright Acme Corporation' in root LICENSE");

        // Negative 6b: Non-optional transitive peerDependencies must be covered; uninstalled optional peerDependencies are allowed
        var viteLockOptionalPeerUninstalled = viteLockWithExcluded.Replace(
            "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",",
            "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",\"peerDependencies\":{\"dompurify\":\"^3.0.0\"},\"peerDependenciesMeta\":{\"dompurify\":{\"optional\":true}},",
            StringComparison.Ordinal);
        var optPeerSrc = BuildViteSource(viteLockOptionalPeerUninstalled);
        var (optPeerBnd, optPeerAtt) = MakeProvenance(vitePkg, vitePkg, optPeerSrc);
        check(Dispatch5(vitePkg, vitePkg, optPeerBnd, optPeerAtt, optPeerSrc).BranchId == "provenance-notices-verified",
            "LP-04 Mode A allows uninstalled optional transitive peerDependencies");

        var viteLockRequiredPeerUncovered = viteLockWithExcluded.Replace(
            "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"}",
            "\"node_modules/@lit-labs/ssr-dom-shim\":{\"version\":\"1.6.0\",\"license\":\"BSD-3-Clause\"},\"node_modules/uncovered-peer\":{\"version\":\"1.0.0\",\"license\":\"MIT\"}",
            StringComparison.Ordinal).Replace(
            "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",",
            "\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\",\"peerDependencies\":{\"uncovered-peer\":\"^1.0.0\"},",
            StringComparison.Ordinal);
        var reqPeerSrc = BuildViteSource(viteLockRequiredPeerUncovered);
        var (reqPeerBnd, reqPeerAtt) = MakeProvenance(vitePkg, vitePkg, reqPeerSrc);
        check(Dispatch5(vitePkg, vitePkg, reqPeerBnd, reqPeerAtt, reqPeerSrc).BranchId == "provenance-notices-unverified",
            "LP-04 Mode A rejects uncovered non-optional transitive peerDependencies");

        // Decoupled LP-04 bundler-generated notice positive: verifies THIRD-PARTY-LICENSES.md + package-lock.json + inline notices
        // for top-level bundled JS even when vite.config.ts uses a custom shape outside LP-10's TryResolveAttestedViteBuildPlan.
        var decoupledPkg = BuildZip(
            ("Example.Controls.nuspec", nuspec),
            ("LICENSE", licenseBytes),
            ("THIRD-PARTY-LICENSES.md", viteTplBytes),
            ("staticwebassets/index.a1b2c3d4.bundle.js", bundledScript));
        var decoupledSrc = BuildViteSource(viteLockWithExcluded, configText: "export default { customBundlerShape: true };\n");
        var (decoupledBnd, decoupledAtt) = MakeProvenance(decoupledPkg, decoupledPkg, decoupledSrc);
        var decoupledRes = Dispatch5(decoupledPkg, decoupledPkg, decoupledBnd, decoupledAtt, decoupledSrc);
        check(decoupledRes.BranchId == "provenance-notices-verified" && decoupledRes.Decision == "deterministic",
            $"LP-04 decoupled bundler-generated notice should verify without LP-10 Vite plan: {decoupledRes.BranchId} ({decoupledRes.MissingFact})");

        // Negative 7: Bundler-manifest path with package.json dependency version mismatching package-lock.json
        JsonCase("package.json range mismatching package-lock.json root dependency spec", "package.json",
            "{\"dependencies\":{\"lit-html\":\"^4.0.0\"}}");
        JsonCase("package-lock.json missing root packages[''] entry", "package-lock.json",
            "{\"packages\":{\"node_modules/lit-html\":{\"version\":\"3.3.3\",\"license\":\"BSD-3-Clause\"}}}");
        JsonCase("package-lock.json resolved version outside declared semver range", "package-lock.json",
            "{\"packages\":{\"\":{\"dependencies\":{\"lit-html\":\"^3.3.3\"}},\"node_modules/lit-html\":{\"version\":\"2.0.0\",\"license\":\"BSD-3-Clause\"}}}");
    }
}
