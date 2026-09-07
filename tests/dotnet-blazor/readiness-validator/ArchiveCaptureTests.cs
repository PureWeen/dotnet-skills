using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using BlazorComponentReadiness.Validator.Cli;
using BlazorComponentReadiness.Validator.Inputs;
using BlazorComponentReadiness.Validator.IO;

internal static class ArchiveCaptureTests
{
    public static void Run(string repositoryRoot, string pluginRoot)
    {
        var configuredRoot = Environment.GetEnvironmentVariable("READINESS_TEST_ROOT");
        var testRoot = Path.GetFullPath(
            string.IsNullOrWhiteSpace(configuredRoot)
                ? Path.Combine(repositoryRoot, "artifacts", "readiness-validator-archive-tests")
                : Path.Combine(configuredRoot, "archive"));
        if (Directory.Exists(testRoot))
        {
            Directory.Delete(testRoot, recursive: true);
        }

        Directory.CreateDirectory(testRoot);
        try
        {
            TestTarGzipCapture(testRoot);
            TestCaptureFailures(testRoot);
            TestZipCapture(testRoot);
        }
        finally
        {
            if (Directory.Exists(testRoot))
            {
                Directory.Delete(testRoot, recursive: true);
            }
        }
    }

    private static void TestTarGzipCapture(string testRoot)
    {
        var root = Path.Combine(testRoot, "fixture");
        var sourceRoot = Path.Combine(root, "public-inputs", "source");
        Directory.CreateDirectory(sourceRoot);
        Directory.CreateDirectory(Path.Combine(root, ".git"));
        File.WriteAllText(Path.Combine(root, ".git", "HEAD"), "ref: refs/heads/unrelated\n");
        var sourcePath = Path.Combine(sourceRoot, "src", "Component.razor");
        Directory.CreateDirectory(Path.GetDirectoryName(sourcePath)!);
        File.WriteAllText(sourcePath, "@* archive capture fixture *@\n", Encoding.UTF8);
        var archivePath = Path.Combine(root, "public-inputs", "source.tar.gz");
        CreateTarGzip(
            archivePath,
            "igniteui-blazor-65e8af57a54edc3a098dd16dea7ce5d287a3c5d2/src/Component.razor",
            File.ReadAllBytes(sourcePath));

        var arguments = new[]
        {
            "source", "capture-archive",
            "--root", root,
            "--archive", "public-inputs/source.tar.gz",
            "--source-root", "public-inputs/source",
            "--archive-prefix", "igniteui-blazor-65e8af57a54edc3a098dd16dea7ce5d287a3c5d2",
            "--archive-format", "tar.gz",
            "--repository-uri", "https://github.com/igniteui/igniteui-blazor",
            "--source-commit", "65e8af57a54edc3a098dd16dea7ce5d287a3c5d2",
            "--source-mapping", "owner-selected GitHub codeload archive at the pinned commit",
            "--source-confidence", "high",
            "--acquisition-locator", "https://codeload.github.com/IgniteUI/igniteui-blazor/tar.gz/65e8af57a54edc3a098dd16dea7ce5d287a3c5d2",
            "--source-path", "src/Component.razor",
            "--output", "public-inputs/source-capture.json"
        };
        var firstOutput = new StringWriter();
        var firstError = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(arguments, firstOutput, firstError),
            "tar.gz capture");
        var receiptPath = Path.Combine(root, "public-inputs", "source-capture.json");
        var receiptBytes = File.ReadAllBytes(receiptPath);
        AssertEqual(string.Empty, firstOutput.ToString(), "capture result is retained, not mixed into launcher stdout");
        using (var receipt = JsonDocument.Parse(receiptBytes))
        {
            AssertEqual("source-archive", receipt.RootElement.GetProperty("capture_kind").GetString(), "capture kind");
            AssertEqual(
                "65e8af57a54edc3a098dd16dea7ce5d287a3c5d2",
                receipt.RootElement.GetProperty("declared_source").GetProperty("commit").GetString(),
                "declared source commit");
            Assert(
                !receipt.RootElement.TryGetProperty("acquisition", out _),
                "capture does not fabricate a download method or result");
            AssertEqual(
                "public-inputs/source.tar.gz",
                receipt.RootElement.GetProperty("archive").GetProperty("path").GetString(),
                "retained archive path");
            AssertEqual(
                "src/Component.razor",
                receipt.RootElement.GetProperty("source_artifacts")[0].GetProperty("source_path").GetString(),
                "selected source path");
        }

        var secondOutput = Path.Combine(root, "public-inputs", "source-capture-2.json");
        var secondArguments = arguments
            .Select(value => value == "public-inputs/source-capture.json" ? "public-inputs/source-capture-2.json" : value)
            .ToArray();
        var secondStdout = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(secondArguments, secondStdout, new StringWriter()),
            "deterministic second capture");
        AssertBytes(
            receiptBytes,
            File.ReadAllBytes(secondOutput),
            "deterministic receipt bytes");

        var collision = new StringWriter();
        AssertEqual(
            ExitCodes.EnvironmentFailure,
            CliApplication.Run(arguments, collision, new StringWriter()),
            "capture output is immutable");
        AssertBytes(receiptBytes, File.ReadAllBytes(receiptPath), "immutable receipt content");

        var packagePath = Path.Combine(root, "package.nupkg");
        CreatePackage(packagePath);
        var candidatesPath = Path.Combine(root, "candidates.json");
        var candidateInit = new[]
        {
            "inputs", "candidates", "init",
            "--acquisition", "published",
            "--package-locator", "package.nupkg",
            "--package-method", "local-file",
            "--source-availability", "source-available",
            "--repository-uri", "https://github.com/igniteui/igniteui-blazor",
            "--source-commit", "65e8af57a54edc3a098dd16dea7ce5d287a3c5d2",
            "--source-mapping", "owner-selected GitHub codeload archive at the pinned commit",
            "--source-confidence", "high",
            "--output", candidatesPath
        };
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(candidateInit, new StringWriter(), new StringWriter()),
            "candidate initialization after capture");
        var retrievalPath = Path.Combine(root, "candidates-retrieval.json");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "inputs", "candidates", "add-retrieval",
                    "--input", candidatesPath,
                    "--subject", "package",
                    "--locator", "package.nupkg",
                    "--method", "local-file",
                    "--result", "succeeded",
                    "--output", retrievalPath
                ],
                new StringWriter(),
                new StringWriter()),
            "candidate retrieval after capture");
        var candidateWithArtifact = Path.Combine(root, "candidates-source.json");
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                [
                    "inputs", "candidates", "add-source-artifact",
                    "--input", retrievalPath,
                    "--source-path", "src/Component.razor",
                    "--path", "public-inputs/source/src/Component.razor",
                    "--output", candidateWithArtifact
                ],
                new StringWriter(),
                new StringWriter()),
            "candidate source artifact after capture");
        var manifest = InputManifestService.Discover(
            root,
            packagePath,
            File.ReadAllBytes(candidateWithArtifact));
        AssertEqual(1, manifest.SourceArtifacts.Count, "downstream source artifact count");
        AssertEqual(
            "src/Component.razor",
            manifest.SourceArtifacts[0].SourcePath,
            "downstream source artifact path");
        AssertEqual(
            "confirmed",
            InputManifestService.Confirm(manifest, root).State,
            "downstream source artifact confirmation");
        Assert(
            File.ReadAllText(Path.Combine(root, ".git", "HEAD")) == "ref: refs/heads/unrelated\n",
            "unrelated enclosing git metadata is untouched");
    }

    private static void TestCaptureFailures(string testRoot)
    {
        var root = Path.Combine(testRoot, "failures");
        var sourceRoot = Path.Combine(root, "source");
        Directory.CreateDirectory(Path.Combine(sourceRoot, "src"));
        File.WriteAllText(Path.Combine(sourceRoot, "src", "file.txt"), "local");
        var archivePath = Path.Combine(root, "source.tar.gz");
        CreateTarGzip(archivePath, "prefix/src/file.txt", Encoding.UTF8.GetBytes("archive"));
        var args = new[]
        {
            "source", "capture-archive",
            "--root", root,
            "--archive", "source.tar.gz",
            "--source-root", "source",
            "--archive-prefix", "prefix",
            "--archive-format", "tar.gz",
            "--repository-uri", "https://example.com/vendor/repo",
            "--source-commit", "0123456789012345678901234567890123456789",
            "--source-mapping", "test mapping",
            "--source-confidence", "medium",
            "--acquisition-locator", "https://example.com/archive.tar.gz",
            "--source-path", "src/file.txt",
            "--output", "receipt.json"
        };
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(args, new StringWriter(), new StringWriter()),
            "mismatched extracted file fails closed");
        Assert(!File.Exists(Path.Combine(root, "receipt.json")), "failed capture writes no receipt");

        var invalidPrefix = args
            .Select(value => value == "prefix" ? "../unsafe" : value)
            .ToArray();
        AssertEqual(
            ExitCodes.ValidationFailure,
            CliApplication.Run(invalidPrefix, new StringWriter(), new StringWriter()),
            "unsafe archive prefix fails closed");

        File.WriteAllText(Path.Combine(sourceRoot, "src", "file.txt"), "archive");
        string[] WithOption(string option, string value)
        {
            var changed = args.ToArray();
            changed[Array.IndexOf(changed, option) + 1] = value;
            return changed;
        }

        var controlError = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(WithOption("--output", "valid-control.json"), new StringWriter(), controlError),
            $"valid counterpart of rejection cases: {controlError}");

        CreateTarGzip(archivePath, "prefix/src/file.txt", []);
        File.WriteAllBytes(Path.Combine(sourceRoot, "src", "file.txt"), []);
        var emptyError = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(WithOption("--output", "empty-file.json"), new StringWriter(), emptyError),
            $"empty regular source file remains valid: {emptyError}");
        CreateTarGzip(archivePath, "prefix/src/file.txt", Encoding.UTF8.GetBytes("archive"));
        File.WriteAllText(Path.Combine(sourceRoot, "src", "file.txt"), "archive");

        void Reject(string name, string[] command, string message)
        {
            var error = new StringWriter();
            Assert(CliApplication.Run(command, new StringWriter(), error) != ExitCodes.Success,
                $"{name} must fail");
            Assert(error.ToString().Contains(message, StringComparison.OrdinalIgnoreCase),
                $"{name} fails for the expected reason: {error}");
            Assert(!File.Exists(Path.Combine(root, "receipt.json")), $"{name} writes no receipt");
        }

        Reject("missing archive", WithOption("--archive", "missing.tar.gz"), "does not exist");
        Reject("missing selected member", WithOption("--source-path", "src/missing.txt"), "does not contain selected file");
        Reject("outside-root archive", WithOption("--archive", "../outside.tar.gz"), "relative path");
        Reject("traversal source selection", WithOption("--source-path", "../file.txt"), "relative path");
        Reject("missing output parent", WithOption("--output", "missing/receipt.json"), "parent");
        Reject("output inside source", WithOption("--output", "source/receipt.json"), "outside the extracted source");
        Assert(!File.Exists(Path.Combine(sourceRoot, "receipt.json")), "source tree is never an output destination");
        Reject("invalid commit", WithOption("--source-commit", "master"), "commit");
        Reject("non-HTTPS repository", WithOption("--repository-uri", "http://example.com/vendor/repo"), "HTTPS");
        Reject("missing locator", WithOption("--acquisition-locator", ""), "acquisition");
        Reject("invalid confidence", WithOption("--source-confidence", "verified"), "confidence");
        Reject("wrong expected digest", [.. args, "--expected-sha256", new string('0', 64)], "expected SHA-256");
        Reject("duplicate selection", [.. args, "--source-path", "src/file.txt"], "unique");
        Reject("unknown option", [.. args, "--git-clean", "true"], "Unknown option");
        Reject("unsupported source operation", ["source", "checkout", "--help"], "Unknown source command");

        CreateTarGzip(archivePath, "prefix/../file.txt", Encoding.UTF8.GetBytes("archive"));
        Reject("unsafe archive entry", args, "safe regular archive path");

        using (var file = File.Create(archivePath))
        using (var gzip = new GZipStream(file, CompressionLevel.NoCompression))
        using (var writer = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: false))
        {
            for (var index = 0; index < 2; index++)
            {
                writer.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "prefix/src/file.txt")
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes("archive"))
                });
            }
        }

        Reject("duplicate archive member", args, "duplicate entry");
        using (var file = File.Create(archivePath))
        using (var gzip = new GZipStream(file, CompressionLevel.NoCompression))
        using (var writer = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: false))
        {
            writer.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "prefix/src/file.txt")
            {
                LinkName = "elsewhere"
            });
        }

        Reject("archive symbolic link", args, "not a regular file");
        File.WriteAllText(archivePath, "not an archive");
        Reject("malformed archive", args, "not a valid gzip");
        using (var oversized = File.Create(archivePath))
        {
            oversized.SetLength(ResourceLimits.SourceArchiveBytes + 1);
        }

        Reject("compressed archive size limit", args, "limit");

        CreateTarGzip(archivePath, "prefix/src/file.txt", Encoding.UTF8.GetBytes("archive"));
        if (!OperatingSystem.IsWindows())
        {
            var localPath = Path.Combine(sourceRoot, "src", "file.txt");
            var realPath = Path.Combine(root, "real.txt");
            File.Move(localPath, realPath);
            File.CreateSymbolicLink(localPath, realPath);
            Reject("captured file symbolic link", args, "Symbolic links");
        }
    }

    private static void TestZipCapture(string testRoot)
    {
        var root = Path.Combine(testRoot, "zip");
        Directory.CreateDirectory(Path.Combine(root, "source"));
        var content = Encoding.UTF8.GetBytes("zip source");
        File.WriteAllBytes(Path.Combine(root, "source", "file.txt"), content);
        using (var archive = ZipFile.Open(Path.Combine(root, "source.zip"), ZipArchiveMode.Create))
        {
            using var entry = archive.CreateEntry("prefix/file.txt").Open();
            entry.Write(content);
        }

        var error = new StringWriter();
        AssertEqual(
            ExitCodes.Success,
            CliApplication.Run(
                ["source", "capture-archive", "--root", root, "--archive", "source.zip",
                    "--source-root", "source", "--archive-prefix", "prefix", "--archive-format", "zip",
                    "--repository-uri", "https://example.com/vendor/repo",
                    "--source-commit", "0123456789012345678901234567890123456789",
                    "--source-mapping", "Fixture declared mapping", "--source-confidence", "low",
                    "--acquisition-locator", "https://example.com/source.zip",
                    "--source-path", "file.txt", "--output", "receipt.json"],
                new StringWriter(),
                error),
            $"ZIP source capture: {error}");
    }

    private static void CreateTarGzip(string path, string entryName, byte[] content)
    {
        using var file = File.Create(path);
        using var gzip = new GZipStream(file, CompressionLevel.NoCompression);
        using var writer = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: false);
        writer.WriteEntry(new PaxGlobalExtendedAttributesTarEntry(
            [new KeyValuePair<string, string>("comment", "Declared archive metadata, not remote identity proof")]));
        var entry = new PaxTarEntry(TarEntryType.RegularFile, entryName)
        {
            DataStream = new MemoryStream(content, writable: false)
        };
        writer.WriteEntry(entry);
    }

    private static void CreatePackage(string path)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        var entry = archive.CreateEntry(
            "Fixture.Package.nuspec",
            CompressionLevel.NoCompression);
        using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
        writer.Write(
            "<package><metadata><id>Fixture.Package</id><version>1.0.0</version></metadata></package>");
    }

    private static void AssertBytes(byte[] expected, byte[] actual, string name) =>
        Assert(expected.SequenceEqual(actual), $"{name}: byte sequences differ.");

    private static void AssertEqual<T>(T expected, T actual, string name) =>
        Assert(EqualityComparer<T>.Default.Equals(expected, actual), $"{name}: expected '{expected}', actual '{actual}'.");

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
