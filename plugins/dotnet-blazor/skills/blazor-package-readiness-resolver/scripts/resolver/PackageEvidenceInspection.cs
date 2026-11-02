using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace BlazorPackageResolver;

public static class PackageEvidenceInspection
{
    private const int MaxOutputBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private sealed record Entry(string Path, int SizeBytes, string Sha256);
    private sealed record TextCandidate(string Path, int SizeBytes, string Sha256,
        string TextState, string? Utf8Text);
    private sealed record Declaration(string? Type, string? Value);
    private sealed record RepositoryDeclaration(string? Type, string? Url, string? Commit);
    private sealed record DependencyDeclaration(string? TargetFramework, string Id, string? Version);
    private sealed record Package(string Role, string Id, string Version, string Sha256,
        Declaration[] LicenseDeclarations, RepositoryDeclaration[] RepositoryDeclarations,
        DependencyDeclaration[] DeclaredDependencies, TextCandidate[] LicenseOrNoticeCandidates);
    private sealed record Project(string Path, string Sha256, string ParseState,
        string? SdkDeclaration, string[] PackageIdDeclarations, Entry[] AncestorBuildFiles);
    private sealed record Source(string Sha256, int FileCount, bool? DeclaredRootMatches,
        Project[] Projects, TextCandidate[] LicenseOrNoticeCandidates);
    private sealed record Match(string PackageEntry, string Sha256, string[] SourceEntries);
    private sealed record AssemblyCandidate(string Path, string Sha256, string State,
        string? Name, string? Version, string[] InformationalVersions,
        Declaration[] RepositoryMetadata, int? PublicKeyLength, bool? StrongNameSignedFlag,
        int? StrongNameSignatureSize, string? Detail);
    private sealed record Inspection(int SchemaVersion, string Producer, IReadOnlyList<PinnedInput> Inputs,
        Package Package, Entry[] PackageEntries, Package[] SuppliedDependencies,
        Source? Source, Match[] ExactSourceMatches, AssemblyCandidate[] AssemblyCandidates,
        string[] Diagnostics, string[] Limitations);

    public static byte[] Run(IReadOnlyList<PinnedInput> pins, IReadOnlyDictionary<string, CheckedInput> inputs)
    {
        if (pins.Count != inputs.Count || pins.Select(pin => pin.Role).Distinct(StringComparer.Ordinal).Count() != pins.Count ||
            pins.Any(pin => !inputs.TryGetValue(pin.Role, out var input) ||
                input.Identity != pin || Catalog.Digest(input.Content.Span) != pin.Sha256))
            throw new InvalidDataException("Inspection input bindings differ from their checked bytes.");
        if (!inputs.TryGetValue("package", out var package) ||
            inputs.Keys.Any(role => role is not ("package" or "source-archive") &&
                !Regex.IsMatch(role, @"\Adependency-[0-9]{3}\z", RegexOptions.CultureInvariant)) ||
            inputs.Count(role => role.Key.StartsWith("dependency-", StringComparison.Ordinal)) > 128)
            throw new InvalidDataException("Inspection requires one package, optional source-archive and at most 128 NuGet dependency-NNN inputs.");
        var diagnostics = new List<string>();
        var rootFiles = Archive(package);
        var root = ObservePackage(package, rootFiles);
        var dependencies = inputs.Values.Where(input =>
                input.Identity.Role.StartsWith("dependency-", StringComparison.Ordinal))
            .OrderBy(input => input.Identity.Role, StringComparer.Ordinal)
            .Select(input => ObservePackage(input, Archive(input))).ToArray();
        if (dependencies.Select(item => item.Id + "/" + item.Version)
                .Distinct(StringComparer.Ordinal).Count() != dependencies.Length ||
            dependencies.Any(item => item.Id == root.Id && item.Version == root.Version))
            throw new InvalidDataException("Inspection dependency identities must be distinct and exclude the root.");
        Source? source = null;
        var matches = new List<Match>();
        if (inputs.TryGetValue("source-archive", out var archive))
        {
            var (_, declaration) = Lp02PublicSourceResolver.InspectPackage(package.Content);
            if (!Lp02PublicSourceResolver.TryArchive(archive.Content, out var files, declaration?.Commit,
                    sourceMembers: true))
                throw new InvalidDataException("Source archive is outside the bounded safe archive profile.");
            bool? rootMatches = null;
            if (declaration is not null && Lp02PublicSourceResolver.TryRepository(
                    declaration.RepositoryUrl, declaration.Commit, out var repository, out _))
            {
                var prefix = repository.Split('/')[^1] + "-" + declaration.Commit + "/";
                rootMatches = files.Count > 0 && files.Keys.All(path => path.StartsWith(prefix, StringComparison.Ordinal));
                if (rootMatches == false)
                    diagnostics.Add("Source archive paths do not match the package-declared repository/revision prefix.");
            }
            else diagnostics.Add("No supported package-declared repository/revision is available for a source-root comparison.");
            var projectPaths = files.Keys.Where(path => path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.Ordinal).ToArray();
            if (projectPaths.Length > 64)
                throw new InvalidDataException("Source inspection supports at most 64 project files.");
            var projects = projectPaths.Select(path => ObserveProject(path, files, diagnostics)).ToArray();
            source = new(archive.Identity.Sha256, files.Count, rootMatches, projects,
                Candidates(files.Where(pair => NoticeName(pair.Key))));
            var hashes = files.GroupBy(pair => Catalog.Digest(pair.Value), StringComparer.Ordinal)
                .ToDictionary(group => group.Key, group => group.Select(pair => pair.Key)
                    .Order(StringComparer.Ordinal).ToArray(), StringComparer.Ordinal);
            foreach (var (path, bytes) in rootFiles.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                if (bytes.Length == 0) continue;
                var hash = Catalog.Digest(bytes);
                if (hashes.TryGetValue(hash, out var paths)) matches.Add(new(path, hash, paths));
            }
        }
        var assemblies = rootFiles.Where(pair => pair.Value.AsSpan().StartsWith("MZ"u8) ||
                new[] { ".dll", ".exe", ".winmd" }.Any(suffix =>
                    pair.Key.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => ObserveAssembly(pair.Key, pair.Value)).ToArray();
        var result = new Inspection(1, "package-evidence-observations/1.1.0", pins,
            root, Entries(rootFiles), dependencies, source, matches.ToArray(), assemblies, diagnostics.ToArray(),
            [
                "Local checked bytes only; input hashes do not authenticate acquisition, source publication, reviewer authority or completeness.",
                "Supplied dependencies and their declared ranges/licenses are observations, not a resolved direct/transitive closure or whole-version grant applicability.",
                "Source projects, Razor SDKs and inherited build files are read as data only; no MSBuild evaluation, assessed restore/build or code execution.",
                "Exact source matches establish byte equality only, not ownership, upstream identity, notice sufficiency, compiled build correspondence or a release mapping.",
                "License/notice candidates are named archive entries, not a complete obligation review or exhaustive notice map.",
                "Candidate text is literal strict UTF-8 only up to 4096 bytes; larger or unsupported text retains its exact size/digest and explicit text state, not a clipped grant.",
                "Assembly identities, repository/version attributes and signing fields are observations, not authenticated authorship, source/build correspondence or a complete nested-assembly inventory.",
                "This packet supplements LP-01/02/03/04/10 and PI-01 evidence; it is not an acquisition/admission receipt, a row decision, owner approval or readiness certification."
            ]);
        using var output = new ObservationBuffer();
        using (var writer = new Utf8JsonWriter(output))
            JsonSerializer.Serialize(writer, result, Options);
        output.WriteByte((byte)'\n');
        return output.ToArray();
    }

    private sealed class ObservationBuffer : MemoryStream
    {
        private void Admit(int count)
        {
            if (count > MaxOutputBytes - Length)
                throw new InvalidDataException("Evidence observation output exceeds 2 MiB; no clipped packet was produced.");
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Admit(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Admit(buffer.Length);
            base.Write(buffer);
        }

        public override void WriteByte(byte value)
        {
            Admit(1);
            base.WriteByte(value);
        }
    }

    private static Dictionary<string, byte[]> Archive(CheckedInput input)
    {
        if (Lp03PackageEvidence.Read(input.Content, null) is null ||
            !Lp02PublicSourceResolver.TryArchive(input.Content, out var files))
            throw new InvalidDataException($"Package role {input.Identity.Role} is outside the bounded package evidence profile.");
        return files;
    }

    private static Package ObservePackage(CheckedInput input, Dictionary<string, byte[]> files)
    {
        var identity = Lp03PackageEvidence.Read(input.Content, null)!;
        var metadata = NuGetNuspecReader.Read(input.Content).Metadata!;
        var ns = metadata.Name.Namespace;
        var licenses = metadata.Elements(ns + "license")
            .Select(element => new Declaration((string?)element.Attribute("type"), element.Value)).ToArray();
        var repositories = metadata.Elements(ns + "repository")
            .Select(element => new RepositoryDeclaration((string?)element.Attribute("type"),
                (string?)element.Attribute("url"), (string?)element.Attribute("commit"))).ToArray();
        var dependencies = metadata.Elements(ns + "dependencies").SelectMany(element =>
            element.Elements().SelectMany(child => child.Name == ns + "group"
                ? child.Elements(ns + "dependency").Select(dependency => ObserveDependency(dependency,
                    (string?)child.Attribute("targetFramework")))
                : child.Name == ns + "dependency" ? [ObserveDependency(child, null)] : []))
            .ToArray();
        var candidates = Candidates(files.Where(pair => NoticeName(pair.Key) ||
            licenses.Any(license => license.Type == "file" && license.Value == pair.Key)));
        return new(input.Identity.Role, identity.Id, identity.Version, input.Identity.Sha256,
            licenses, repositories, dependencies, candidates);
    }

    private static DependencyDeclaration ObserveDependency(XElement element, string? target)
    {
        var id = (string?)element.Attribute("id");
        if (string.IsNullOrWhiteSpace(id))
            throw new InvalidDataException("A declared dependency has no unambiguous ID.");
        return new(target, id, (string?)element.Attribute("version"));
    }

    private static bool NoticeName(string path)
    {
        var name = path.Split('/')[^1];
        return Regex.IsMatch(name, @"\A(?:licen[cs]e|notice|copying|third[-_. ]party)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static Entry[] Entries(Dictionary<string, byte[]> files) => files
        .OrderBy(pair => pair.Key, StringComparer.Ordinal)
        .Select(pair => new Entry(pair.Key, pair.Value.Length, Catalog.Digest(pair.Value))).ToArray();

    private static TextCandidate[] Candidates(IEnumerable<KeyValuePair<string, byte[]>> files) => files
        .OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair =>
        {
            string? text = null;
            var state = "size-limit";
            if (pair.Value.Length <= 4096)
            {
                try
                {
                    text = Utf8.GetString(pair.Value);
                    state = "retained-utf8";
                }
                catch (DecoderFallbackException) { state = "unsupported-utf8"; }
            }
            return new TextCandidate(pair.Key, pair.Value.Length, Catalog.Digest(pair.Value), state, text);
        }).ToArray();

    private static AssemblyCandidate ObserveAssembly(string path, byte[] bytes)
    {
        var inspected = Pi01PeInspector.Inspect(bytes);
        if (inspected.State is not ("unsigned" or "delay-signed" or "public-signed" or
                "verified-signed" or "invalid-signature" or "signature-unverified"))
            return new(path, Catalog.Digest(bytes), inspected.State, null, null, [], [],
                null, null, null, inspected.Detail);
        using var pe = new PEReader(new MemoryStream(bytes, writable: false));
        var metadata = pe.GetMetadataReader();
        var definition = metadata.GetAssemblyDefinition();
        var versions = new List<string>();
        var repositories = new List<Declaration>();
        foreach (var handle in definition.GetCustomAttributes())
        {
            var attribute = metadata.GetCustomAttribute(handle);
            EntityHandle type;
            BlobHandle signature;
            string constructor;
            if (attribute.Constructor.Kind == HandleKind.MemberReference)
            {
                var member = metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
                type = member.Parent;
                signature = member.Signature;
                constructor = metadata.GetString(member.Name);
            }
            else if (attribute.Constructor.Kind == HandleKind.MethodDefinition)
            {
                var method = metadata.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor);
                type = method.GetDeclaringType();
                signature = method.Signature;
                constructor = metadata.GetString(method.Name);
            }
            else continue;
            var (space, name) = type.Kind switch
            {
                HandleKind.TypeReference => (metadata.GetTypeReference((TypeReferenceHandle)type).Namespace,
                    metadata.GetTypeReference((TypeReferenceHandle)type).Name),
                HandleKind.TypeDefinition => (metadata.GetTypeDefinition((TypeDefinitionHandle)type).Namespace,
                    metadata.GetTypeDefinition((TypeDefinitionHandle)type).Name),
                _ => (default(StringHandle), default(StringHandle))
            };
            if (constructor != ".ctor" || metadata.GetString(space) != "System.Reflection") continue;
            var attributeName = metadata.GetString(name);
            var shape = metadata.GetBlobBytes(signature).AsSpan();
            bool version = attributeName == "AssemblyInformationalVersionAttribute" &&
                shape.SequenceEqual(new byte[] { 0x20, 1, 1, 0x0e });
            bool repository = attributeName == "AssemblyMetadataAttribute" &&
                shape.SequenceEqual(new byte[] { 0x20, 2, 1, 0x0e, 0x0e });
            if (!version && !repository) continue;
            var value = metadata.GetBlobReader(attribute.Value);
            if (value.ReadUInt16() != 1)
                throw new InvalidDataException("Assembly attribute has an unsupported value prolog.");
            var first = value.ReadSerializedString();
            if (version && first is not null) versions.Add(first);
            else if (repository)
            {
                var second = value.ReadSerializedString();
                if (first == "RepositoryUrl" || first == "RepositoryCommit")
                    repositories.Add(new(first, second));
            }
        }
        var header = pe.PEHeaders.CorHeader!;
        return new(path, Catalog.Digest(bytes), inspected.State, metadata.GetString(definition.Name),
            definition.Version.ToString(), versions.ToArray(), repositories.ToArray(),
            definition.PublicKey.IsNil ? 0 : metadata.GetBlobBytes(definition.PublicKey).Length,
            (header.Flags & CorFlags.StrongNameSigned) != 0, header.StrongNameSignatureDirectory.Size,
            inspected.Detail);
    }

    private static Project ObserveProject(string path, Dictionary<string, byte[]> files, List<string> diagnostics)
    {
        var bytes = files[path];
        var ancestors = files.Where(pair =>
        {
            var split = pair.Key.LastIndexOf('/') + 1;
            var name = pair.Key[split..];
            return (name.Equals("Directory.Build.props", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Directory.Build.targets", StringComparison.OrdinalIgnoreCase)) &&
                path.StartsWith(pair.Key[..split], StringComparison.OrdinalIgnoreCase);
        }).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        if (bytes.Length > Lp02PublicSourceResolver.MaxSelectedFileBytes)
        {
            diagnostics.Add($"Project {path} exceeds 1 MiB; only its digest and inherited-file inventory were retained.");
            return new(path, Catalog.Digest(bytes), "size-limit", null, [], Entries(ancestors));
        }
        try
        {
            var text = bytes.AsSpan();
            if (text.StartsWith(new byte[] { 239, 187, 191 })) text = text[3..];
            using var input = new StringReader(Utf8.GetString(text));
            using var reader = XmlReader.Create(input, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
                MaxCharactersInDocument = Lp02PublicSourceResolver.MaxSelectedFileBytes
            });
            var document = XDocument.Load(reader);
            if (document.Root is not { } root || root.Name.LocalName != "Project")
                throw new XmlException("Not a project document.");
            return new(path, Catalog.Digest(bytes), "unevaluated-xml",
                (string?)root.Attribute("Sdk"),
                root.Descendants().Where(element =>
                    element.Name.LocalName.Equals("PackageId", StringComparison.OrdinalIgnoreCase))
                    .Select(element => element.Value).ToArray(), Entries(ancestors));
        }
        catch (Exception error) when (error is XmlException or DecoderFallbackException)
        {
            diagnostics.Add($"Project {path} has unsupported XML/UTF-8; only its digest and inherited-file inventory were retained.");
            return new(path, Catalog.Digest(bytes), "unsupported-xml-or-encoding", null, [], Entries(ancestors));
        }
    }
}
