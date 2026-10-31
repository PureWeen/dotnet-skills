using System.Text.Json;
using System.Text.Json.Nodes;
using BlazorPackageResolver;

internal static class RequestChecks
{
    internal static void Run(Registry registry, string root)
    {
        int count = 0;
        var files = new[] { Path.Combine(root, "cases.json") }.Concat(
            Directory.EnumerateFiles(root, "cases.json", SearchOption.AllDirectories)
                .Where(path => Path.GetDirectoryName(path) != root));
        foreach (var manifest in files)
        {
            using var pins = JsonDocument.Parse(File.ReadAllBytes(
                Path.Combine(FixtureCorpus.Tests(), "corpus", "lock.json")));
            var logical = Path.GetRelativePath(root, manifest).Replace('\\', '/');
            var frozenOutput = Replay.Run(manifest, registry);
            if (Catalog.Digest(frozenOutput) != pins.RootElement.GetProperty("row_outputs")
                    .GetProperty(logical).GetString())
                throw new Exception("Canonical output differs from the accepted result digest.");
            var suite = JsonNode.Parse(File.ReadAllBytes(manifest))!.AsObject();
            var cases = suite["cases"]!.AsArray();
            foreach (var item in cases)
            {
                var value = item!.AsObject();
                value.Remove("expected");
                value.Remove("rationale");
                value.Remove("evidence_pointers");
            }
            var request = Path.Combine(Path.GetDirectoryName(manifest)!, "resolve-request.generated.json");
            File.WriteAllText(request, suite.ToJsonString());
            try
            {
                if (!Requests.Run(request, registry).SequenceEqual(frozenOutput))
                    throw new Exception("Answer-free request differs from accepted replay.");
                count += cases.Count;
            }
            finally { File.Delete(request); }
        }
        var path = Path.Combine(root, "request-boundary.json");
        foreach (var invalid in new[] { "", "\0" })
        {
            try { Requests.Run(invalid, registry); throw new Exception("Invalid manifest path accepted."); }
            catch (InvalidDataException) { }
            try { Requests.Package(invalid, registry); throw new Exception("Invalid package path accepted."); }
            catch (InvalidDataException) { }
        }
        void Reject(string text)
        {
            File.WriteAllText(path, text);
            try { Requests.Run(path, registry); }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or IOException) { return; }
            throw new Exception("Invalid request was accepted.");
        }
        Reject("""{"schema_version":1,"schema_version":1,"cases":[]}""");
        Reject("""{"schema_version":1,"cases":[],"weakening":"graph-counts"}""");
        Reject("""{"schema_version":1,"cases":[]}""");
        Reject("""{"schema_version":2,"cases":[]}""");
        Reject("""{"schema_version":1,"cases":[{"case_id":"x","row_id":"LP-04","inputs":[{"role":"package","path":"../escape","sha256":""}]}]}""");
        Reject("""{"schema_version":1,"cases":[{"case_id":"x","row_id":"LP-04","inputs":null}]}""");
        Reject("""{"schema_version":1,"cases":[{"case_id":"x","row_id":null,"inputs":[]}]}""");
        Reject("""{"schema_version":1,"cases":[{"case_id":"x","row_id":"ZZ-99","inputs":[]}]}""");
        Reject("""{"schema_version":1,"cases":[{"case_id":" ","row_id":"LP-04","inputs":[]}]}""");
        var digest = Catalog.Digest(File.ReadAllBytes(Path.Combine(root, "lp05", "packages", "expression.nupkg")));
        var valid = JsonNode.Parse(
            $$"""{"schema_version":1,"cases":[{"case_id":"x","row_id":"LP-05","inputs":[{"role":"package","path":"lp05/packages/expression.nupkg","sha256":"{{digest}}"}]}]}""")!;
        void Change(Action<JsonNode> mutation)
        {
            var value = valid.DeepClone();
            mutation(value);
            Reject(value.ToJsonString());
        }
        Change(value => value["cases"]![0]!["inputs"]![0]!["sha256"] = new string('0', 64));
        Change(value => value["cases"]![0]!["inputs"]![0]!["sha256"] = digest.ToUpperInvariant());
        Change(value => value["cases"]![0]!["inputs"]![0]!["role"] = " ");
        Change(value => value["cases"]![0]!["inputs"]!.AsArray().Add(value["cases"]![0]!["inputs"]![0]!.DeepClone()));
        Change(value => value["cases"]!.AsArray().Add(value["cases"]![0]!.DeepClone()));
        Change(value => value["cases"]![0]!["inputs"]![0]!["path"] = "/absolute");
        Change(value => value["cases"]![0]!["inputs"]![0]!["path"] = "lp05/../lp05/packages/expression.nupkg");
        Change(value => value["cases"]![0]!["inputs"]![0]!["path"] = "lp05\\packages\\expression.nupkg");
        Change(value => value["cases"]![0]!["expected"] = new JsonObject());
        Change(value => value["cases"]![0]!["inputs"] = new JsonArray(
            Enumerable.Range(0, 513).Select(_ => valid["cases"]![0]!["inputs"]![0]!.DeepClone()).ToArray()));
        Change(value => value["cases"] = new JsonArray(
            Enumerable.Range(0, 257).Select(_ => valid["cases"]![0]!.DeepClone()).ToArray()));
        var atLimit = valid.ToJsonString().PadRight(1024 * 1024);
        File.WriteAllText(path, atLimit);
        if (Requests.Run(path, registry).Length == 0) throw new Exception("Inclusive manifest limit failed.");
        Reject(atLimit + " ");
        File.Delete(path);
        Console.WriteLine($"Answer-free request admission matches {count} frozen replay scenarios.");
    }
}
