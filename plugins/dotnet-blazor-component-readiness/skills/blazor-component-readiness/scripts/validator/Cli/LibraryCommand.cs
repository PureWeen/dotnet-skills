using BlazorComponentReadiness.Validator.Inventory;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Library;
using BlazorComponentReadiness.Validator.Contracts;

namespace BlazorComponentReadiness.Validator.Cli;

public static class LibraryCommand
{
    private const string Help =
        """
        Full-library validation and factual index

        Usage:
          readiness-validator library reconcile --root <dir> --inventory <inventory.confirmed.json> --run-manifest <run-manifest.json>
          readiness-validator library validate --root <dir> --inventory <inventory.confirmed.json> --run-manifest <run-manifest.json>
          readiness-validator library index --root <dir> --inventory <inventory.confirmed.json> --run-manifest <run-manifest.json> --json <library-index.json> --markdown <library-index.md>
        """;

    public static int Run(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 0 || IsHelp(args[0]))
        {
            output.WriteLine(Help);
            return ExitCodes.Success;
        }

        return args[0] switch
        {
            "reconcile" => Reconcile(args.Skip(1).ToArray()),
            "validate" => Validate(args.Skip(1).ToArray()),
            "index" => Index(args.Skip(1).ToArray()),
            _ => throw new UsageException($"Unknown library command '{args[0]}'.")
        };
    }

    private static int Reconcile(IReadOnlyList<string> args)
    {
        var options = CommandOptions.Parse(args, "--root", "--inventory", "--run-manifest");
        var (root, inventoryBytes, inventory) = LoadInventory(options);
        var manifestRelative = InventoryCommand.ExactPath(
            root,
            options.Single("--run-manifest"),
            "run-manifest.json");
        LibraryRunManifest? previous = null;
        var manifestPath = Path.Combine(root, manifestRelative);
        if (File.Exists(manifestPath))
        {
            try
            {
                var previousBytes = BoundedIO.ReadAllBytes(
                    manifestPath,
                    ResourceLimits.SerializedArtifactBytes,
                    "run manifest");
                previous = LibraryService.Parse(previousBytes);
                LibraryService.ValidateShape(previous, inventory, inventoryBytes);
            }
            catch (DeterministicValidationException)
            {
                previous = null;
            }
        }

        var reconciled = LibraryService.Reconcile(root, inventory, inventoryBytes, previous);
        AtomicFile.Replace(root, manifestRelative, LibraryService.Serialize(reconciled));
        return ExitCodes.Success;
    }

    private static int Validate(IReadOnlyList<string> args)
    {
        var options = CommandOptions.Parse(args, "--root", "--inventory", "--run-manifest");
        var (root, inventoryBytes, inventory) = LoadInventory(options);
        var manifestBytes = InventoryCommand.ReadExact(
            root,
            options.Single("--run-manifest"),
            "run-manifest.json",
            "run manifest");
        var manifest = LibraryService.Parse(manifestBytes);
        _ = LibraryService.Validate(root, inventory, inventoryBytes, manifest);
        return ExitCodes.Success;
    }

    private static int Index(IReadOnlyList<string> args)
    {
        var options = CommandOptions.Parse(
            args,
            "--root",
            "--inventory",
            "--run-manifest",
            "--json",
            "--markdown");
        var (root, inventoryBytes, inventory) = LoadInventory(options);
        var manifestBytes = InventoryCommand.ReadExact(
            root,
            options.Single("--run-manifest"),
            "run-manifest.json",
            "run manifest");
        var manifest = LibraryService.Parse(manifestBytes);
        var validated = LibraryService.Validate(root, inventory, inventoryBytes, manifest);
        var canonicalManifestBytes = LibraryService.Serialize(validated);
        var index = LibraryService.CreateIndex(
            inventory,
            inventoryBytes,
            validated,
            canonicalManifestBytes);
        var json = InventoryCommand.ExactPath(
            root,
            options.Single("--json"),
            "library-index.json");
        var markdown = InventoryCommand.ExactPath(
            root,
            options.Single("--markdown"),
            "library-index.md");
        AtomicFile.Replace(root, json, index.Json);
        AtomicFile.Replace(root, markdown, index.Markdown);
        return ExitCodes.Success;
    }

    private static (string Root, byte[] InventoryBytes, LibraryInventory Inventory)
        LoadInventory(CommandOptions options)
    {
        var root = InventoryCommand.PrepareRoot(options.Single("--root"));
        var inventoryBytes = InventoryCommand.ReadExact(
            root,
            options.Single("--inventory"),
            "inventory.confirmed.json",
            "confirmed inventory");
        var inventory = InventoryService.Parse(inventoryBytes);
        InventoryService.Validate(inventory, root, requireConfirmed: true);
        return (root, inventoryBytes, inventory);
    }

    private static bool IsHelp(string value) => value is "--help" or "-h";
}
