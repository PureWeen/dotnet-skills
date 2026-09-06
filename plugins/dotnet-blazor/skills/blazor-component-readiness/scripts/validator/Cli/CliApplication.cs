using BlazorComponentReadiness.Validator.IO;
using System.Text;

namespace BlazorComponentReadiness.Validator.Cli;

public static class CliApplication
{
    private const string RootHelp =
        """
        Blazor component readiness validator

        Usage:
          readiness-validator <command> [options]

        Commands:
          package inspect    Inspect the exact identity and digest of a local .nupkg.
          inputs discover    Canonicalize discovery candidates into a draft input manifest.
          inputs confirm     Freeze a validated draft as an immutable confirmed manifest.
          inputs validate    Recheck confirmed manifest package and local input bytes.
          evidence ledger-build
                             Build an immutable repository or component source ledger.
          evidence ledger-validate
                             Validate canonical source-ledger bytes and identities.
          evidence bundle    Select evidence into a self-contained assessment bundle.
          assessment init    Create canonical unified, package, or component rows.
          assessment validate
                             Validate an assessment against inputs, rubric, and evidence.
          assessment revise  Validate an evidence-backed correction and render its next revision.
          report render      Render the next immutable deterministic revision.
          report verify      Verify report bytes and every validation-manifest binding.
          reader render      Derive the four-column partner-preview report outside revisions.
          reader verify      Recompute and verify reader coverage, source bindings and evidence.
          inventory discover Canonicalize package/component library discovery candidates.
          inventory confirm  Freeze one immutable confirmed library inventory.
          inventory status   Report completed, pending, blocked, incomplete, or invalid work.
          library reconcile  Reconstruct mutable run state from immutable validated revisions.
          library validate   Prove every confirmed library work unit is accounted for.
          library index      Write deterministic factual JSON and Markdown library indexes.
          comparison inputs-freeze
                             Freeze conclusion-free exact inputs for a blinded comparison.
          comparison inputs-validate
                             Revalidate the exact allowed-input set before a blind worker starts.
          help               Show this help.

        Run 'readiness-validator <command> --help' for command details.
        """;

    private const string PackageInspectHelp =
        """
        Inspect a local NuGet package

        Usage:
          readiness-validator package inspect --nupkg <path>

        Output:
          Canonical JSON containing the exact package ID, version, archive digest,
          archive size, and nuspec entry name.
        """;

    public static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error)
    {
        try
        {
            if (args.Count == 0)
            {
                throw new UsageException("A command is required.");
            }

            if (IsHelp(args[0]) || string.Equals(args[0], "help", StringComparison.Ordinal))
            {
                output.WriteLine(RootHelp);
                return ExitCodes.Success;
            }

            if (string.Equals(args[0], "evidence", StringComparison.Ordinal))
            {
                return EvidenceCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (string.Equals(args[0], "inputs", StringComparison.Ordinal))
            {
                return InputsCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (string.Equals(args[0], "assessment", StringComparison.Ordinal))
            {
                return AssessmentCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (string.Equals(args[0], "report", StringComparison.Ordinal))
            {
                return ReportCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (string.Equals(args[0], "reader", StringComparison.Ordinal))
            {
                return ReaderCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (string.Equals(args[0], "inventory", StringComparison.Ordinal))
            {
                return InventoryCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (string.Equals(args[0], "library", StringComparison.Ordinal))
            {
                return LibraryCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (string.Equals(args[0], "comparison", StringComparison.Ordinal))
            {
                return ComparisonCommand.Run(args.Skip(1).ToArray(), output);
            }

            if (!string.Equals(args[0], "package", StringComparison.Ordinal))
            {
                throw new UsageException($"Unknown command '{args[0]}'.");
            }

            return RunPackage(args.Skip(1).ToArray(), output);
        }
        catch (UsageException exception)
        {
            error.WriteLine($"usage error: {exception.Message}");
            error.WriteLine();
            error.WriteLine(RootHelp);
            return ExitCodes.InvalidUsage;
        }
        catch (DeterministicValidationException exception)
        {
            error.WriteLine($"validation error: {exception.Message}");
            return ExitCodes.ValidationFailure;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error.WriteLine($"environment error: {exception.Message}");
            return ExitCodes.EnvironmentFailure;
        }
        catch (Exception exception)
        {
            error.WriteLine($"environment error: unexpected validator failure: {exception.Message}");
            return ExitCodes.EnvironmentFailure;
        }
    }

    private static int RunPackage(IReadOnlyList<string> args, TextWriter output)
    {
        if (args.Count == 0 || IsHelp(args[0]))
        {
            output.WriteLine(PackageInspectHelp);
            return ExitCodes.Success;
        }

        if (!string.Equals(args[0], "inspect", StringComparison.Ordinal))
        {
            throw new UsageException($"Unknown package command '{args[0]}'.");
        }

        if (args.Count == 2 && IsHelp(args[1]))
        {
            output.WriteLine(PackageInspectHelp);
            return ExitCodes.Success;
        }

        if (args.Count != 3 || !string.Equals(args[1], "--nupkg", StringComparison.Ordinal))
        {
            throw new UsageException("Package inspection requires exactly '--nupkg <path>'.");
        }

        if (string.IsNullOrWhiteSpace(args[2]))
        {
            throw new UsageException("The --nupkg path cannot be empty.");
        }

        var identity = NupkgInspector.Inspect(args[2]);
        var json = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("package_id", identity.Id);
            writer.WriteString("package_version", identity.Version);
            writer.WriteString("nupkg_sha256", identity.NupkgSha256);
            writer.WriteNumber("nupkg_size", identity.NupkgSize);
            writer.WriteString("nuspec_entry", identity.NuspecEntry);
            writer.WriteEndObject();
        });
        output.Write(Encoding.UTF8.GetString(json));
        output.WriteLine();
        return ExitCodes.Success;
    }

    private static bool IsHelp(string value) =>
        string.Equals(value, "--help", StringComparison.Ordinal) ||
        string.Equals(value, "-h", StringComparison.Ordinal);

}
