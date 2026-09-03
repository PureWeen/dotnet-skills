using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.IO;

namespace BlazorComponentReadiness.Validator.Assessment;

public static class EvidenceInputBindingValidator
{
    public static void Validate(
        string root,
        ReadinessAssessment assessment,
        InputManifest input,
        EvidenceBundle evidence)
    {
        var selected = evidence.Selection
            .Select(selection => selection.EvidenceId)
            .ToHashSet(StringComparer.Ordinal);
        var records = evidence.SourceLedgers
            .SelectMany(source => source.Ledger.Records)
            .Where(record => selected.Contains(record.StableId))
            .ToDictionary(record => record.StableId, StringComparer.Ordinal);
        var packagePath = SafePath.ResolveUnderRoot(
            root,
            input.Package.NupkgPath,
            requireExisting: true,
            requireFile: true);
        var component = assessment.Identity.ComponentId is null
            ? null
            : input.Components.Single(item => item.Id == assessment.Identity.ComponentId);

        foreach (var selection in evidence.Selection)
        {
            var record = records[selection.EvidenceId];
            var provenance = record.Provenance;
            var valid = provenance.Kind switch
            {
                EvidenceIdentity.VendorPublicDocumentation =>
                    input.Documentation.Any(document =>
                        document.Url == provenance.Locator &&
                        document.ContentDigest == provenance.ContentDigest),
                EvidenceIdentity.PackageArtifactMetadata =>
                    ValidatePackageArtifact(packagePath, input, provenance),
                EvidenceIdentity.OwnerSuppliedInternalEvidence or
                    EvidenceIdentity.OwnerSuppliedPublicEvidence =>
                    input.OwnerInputs.Any(owner =>
                        owner.Basename == provenance.Locator &&
                        owner.Provenance == provenance.Kind &&
                        owner.ContentDigest == provenance.ContentDigest),
                EvidenceIdentity.VendorSourceRepository =>
                    ValidateSourceArtifact(component, input, provenance),
                EvidenceIdentity.OwnerDeclaredClosedSource =>
                    input.Source.Availability == "closed-source",
                EvidenceIdentity.ReproducedRuntimeObservation or
                    EvidenceIdentity.OwnerDeclaredUnavailable => true,
                _ => false
            };
            if (!valid)
            {
                throw new DeterministicValidationException(
                    $"Selected evidence '{record.StableId}' is not bound to the confirmed input manifest.");
            }
        }
    }

    private static bool ValidatePackageArtifact(
        string packagePath,
        InputManifest input,
        EvidenceProvenance provenance)
    {
        var computed = NupkgInspector.ComputeEvidenceContentSha256(
            packagePath,
            provenance.Locator);
        if (computed != provenance.ContentDigest.Value)
        {
            return false;
        }

        if (provenance.Locator == NupkgInspector.WholePackageEvidenceLocator)
        {
            return provenance.ContentDigest == input.Package.NupkgDigest;
        }

        var captured = input.PackageSources
            .Where(source => source.Locator == provenance.Locator)
            .ToArray();
        return captured.Length == 0 ||
            captured.Length == 1 && captured[0].ContentDigest == provenance.ContentDigest;
    }

    private static bool ValidateSourceArtifact(
        InputComponent? component,
        InputManifest input,
        EvidenceProvenance provenance)
    {
        const string Prefix = "source:";
        if (!provenance.Locator.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var sourcePath = provenance.Locator[Prefix.Length..];
        if (component is not null &&
            !component.AllowedSourcePaths.Contains(sourcePath, StringComparer.Ordinal))
        {
            return false;
        }

        return input.Source.Availability == "source-available" &&
            input.SourceArtifacts.Any(artifact =>
                artifact.SourcePath == sourcePath &&
                artifact.ContentDigest == provenance.ContentDigest);
    }
}
