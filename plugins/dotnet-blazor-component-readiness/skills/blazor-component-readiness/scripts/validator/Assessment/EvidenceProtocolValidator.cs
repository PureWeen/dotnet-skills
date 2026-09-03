using System.Text.Json;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.Evidence;
using BlazorComponentReadiness.Validator.IO;
using BlazorComponentReadiness.Validator.Validation;

namespace BlazorComponentReadiness.Validator.Assessment;

public static class EvidenceProtocolValidator
{
    public const string LifecycleMethod = "protocol:dynamic-child-lifecycle-v1";
    public const string NoticeCoverageMethod = "protocol:notice-coverage-v1";
    public const string AuthenticodeMethod = "protocol:authenticode-verification-v1";
    public const string SupportOwnershipMethod = "protocol:support-ownership-v1";
    public const string ToolchainMethod = "protocol:toolchain-probe-v1";

    private static readonly string[] LifecycleOperations =
    [
        "add-child",
        "remove-child",
        "keyed-reorder",
        "disable-or-remove-selected-child",
        "membership-reconciliation",
        "propagated-name-default-value-state",
        "focus-ownership-restoration",
        "single-roving-tab-stop",
        "callbacks-error-routing",
        "cleanup-disposal"
    ];

    private static readonly IReadOnlyDictionary<string, string[]> LifecycleRows =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["A11Y-06"] =
            [
                "add-child",
                "remove-child",
                "keyed-reorder",
                "disable-or-remove-selected-child",
                "membership-reconciliation",
                "propagated-name-default-value-state",
                "single-roving-tab-stop"
            ],
            ["A11Y-07"] =
            [
                "disable-or-remove-selected-child",
                "focus-ownership-restoration",
                "single-roving-tab-stop"
            ],
            ["A11Y-08"] =
            [
                "add-child",
                "membership-reconciliation",
                "propagated-name-default-value-state"
            ],
            ["BEQ-12"] = ["callbacks-error-routing"],
            ["BEQ-15"] = ["cleanup-disposal"]
        };

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

        var protocols = new Dictionary<string, ParsedProtocol>(StringComparer.Ordinal);
        foreach (var record in records.Values.Where(record =>
                     record.Provenance.Method.StartsWith("protocol:", StringComparison.Ordinal)))
        {
            if (!protocols.TryAdd(
                    record.StableId,
                    ParseProtocol(root, input, record)))
            {
                throw new DeterministicValidationException(
                    $"Evidence protocol '{record.StableId}' is duplicated.");
            }
        }

        ValidateLifecycle(assessment, input, records, protocols);
        RequireProtocolForOutcomeRow(
            assessment,
            records,
            protocols,
            "LP-04",
            NoticeCoverageMethod,
            "complete",
            "incomplete");
        RequireProtocolForOutcomeRow(
            assessment,
            records,
            protocols,
            "PI-02",
            AuthenticodeMethod,
            "passed",
            "failed");
        RequireProtocolForVerifiedRow(
            assessment,
            records,
            protocols,
            "SUP-01",
            SupportOwnershipMethod);
        ValidateToolchainRows(assessment, input, records, protocols);
    }

    private static ParsedProtocol ParseProtocol(
        string root,
        InputManifest input,
        EvidenceRecord record)
    {
        var bytes = ReadProtocolBytes(root, input, record);
        return record.Provenance.Method switch
        {
            LifecycleMethod => ParseLifecycle(bytes, input),
            NoticeCoverageMethod => ParseNoticeCoverage(bytes, input),
            AuthenticodeMethod => ParseAuthenticode(root, bytes, input),
            SupportOwnershipMethod => ParseSupportOwnership(bytes),
            ToolchainMethod => ParseToolchain(bytes, input),
            _ => throw new DeterministicValidationException(
                $"Evidence '{record.StableId}' uses unknown structured method '{record.Provenance.Method}'.")
        };
    }

    private static byte[] ReadProtocolBytes(
        string root,
        InputManifest input,
        EvidenceRecord record)
    {
        var provenance = record.Provenance;
        var basename = Canonicalization.Basename(
            provenance.Locator,
            "structured evidence locator");
        var evidenceInput = input.EvidenceInputs.SingleOrDefault(item =>
            item.Basename == basename &&
            item.ContentDigest == provenance.ContentDigest);
        var ownerInput = input.OwnerInputs.SingleOrDefault(item =>
            item.Basename == basename &&
            item.ContentDigest == provenance.ContentDigest);
        var bound = provenance.Kind switch
        {
            EvidenceIdentity.ReproducedRuntimeObservation or
                EvidenceIdentity.ReviewerGeneratedAnalysis => evidenceInput is not null,
            EvidenceIdentity.OwnerSuppliedInternalEvidence or
                EvidenceIdentity.OwnerSuppliedPublicEvidence => ownerInput is not null,
            _ => false
        };
        if (!bound)
        {
            throw new DeterministicValidationException(
                $"Evidence '{record.StableId}' structured protocol is not bound to a compatible confirmed input.");
        }

        return BoundedIO.ReadAllBytes(
            SafePath.ResolveUnderRoot(root, basename, requireExisting: true, requireFile: true),
            ResourceLimits.SupplementalInputAggregateBytes,
            "structured evidence protocol");
    }

    private static ParsedProtocol ParseLifecycle(
        ReadOnlyMemory<byte> bytes,
        InputManifest input)
    {
        using var document = StrictJson.Parse(
            bytes,
            ResourceLimits.SupplementalInputAggregateBytes,
            "dynamic child lifecycle protocol");
        var root = document.RootElement;
        ContractJson.RequireProperties(root, "schema_version", "protocol", "operations");
        RequireProtocolHeader(root, "dynamic-child-lifecycle");
        var operations = ContractJson.Array(root, "operations")
            .EnumerateArray()
            .Select(ParseLifecycleOperation)
            .ToArray();
        if (!operations.Select(item => item.Operation)
                .SequenceEqual(LifecycleOperations, StringComparer.Ordinal))
        {
            throw new DeterministicValidationException(
                "Dynamic child lifecycle protocol must contain every required operation exactly once in canonical order.");
        }

        foreach (var operation in operations)
        {
            if (operation.Disposition == "observed")
            {
                if (operation.Outcome is not ("passed" or "failed") ||
                    operation.RawObservationDigest is null ||
                    operation.NotTestedReason is not null ||
                    !HasInputDigest(input, operation.RawObservationDigest, "raw-observation"))
                {
                    throw new DeterministicValidationException(
                        $"Lifecycle operation '{operation.Operation}' requires a digest-bound raw observation and passed/failed outcome.");
                }
            }
            else if (operation.Disposition == "not-tested")
            {
                if (operation.Outcome is not null ||
                    operation.RawObservationDigest is not null ||
                    !IsSubstantive(operation.NotTestedReason))
                {
                    throw new DeterministicValidationException(
                        $"Lifecycle operation '{operation.Operation}' requires an explicit not-tested reason.");
                }
            }
            else
            {
                throw new DeterministicValidationException(
                    $"Lifecycle operation '{operation.Operation}' has invalid disposition.");
            }
        }

        var canonical = SerializeLifecycle(operations);
        ContractJson.RequireCanonical(bytes.Span, canonical, "dynamic child lifecycle protocol");
        return new ParsedProtocol(
            LifecycleMethod,
            operations.ToDictionary(item => item.Operation, StringComparer.Ordinal),
            null);
    }

    private static LifecycleOperation ParseLifecycleOperation(JsonElement element)
    {
        ContractJson.RequireProperties(
            element,
            "operation",
            "disposition",
            "outcome",
            "raw_observation_sha256",
            "not_tested_reason");
        return new LifecycleOperation(
            ContractJson.String(element, "operation"),
            ContractJson.String(element, "disposition"),
            ContractJson.NullableString(element, "outcome"),
            ContractJson.NullableObject(element, "raw_observation_sha256") is { } digest
                ? ContractJson.Digest(digest)
                : null,
            ContractJson.NullableString(element, "not_tested_reason"));
    }

    private static byte[] SerializeLifecycle(IReadOnlyList<LifecycleOperation> operations) =>
        StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "dynamic-child-lifecycle");
            writer.WritePropertyName("operations");
            writer.WriteStartArray();
            foreach (var operation in operations)
            {
                writer.WriteStartObject();
                writer.WriteString("operation", operation.Operation);
                writer.WriteString("disposition", operation.Disposition);
                WriteNullable(writer, "outcome", operation.Outcome);
                writer.WritePropertyName("raw_observation_sha256");
                if (operation.RawObservationDigest is null)
                {
                    writer.WriteNullValue();
                }
                else
                {
                    WriteDigest(writer, operation.RawObservationDigest);
                }

                WriteNullable(writer, "not_tested_reason", operation.NotTestedReason);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        });

    private static ParsedProtocol ParseNoticeCoverage(
        ReadOnlyMemory<byte> bytes,
        InputManifest input)
    {
        using var document = StrictJson.Parse(
            bytes,
            ResourceLimits.SupplementalInputAggregateBytes,
            "notice coverage protocol");
        var root = document.RootElement;
        ContractJson.RequireProperties(
            root,
            "schema_version",
            "protocol",
            "coverage",
            "dependency_inventory_sha256",
            "bundled_asset_inventory_sha256",
            "notice_mapping_sha256");
        RequireProtocolHeader(root, "notice-coverage");
        var coverage = ContractJson.String(root, "coverage");
        var dependencies = ContractJson.Digest(
            ContractJson.Object(root, "dependency_inventory_sha256"));
        var assets = ContractJson.Digest(
            ContractJson.Object(root, "bundled_asset_inventory_sha256"));
        var mapping = ContractJson.Digest(
            ContractJson.Object(root, "notice_mapping_sha256"));
        if (coverage is not ("complete" or "incomplete") ||
            !HasInputDigest(input, dependencies, "dependency-inventory") ||
            !HasInputDigest(input, assets, "bundled-asset-inventory") ||
            !HasInputDigest(input, mapping, "notice-mapping"))
        {
            throw new DeterministicValidationException(
                "Notice coverage verification requires dependency, bundled-asset, and notice-mapping inputs plus a complete/incomplete disposition.");
        }

        var canonical = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "notice-coverage");
            writer.WriteString("coverage", coverage);
            WriteDigest(writer, "dependency_inventory_sha256", dependencies);
            WriteDigest(writer, "bundled_asset_inventory_sha256", assets);
            WriteDigest(writer, "notice_mapping_sha256", mapping);
            writer.WriteEndObject();
        });
        ContractJson.RequireCanonical(bytes.Span, canonical, "notice coverage protocol");
        return new ParsedProtocol(NoticeCoverageMethod, null, coverage);
    }

    private static ParsedProtocol ParseAuthenticode(
        string rootPath,
        ReadOnlyMemory<byte> bytes,
        InputManifest input)
    {
        using var document = StrictJson.Parse(
            bytes,
            ResourceLimits.SupplementalInputAggregateBytes,
            "Authenticode verification protocol");
        var root = document.RootElement;
        ContractJson.RequireProperties(root, "schema_version", "protocol", "artifacts");
        RequireProtocolHeader(root, "authenticode-verification");
        var artifacts = ContractJson.Array(root, "artifacts")
            .EnumerateArray()
            .Select(ParseAuthenticodeArtifact)
            .ToArray();
        var packagePath = SafePath.ResolveUnderRoot(
            rootPath,
            input.Package.NupkgPath,
            requireExisting: true,
            requireFile: true);
        var expectedEntries = NupkgInspector.GetFileEntryDigests(packagePath, ".dll");
        if (expectedEntries.Count == 0 ||
            !artifacts.Select(item => item.PackageEntry)
                .SequenceEqual(expectedEntries.Keys, StringComparer.Ordinal))
        {
            throw new DeterministicValidationException(
                "Authenticode verification must cover every shipped DLL package entry exactly once.");
        }

        var passed = true;
        foreach (var artifact in artifacts)
        {
            if (artifact.ArtifactDigest.Value != expectedEntries[artifact.PackageEntry] ||
                !IsSubstantive(artifact.ExpectedIdentity) ||
                !HasText(artifact.ObservedIdentity, 3) ||
                artifact.FileDigestDisposition is not ("valid" or "invalid") ||
                artifact.ChainDisposition is not ("valid" or "invalid" or "not-tested") ||
                artifact.TimestampDisposition is not ("valid" or "invalid" or "not-applicable" or "not-tested") ||
                artifact.RevocationDisposition is not ("valid" or "invalid" or "not-applicable" or "not-tested") ||
                !HasInputDigest(input, artifact.RawObservationDigest, "authenticode-log"))
            {
                throw new DeterministicValidationException(
                    $"Authenticode verification for '{artifact.PackageEntry}' is malformed or lacks a digest-bound raw verification log.");
            }

            passed &= artifact.ExpectedIdentity == artifact.ObservedIdentity &&
                artifact.FileDigestDisposition == "valid" &&
                artifact.ChainDisposition == "valid" &&
                artifact.TimestampDisposition is "valid" or "not-applicable" &&
                artifact.RevocationDisposition is "valid" or "not-applicable";
        }

        var canonical = SerializeAuthenticode(artifacts);
        ContractJson.RequireCanonical(bytes.Span, canonical, "Authenticode verification protocol");
        return new ParsedProtocol(AuthenticodeMethod, null, passed ? "passed" : "failed");
    }

    private static AuthenticodeArtifact ParseAuthenticodeArtifact(JsonElement element)
    {
        ContractJson.RequireProperties(
            element,
            "package_entry",
            "artifact_sha256",
            "expected_identity",
            "observed_identity",
            "file_digest_disposition",
            "chain_disposition",
            "timestamp_disposition",
            "revocation_disposition",
            "raw_observation_sha256");
        return new AuthenticodeArtifact(
            Canonicalization.RelativePath(
                ContractJson.String(element, "package_entry"),
                "Authenticode package entry"),
            ContractJson.Digest(ContractJson.Object(element, "artifact_sha256")),
            ContractJson.String(element, "expected_identity"),
            ContractJson.String(element, "observed_identity"),
            ContractJson.String(element, "file_digest_disposition"),
            ContractJson.String(element, "chain_disposition"),
            ContractJson.String(element, "timestamp_disposition"),
            ContractJson.String(element, "revocation_disposition"),
            ContractJson.Digest(ContractJson.Object(element, "raw_observation_sha256")));
    }

    private static byte[] SerializeAuthenticode(IReadOnlyList<AuthenticodeArtifact> artifacts) =>
        StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "authenticode-verification");
            writer.WritePropertyName("artifacts");
            writer.WriteStartArray();
            foreach (var artifact in artifacts)
            {
                writer.WriteStartObject();
                writer.WriteString("package_entry", artifact.PackageEntry);
                WriteDigest(writer, "artifact_sha256", artifact.ArtifactDigest);
                writer.WriteString("expected_identity", artifact.ExpectedIdentity);
                writer.WriteString("observed_identity", artifact.ObservedIdentity);
                writer.WriteString("file_digest_disposition", artifact.FileDigestDisposition);
                writer.WriteString("chain_disposition", artifact.ChainDisposition);
                writer.WriteString("timestamp_disposition", artifact.TimestampDisposition);
                writer.WriteString("revocation_disposition", artifact.RevocationDisposition);
                WriteDigest(writer, "raw_observation_sha256", artifact.RawObservationDigest);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        });

    private static ParsedProtocol ParseSupportOwnership(ReadOnlyMemory<byte> bytes)
    {
        using var document = StrictJson.Parse(
            bytes,
            ResourceLimits.SupplementalInputAggregateBytes,
            "support ownership protocol");
        var root = document.RootElement;
        ContractJson.RequireProperties(
            root,
            "schema_version",
            "protocol",
            "accountable_role",
            "accountable_owner",
            "scope",
            "backup_owner",
            "escalation_path",
            "effective_at_utc");
        RequireProtocolHeader(root, "support-ownership");
        var values = new[]
        {
            ContractJson.String(root, "accountable_role"),
            ContractJson.String(root, "accountable_owner"),
            ContractJson.String(root, "scope"),
            ContractJson.String(root, "backup_owner"),
            ContractJson.String(root, "escalation_path")
        };
        if (values.Any(value => !IsSubstantive(value)) ||
            !DateTimeOffset.TryParse(
                ContractJson.String(root, "effective_at_utc"),
                out var effective) ||
            effective.Offset != TimeSpan.Zero)
        {
            throw new DeterministicValidationException(
                "Support ownership verification requires accountable role/owner, scope, backup, escalation, and a UTC effective time.");
        }

        var canonical = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "support-ownership");
            writer.WriteString("accountable_role", values[0]);
            writer.WriteString("accountable_owner", values[1]);
            writer.WriteString("scope", values[2]);
            writer.WriteString("backup_owner", values[3]);
            writer.WriteString("escalation_path", values[4]);
            writer.WriteString(
                "effective_at_utc",
                effective.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"));
            writer.WriteEndObject();
        });
        ContractJson.RequireCanonical(bytes.Span, canonical, "support ownership protocol");
        return new ParsedProtocol(SupportOwnershipMethod, null, null);
    }

    private static ParsedProtocol ParseToolchain(
        ReadOnlyMemory<byte> bytes,
        InputManifest input)
    {
        using var document = StrictJson.Parse(
            bytes,
            ResourceLimits.SupplementalInputAggregateBytes,
            "toolchain probe protocol");
        var root = document.RootElement;
        ContractJson.RequireProperties(
            root,
            "schema_version",
            "protocol",
            "toolchain_name",
            "toolchain_version",
            "target_framework",
            "support_disposition",
            "command",
            "result",
            "raw_log_sha256");
        RequireProtocolHeader(root, "toolchain-probe");
        var name = ContractJson.String(root, "toolchain_name");
        var version = ContractJson.String(root, "toolchain_version");
        var framework = ContractJson.String(root, "target_framework");
        var support = ContractJson.String(root, "support_disposition");
        var command = ContractJson.String(root, "command");
        var result = ContractJson.String(root, "result");
        var rawLog = ContractJson.Digest(ContractJson.Object(root, "raw_log_sha256"));
        if (!HasText(name, 3) ||
            !HasText(version, 3) ||
            !HasText(framework, 3) ||
            !IsSubstantive(command) ||
            support != "supported" ||
            result is not ("passed" or "failed") ||
            !HasInputDigest(input, rawLog, "toolchain-log"))
        {
            throw new DeterministicValidationException(
                "Toolchain probe verification requires a supported named toolchain, target framework, command, result, and digest-bound raw log.");
        }

        var canonical = StrictJson.SerializeCanonical(writer =>
        {
            writer.WriteStartObject();
            writer.WriteNumber("schema_version", 1);
            writer.WriteString("protocol", "toolchain-probe");
            writer.WriteString("toolchain_name", name);
            writer.WriteString("toolchain_version", version);
            writer.WriteString("target_framework", framework);
            writer.WriteString("support_disposition", support);
            writer.WriteString("command", command);
            writer.WriteString("result", result);
            WriteDigest(writer, "raw_log_sha256", rawLog);
            writer.WriteEndObject();
        });
        ContractJson.RequireCanonical(bytes.Span, canonical, "toolchain probe protocol");
        return new ParsedProtocol(ToolchainMethod, null, result);
    }

    private static void ValidateLifecycle(
        ReadinessAssessment assessment,
        InputManifest input,
        IReadOnlyDictionary<string, EvidenceRecord> records,
        IReadOnlyDictionary<string, ParsedProtocol> protocols)
    {
        if (assessment.Identity.ComponentId is null)
        {
            return;
        }

        var component = input.Components.Single(item =>
            item.Id == assessment.Identity.ComponentId);
        var lifecycleProtocols = protocols
            .Where(item =>
                item.Value.Method == LifecycleMethod &&
                records[item.Key].Applicability.Scope == "component-specific" &&
                records[item.Key].Applicability.ComponentId == component.Id)
            .ToArray();
        if (component.DynamicChildLifecycle.Applicability == "not-applicable")
        {
            if (lifecycleProtocols.Length != 0)
            {
                throw new DeterministicValidationException(
                    "A component marked dynamic-child not-applicable cannot select a lifecycle protocol.");
            }

            return;
        }

        if (lifecycleProtocols.Length != 1)
        {
            throw new DeterministicValidationException(
                "A component with grouped, registered, selected, or composite children requires exactly one dynamic lifecycle protocol.");
        }

        var protocolId = lifecycleProtocols[0].Key;
        var operations = lifecycleProtocols[0].Value.Operations!;
        foreach (var (rowId, operationNames) in LifecycleRows)
        {
            var row = assessment.Rows.SingleOrDefault(item => item.Id == rowId);
            if (row is null || row.Status is null)
            {
                continue;
            }

            if (!row.EvidenceIds.Contains(protocolId, StringComparer.Ordinal))
            {
                throw new DeterministicValidationException(
                    $"Lifecycle row '{rowId}' must cite the selected dynamic lifecycle protocol.");
            }

            var relevant = operationNames.Select(name => operations[name]).ToArray();
            switch (row.Status)
            {
                case "verified" when relevant.Any(item =>
                    item.Disposition != "observed" || item.Outcome != "passed"):
                    throw new DeterministicValidationException(
                        $"Lifecycle row '{rowId}' cannot be verified without passed raw observations for every applicable operation.");
                case "gap" when !relevant.Any(item =>
                    item.Disposition == "observed" && item.Outcome == "failed"):
                    throw new DeterministicValidationException(
                        $"Lifecycle row '{rowId}' cannot be a gap without an observed failed operation.");
                case "not tested" when !relevant.Any(item =>
                    item.Disposition == "not-tested"):
                    throw new DeterministicValidationException(
                        $"Lifecycle row '{rowId}' cannot be not tested without an operation-specific blocker.");
                case "not tested" when !IsSubstantive(row.Observation):
                    throw new DeterministicValidationException(
                        $"Lifecycle row '{rowId}' not tested status requires the exact blocker in observation.");
                case "not applicable" or "owner evidence required":
                    throw new DeterministicValidationException(
                        $"Lifecycle row '{rowId}' must resolve to verified, gap, or not tested for an applicable dynamic-child control.");
            }
        }
    }

    private static void RequireProtocolForVerifiedRow(
        ReadinessAssessment assessment,
        IReadOnlyDictionary<string, EvidenceRecord> records,
        IReadOnlyDictionary<string, ParsedProtocol> protocols,
        string rowId,
        string method)
    {
        var row = assessment.Rows.SingleOrDefault(item => item.Id == rowId);
        if (row?.Status != "verified")
        {
            return;
        }

        var matches = row.EvidenceIds.Where(id =>
            protocols.TryGetValue(id, out var protocol) &&
            protocol.Method == method &&
            records[id].Applicability.Scope == row.Scope).ToArray();
        if (matches.Length == 0)
        {
            throw new DeterministicValidationException(
                $"Row '{rowId}' verified status requires structured '{method}' evidence.");
        }
    }

    private static void RequireProtocolForOutcomeRow(
        ReadinessAssessment assessment,
        IReadOnlyDictionary<string, EvidenceRecord> records,
        IReadOnlyDictionary<string, ParsedProtocol> protocols,
        string rowId,
        string method,
        string verifiedResult,
        string gapResult)
    {
        var row = assessment.Rows.SingleOrDefault(item => item.Id == rowId);
        if (row?.Status is not ("verified" or "gap"))
        {
            return;
        }

        var expectedResult = row.Status == "verified" ? verifiedResult : gapResult;
        if (!row.EvidenceIds.Any(id =>
                protocols.TryGetValue(id, out var protocol) &&
                protocol.Method == method &&
                protocol.Result == expectedResult &&
                records[id].Applicability.Scope == row.Scope))
        {
            throw new DeterministicValidationException(
                $"Row '{rowId}' status '{row.Status}' requires structured '{method}' evidence with result '{expectedResult}'.");
        }
    }

    private static void ValidateToolchainRows(
        ReadinessAssessment assessment,
        InputManifest input,
        IReadOnlyDictionary<string, EvidenceRecord> records,
        IReadOnlyDictionary<string, ParsedProtocol> protocols)
    {
        if (!input.EvidenceInputs.Any(item => item.Kind == "toolchain-log"))
        {
            return;
        }

        foreach (var rowId in new[] { "TA-02", "TA-04" })
        {
            var row = assessment.Rows.SingleOrDefault(item => item.Id == rowId);
            if (row?.Status is null)
            {
                continue;
            }

            if (row.Status == "not tested")
            {
                if (!IsSubstantive(row.Observation))
                {
                    throw new DeterministicValidationException(
                        $"Row '{rowId}' not tested status requires the exact toolchain blocker in observation.");
                }

                continue;
            }

            if (row.Status is not ("verified" or "gap"))
            {
                continue;
            }

            var matching = row.EvidenceIds
                .Where(id =>
                    records.ContainsKey(id) &&
                    protocols.TryGetValue(id, out var protocol) &&
                    protocol.Method == ToolchainMethod)
                .Select(id => protocols[id])
                .ToArray();
            var expectedResult = row.Status == "verified" ? "passed" : "failed";
            if (!matching.Any(protocol => protocol.Result == expectedResult))
            {
                throw new DeterministicValidationException(
                    $"Row '{rowId}' status '{row.Status}' requires a supported named-toolchain protocol with result '{expectedResult}'.");
            }
        }
    }

    private static void RequireProtocolHeader(JsonElement root, string expectedProtocol)
    {
        if (ContractJson.Int32(root, "schema_version") != 1 ||
            ContractJson.String(root, "protocol") != expectedProtocol)
        {
            throw new DeterministicValidationException(
                $"Structured evidence protocol must be '{expectedProtocol}' schema version 1.");
        }
    }

    private static bool HasInputDigest(
        InputManifest input,
        Sha256Digest digest,
        string kind) =>
        input.EvidenceInputs.Any(item =>
            item.Kind == kind &&
            item.ContentDigest == digest);

    private static bool IsSubstantive(string? value) =>
        HasText(value, 8);

    private static bool HasText(string? value, int minimumLength) =>
        value is not null &&
        ContractJson.NormalizeText(value, "structured evidence value", 4096).Length >= minimumLength;

    private static void WriteDigest(
        Utf8JsonWriter writer,
        string property,
        Sha256Digest digest)
    {
        writer.WritePropertyName(property);
        WriteDigest(writer, digest);
    }

    private static void WriteDigest(Utf8JsonWriter writer, Sha256Digest digest)
    {
        writer.WriteStartObject();
        writer.WriteString("algorithm", digest.Algorithm);
        writer.WriteString("value", digest.Value);
        writer.WriteEndObject();
    }

    private static void WriteNullable(
        Utf8JsonWriter writer,
        string property,
        string? value)
    {
        if (value is null)
        {
            writer.WriteNull(property);
        }
        else
        {
            writer.WriteString(property, value);
        }
    }

    private sealed record LifecycleOperation(
        string Operation,
        string Disposition,
        string? Outcome,
        Sha256Digest? RawObservationDigest,
        string? NotTestedReason);

    private sealed record AuthenticodeArtifact(
        string PackageEntry,
        Sha256Digest ArtifactDigest,
        string ExpectedIdentity,
        string ObservedIdentity,
        string FileDigestDisposition,
        string ChainDisposition,
        string TimestampDisposition,
        string RevocationDisposition,
        Sha256Digest RawObservationDigest);

    private sealed record ParsedProtocol(
        string Method,
        IReadOnlyDictionary<string, LifecycleOperation>? Operations,
        string? Result);
}
