using System.Text.Json;
using BlazorComponentReadiness.Validator.Contracts;
using BlazorComponentReadiness.Validator.IO;

namespace BlazorComponentReadiness.Validator.Assessment;

public static class AssessmentDraftDecisionService
{
    public const int SchemaVersion = 1;

    public static AssessmentDraftDecisions Parse(ReadOnlyMemory<byte> bytes)
    {
        using var document = StrictJson.Parse(
            bytes,
            ResourceLimits.SerializedArtifactBytes,
            "assessment draft decisions");
        var root = document.RootElement;
        ContractJson.RequirePropertiesUnordered(
            root,
            "schema_version",
            "rows",
            "findings",
            "summary_groups",
            "completion_state");
        var decisions = new AssessmentDraftDecisions(
            ContractJson.Int32(root, "schema_version"),
            ContractJson.Array(root, "rows").EnumerateArray().Select(ParseRow).ToArray(),
            ContractJson.Array(root, "findings").EnumerateArray().Select(ParseFinding).ToArray(),
            ContractJson.Array(root, "summary_groups").EnumerateArray().Select(ParseSummary).ToArray(),
            ContractJson.String(root, "completion_state"));
        if (decisions.SchemaVersion != SchemaVersion)
        {
            throw new DeterministicValidationException(
                $"Assessment draft decisions schema must be {SchemaVersion}.");
        }

        return decisions;
    }

    public static ReadinessAssessment Apply(
        ReadinessAssessment assessment,
        AssessmentDraftDecisions decisions)
    {
        var rubric = AssessmentService.RequireCurrentContract(assessment);
        if (!AssessmentService.CompletionStates.Contains(decisions.CompletionState, StringComparer.Ordinal))
        {
            throw new DeterministicValidationException(
                $"Unknown assessment completion state '{decisions.CompletionState}'.");
        }

        var duplicate = decisions.Rows
            .GroupBy(row => row.Id, StringComparer.Ordinal)
            .FirstOrDefault(group => group.Count() != 1);
        if (duplicate is not null)
        {
            throw new DeterministicValidationException(
                $"Assessment draft decisions contain duplicate row '{duplicate.Key}'.");
        }

        var expectedIds = assessment.Rows.Select(row => row.Id).ToHashSet(StringComparer.Ordinal);
        var unknown = decisions.Rows.FirstOrDefault(row => !expectedIds.Contains(row.Id));
        if (unknown is not null)
        {
            throw new DeterministicValidationException(
                $"Assessment draft decisions contain unknown row '{unknown.Id}'.");
        }

        foreach (var row in decisions.Rows)
        {
            if (!rubric.Statuses.Contains(row.Status, StringComparer.Ordinal))
            {
                throw new DeterministicValidationException(
                    $"Assessment draft decision '{row.Id}' has unknown status '{row.Status}'.");
            }
        }

        var updates = decisions.Rows.ToDictionary(row => row.Id, StringComparer.Ordinal);
        return assessment with
        {
            Rows = assessment.Rows.Select(row =>
            {
                if (!updates.TryGetValue(row.Id, out var update))
                {
                    return row;
                }

                return row with
                {
                    Status = update.Status,
                    Observation = update.Observation,
                    EvidenceIds = update.EvidenceIds,
                    OwnerAction = update.OwnerAction,
                    AssessmentFollowUp = update.AssessmentFollowUp,
                    NotApplicableRationale = update.NotApplicableRationale
                };
            }).ToArray(),
            Findings = decisions.Findings,
            SummaryGroups = decisions.SummaryGroups,
            CompletionState = decisions.CompletionState
        };
    }

    private static AssessmentRowDecision ParseRow(JsonElement element)
    {
        ContractJson.RequirePropertiesUnordered(
            element,
            "id",
            "status",
            "observation",
            "evidence_ids",
            "owner_action",
            "assessment_follow_up",
            "not_applicable_rationale");
        return new AssessmentRowDecision(
            ContractJson.String(element, "id"),
            ContractJson.String(element, "status"),
            ContractJson.String(element, "observation"),
            ContractJson.StringArray(element, "evidence_ids"),
            ContractJson.NullableString(element, "owner_action"),
            ContractJson.NullableString(element, "assessment_follow_up"),
            ContractJson.NullableString(element, "not_applicable_rationale"));
    }

    private static AssessmentFinding ParseFinding(JsonElement element)
    {
        ContractJson.RequirePropertiesUnordered(
            element,
            "title",
            "factual_summary",
            "requirement_ids",
            "evidence_ids");
        return new AssessmentFinding(
            ContractJson.String(element, "title"),
            ContractJson.String(element, "factual_summary"),
            ContractJson.StringArray(element, "requirement_ids"),
            ContractJson.StringArray(element, "evidence_ids"));
    }

    private static AssessmentSummaryGroup ParseSummary(JsonElement element)
    {
        ContractJson.RequirePropertiesUnordered(
            element,
            "name",
            "factual_summary",
            "requirement_ids",
            "evidence_ids");
        return new AssessmentSummaryGroup(
            ContractJson.String(element, "name"),
            ContractJson.String(element, "factual_summary"),
            ContractJson.StringArray(element, "requirement_ids"),
            ContractJson.StringArray(element, "evidence_ids"));
    }
}
