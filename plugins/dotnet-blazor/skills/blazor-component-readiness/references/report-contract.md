# Report and validation-manifest contract

JSON is canonical. Markdown is generated only by the bundled validator and an earlier revision is
never overwritten.

## Revision layout

Use `revisions/0001`, `0002`, and so on. Each directory contains exactly:

- `input-manifest.json`
- `<kind>.assessment.json`
- `<kind>.evidence.json`
- `<kind>.report.md`
- `<kind>.validation.json`

`<kind>` is `unified`, `package`, or `component`. Revision `0001` has no predecessor. Each later
revision binds the immediately preceding validation-manifest digest and cannot skip or reuse a
sequence. A package/version or confirmed-inventory change starts a new root.

## Assessment rows

Every selected row preserves rubric order and contains its ID, rubric-owned scope/area/wording,
one exact status or an incomplete value, factual observation, selected evidence IDs, owner action,
assessment follow-up, and a rationale when not applicable. Findings and summary groups are factual,
unranked, and traceable to selected rows/evidence.

New assessments use schema version 2 and enforce the current typed public-absence/source-proof
rules. Schema-version-1 assessments remain parseable and verifiable with their legacy evidence
rules so immutable historical revisions and predecessor chains do not retroactively fail. Revision
chains may upgrade from v1 to v2 during an evidence-backed correction, but cannot downgrade or skip
schema generations.

The generated report includes:

1. completion state and exact package/component/rubric identity;
2. assessment inputs, retrieval attempts, source availability, source-artifact captures, documents,
   owner inputs, confirmed inventory, modes, and exclusions;
3. counts for all five statuses plus incomplete;
4. factual summaries/findings;
5. optional feedback rendered verbatim;
6. the complete canonical requirements table;
7. fixed limitations distinguishing structural validation from factual truth.

The canonical table header is:

```text
| ID | Scope | Area | Requirement | Status | Factual observation | Evidence and provenance | Owner action | Assessment follow-up / rationale |
```

## Validation manifest

The manifest binds plugin/validator/renderer versions; rubric, scope-map, and selected-overlay
digests; input, assessment, evidence, and report digests; selected evidence IDs; assessment kind and
completion state; package assessment/report bindings for component work; optional feedback digest;
and optional predecessor plus declared changed IDs.

It is tamper-evident but unsigned. It proves byte correspondence, not authorship, factual accuracy,
approval, certification, or suitability.

Run `assessment validate` before `report render`, then `report verify` on the created revision.
Reject an extra byte, stale feedback, wrong package binding, missing selected evidence, changed
identity, evidence not bound to confirmed input bytes, linked revision/artifact paths, mutable
earlier revision, or unverified handoff.

## Decision guidance

The default report remains factual. Only after an explicit verdict/prioritization/remediation/next
steps request, create `decision-guidance.md` beside the relevant feedback file and outside
`revisions/`.

Its first metadata block must include:

```text
Source validation manifest SHA-256: <64-lowercase-hex>
```

Guidance is an unbound, regenerable derivative of exactly that validated revision. It may state the
requested verdict and priorities, but cannot change or supplement canonical facts, rows, evidence,
counts, reports, or manifests. Replace it only after another explicit guidance request.
