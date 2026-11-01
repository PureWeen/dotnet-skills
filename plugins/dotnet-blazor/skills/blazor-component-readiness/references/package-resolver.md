# Offline resolver handoff for package-based assessments

The sibling skill `blazor-package-readiness-resolver` owns
deterministic package/evidence dispatch. In a full plugin installation, load it before
interpreting results. Direct JSON-only resolver requests belong there, not to the full-report
workflow. A single-skill staging of this consumer intentionally does not include that sibling:
initialize the separate report from confirmed inputs, preserve unresolved static rows, and
state that resolver replay is unavailable. Do not invent JSON results, search an unrelated
checkout, download tools, or block the report's own input/assessment initialization.

For the full-plugin package workflow, use [eleven-row autofill](eleven-row-autofill.md).
It collects explicitly authorized inputs, invokes both offline tools, and constructs the eleven
canonical row decisions and evidence through the existing producers. Do not translate those
results again in model prose. Continue the other 49 rows and check preservation of the eleven.
The manual sequence below remains available for individually scoped evidence work and diagnostics;
it does not authorize bypassing the autofill's unknown-branch or changed-tool failures.

1. Use the approved exact local `.nupkg`. Invoke the sibling's
   `scripts/run-resolver.py package <path>` or `resolve <request.json>` with supplied checked
   packet files. The resolver is offline: no acquisition, dependency restore, package build or
   assessed-code execution. This does not cancel the assessment's authorized
   [source/dependency acquisition](artifact-acquisition.md). Package-level scope is not a
   restriction to package-file-only evidence.
2. Retain the command, exit, exact JSON bytes and SHA-256 under the approved output root.
   Do not treat exit 0 as verification. Missing environment/bundled files or invalid input
   is an explicit blocker, not guessed evidence or a product gap.
3. Keep each complete row result and cited input digest. Do not reduce the result to its branch
   name: the `finding`, `evidence_contract`, applicability, missing fact and next category
   bound what it establishes. `escalated` means unresolved, not automatically a gap;
   owner routing applies only to a genuinely owner-private fact.
4. For the report's canonical row, use `verified` only for a qualified affirmative finding
   whose full mandatory conjunction is evidenced; `gap` only for the row's direct adverse
   finding; `not applicable` only for admitted no-applicable-surface. Otherwise retain
   `not tested` or `owner evidence required` with the exact deciding missing fact.
   Preserve stronger conjuncts from the report's status boundaries; no mapping by exit code
   or `decision` alone is allowed.
5. Before finalizing unresolved LP-01/02/03/04/10 observations, inspect the authorized retained
   source and exact dependency packages. When raw archives exist but admitted row packets do
   not, use the sibling's `inspect <inputs.json>` route and its
   [checked inspection contract](../../blazor-package-readiness-resolver/references/evidence-inspection.md).
   Preserve literal licenses/ranges, source/project/import facts and exact per-entry matches
   alongside the stronger missing facts. Do not label those present observations absent or
   discard them merely because the full row remains unresolved. The inspection packet does
   not attest anonymous retrieval, resolved closure, ownership, applicability or notice coverage.
   Do not relabel an old static graph as an admitted resolved export or invent a review/receipt.
6. The existing typed input producer accepts supplemental `document` evidence. Register the
   retained JSON as a document using [input candidates](input-candidates.md), preserve its
   capture metadata/byte digest and confirm a **new** input revision before building evidence
   and assessment records. Cite exact row/result/input references in the deciding evidence.
   Resolver output has no special trusted evidence kind and bypasses no confirmation.
7. After newly authorized source/dependency collection, run inspection on the new exact bytes;
   run `resolve` again only when the required admitted row packets actually exist. Reconfirm
   the supplemental outputs, then recompute affected provisional observations/statuses before
   finalizing. Preserve old outputs as evidence, not the current decision after inputs change.
8. Continue the [assessment workflow](assessment-workflow.md) for all selected report rows.
   The resolver implements only 11 of 60 package rows and no component-specific row.
   Never manufacture completion, legal correctness, release approval or certification.

The validator reads its own `references/rubric.json` and `references/requirement-basis.json`.
They are byte-exact generated copies of the resolver's canonical data, checked against frozen
digests at runtime. Repository version synchronization regenerates both copies and
`plugin-manifest.json`; generated copies are excluded from release-bearing content. Missing
or altered local assets fail explicitly. When a plugin manifest is installed, its snapshot
must match byte-for-byte; isolated staging uses the bundled snapshot without requiring a
parent manifest. No arbitrary host-checkout fallback is permitted.
