# Offline resolver handoff for package-based assessments

The sibling skill `blazor-package-readiness-resolver` owns
deterministic package/evidence dispatch. Load it before interpreting results; it is shipped
in the same plugin. Direct JSON-only resolver requests belong there, not to the full-report
workflow.

1. Use the approved exact local `.nupkg`. Invoke the sibling's
   `scripts/run-resolver.py package <path>` or `resolve <request.json>` with supplied checked
   packet files. No acquisition, dependency restore, package build or assessed-code execution.
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
5. The existing typed input producer accepts supplemental `document` evidence. Register the
   retained JSON as a document using [input candidates](input-candidates.md), preserve its
   capture metadata/byte digest and confirm a **new** input revision before building evidence
   and assessment records. Cite exact row/result/input references in the deciding evidence.
   Resolver output has no special trusted evidence kind and bypasses no confirmation.
6. Continue the [assessment workflow](assessment-workflow.md) for all selected report rows.
   The resolver implements only 11 of 60 package rows and no component-specific row.
   Never manufacture completion, legal correctness, release approval or certification.

The canonical rubric and basis are shared with the sibling resolver's `scripts/resolver/data/`
directory; the report validator reads those exact digest-pinned bytes. A broken plugin
installation is an explicit failure, never an arbitrary host-checkout fallback.
