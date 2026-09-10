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

When optional feedback context is supplied, retain a separate readable companion beside the
feedback source or report. It may summarize each relevant item as `changed`, `qualified`, or
`unchanged`, identify unmapped or ambiguous entries, preserve attribution and source links, and
explain whether the item was context only or supported an evidence-backed correction. Do not place
free-form source prose into the canonical feedback table, mutate immutable revisions, or treat
feedback-only commentary as evidence. The companion is supplemental and does not replace the
canonical report or validation manifest.

The canonical table header is:

```text
| ID | Scope | Area | Requirement | Status | Factual observation | Evidence and provenance | Owner action | Assessment follow-up / rationale |
```

## Validation manifest

### Readable projection

After canonical verification, the [partner-preview reader](partner-preview.md) is the default
local delivery view. `reader render` and `reader verify` produce and check a separate derived
directory; `report render`, `report verify`, canonical bytes and five-file revisions are unchanged.
Its four-column table groups only existing rubric facts and retains each check's exact result,
qualifications, ownership and evidence. `mapping.json` preserves the internal check mapping;
the reader manifest binds the exact source validation digest, rubric, optional package binding
and every derived file. Invalid projection or unavailable private inputs must fall back to the
canonical local report with the reader limitation explicitly reported, never an unverified rewrite.

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

### Explicitly authorized package-scope recovery

The validator supports one independently pinned recovery manifest, not an arbitrary requirement-ID
filter. Ordinary package and component behavior is unchanged when no explicit scope/profile input
is present.
Register the supplied canonical `authorized-package-report-scope.json` as an existing
`evidence_inputs` entry of kind `authorized-package-report-scope`, and register its exact frozen
requirements DOCX as another retained evidence input. For candidate intake, the entries use the
existing `path` and `kind` fields; discovery/confirmation binds their basename, size and SHA-256.
Keep both files beneath the input root. Do not reconstruct or edit the approved manifest.

Initialization, validation, report verification and the reader recognize that retained entry
automatically. There is no ID-list switch to omit later or use as a fallback. Empty, malformed,
unsupported, duplicated or altered scope inputs fail closed, as do wrong document/package
identities and any mismatch in the exact approved canonical selection, count or selected-set digest.
The manifest's authorization claims alone do not establish authority: its exact digest must match
the approval pinned in the validator.

Existing schemas carry the scope transitively through the confirmed input digest, assessment
selection, evidence identity, report/receipt hashes and reader file hashes. Every consumer resolves
the manifest and checks those bindings. The report declares the frozen DOCX and scope identities;
the reader also retains the canonical scope manifest. The frozen rubric scope-map digest keeps its
original meaning and is not replaced by the selected-set digest. Completion refers only to the
authorized selection; it does not establish ordinary full-package coverage or satisfy a component
assessment's full-package prerequisite.

The authorized evidence companion must contain only selected records. Preserve full historical
ledgers separately; do not crop and relabel an original ledger. A new confirmed input changes
evidence identity and therefore requires a new, accurately attributed evidence-backed revision,
not an unchanged-reuse claim. Within a scoped revision lineage, a changed finding requires new
evidence even when its status token did not change.

The scoped partner reader does not export underlying raw evidence attachments, which may contain
internal historical findings. It preserves selected claims, methods, locators, identities and
qualifications, and states that source bytes remain in the local validation inputs. It must not
fall back to copying historical reports, unselected ledger records or archives. Excluded identifiers,
known extension text and broader-coverage claims are rejected in the selected outputs; the final
human/agent usefulness review must additionally detect paraphrased or semantically unrelated
content. Missing bound feedback cannot bypass scoped report verification. A failed scoped reader
is a blocked deliverable, not authorization to publish an unscoped fallback.

### DOCX-only component profile (V1)

This explicitly selected profile uses all 51 component-specific, non-extension checks from frozen
rubric `2.0.0`. It preserves every ID, requirement, ownership, area, primary/additional clause,
and canonical position. The ordered compact ID-array SHA-256 is
`2f0c862398f58aa0cef426cb8a2b4c46fa33e2d907a294bd46d7f1fa3b1f4122`.
There is no caller-defined subset, replacement with clause-level rows, or automatic authority
grant from profile metadata.

Register these retained inputs through the existing candidate builder and confirmation flow:

| Input | Evidence-input kind | Meaning |
|---|---|---|
| Byte-identical `docx-crosswalk.json` from the loaded skill | `docx-component-profile-v1` | Selects the closed V1 validation policy and binds the frozen DOCX/rubric source. |
| Frozen `blazor-partner-components-requirements.docx` | A normal bound requirements-document input | Exact source bytes must match the crosswalk's document identity. |
| Byte-identical scoped package validation receipt, staged as `scoped-package.validation.json` | `scoped-package-context-v1` | Binds the separate package context by digest, not by an assertion of full coverage. |

Use `--package-context-revision` to locate the exact staged package revision on assessment,
report, and reader commands. The locator is not authority: the revision, scope, required internal
closure, package/source identities, and receipt digest must agree with the confirmed input.
An ordinary `--package-revision` remains the full-package path and cannot be substituted.
Missing, orphan, altered, unknown, or conflicting profile/context inputs fail closed.
When the context revision binds feedback, provide its exact bytes with
`--package-context-feedback`. This verifies the context's receipt; it is not component feedback
and is not copied into the component reader. V1 rejects ordinary `--package-feedback`.

Source equality here means the entire `source` record: availability, repository URI, commit,
mapping, and confidence, not just the repository/commit pair. Preserve that record when reusing
the same still-valid context; place new investigation/reuse narrative in separate retrieval or
assessment context. A materially different source claim requires a valid new binding, not a
prose edit to a confirmed manifest or a relaxed equality check.

For this profile, `package_reference` remains null in both the component assessment and validation
manifest: no ordinary full-package prerequisite is asserted. The typed scoped context is bound
through the confirmed input identity and its distinct descriptor. Reader
`package_validation_sha256` also remains null. Do not reinterpret these ordinary fields as scoped
context, reuse the package findings as component findings, or use this profile for ordinary library
completion. The existing 48-check recovery and ordinary/legacy contracts remain unchanged.

Initialization, validation, verification, corrections, and publication rechecks must all resolve
the same bound profile/context policy. Changed input/context identities follow the existing
fresh-binding and lineage rules; a changed locator alone cannot replace a bound context.
V1 does not use the ordinary historical missing-feedback fallback: a feedback-bound predecessor
requires its exact feedback bytes and report reconstruction. If those bytes are unavailable,
verification fails rather than treating a matching report hash as sufficient.

Keep the complete canonical-verification set internally, including all exact ledgers and dependency
inputs required by the existing contracts. A selected-only component companion is allowed only when
constructed and verified through existing mechanisms with correct identities and provenance.
Never crop an original historical ledger and relabel it under its original identity.
When a valid selected record requires an unexported supersession ancestor, the reader may omit
the structured selected-only companion rather than manufacture an invalid partial bundle.
Its existing evidence view must retain the selected record's identity, applicability, provenance,
digests, and supersession references, and explicitly disclose the omitted companion and internal
dependency. Invalid canonical evidence still fails; this is not a general validation-error fallback.

The V1 reader/export set is narrower: no raw registered inputs or attachments, full crosswalk/DOCX,
historical ledgers/reports, context-receipt payloads, or package/source archives are exported merely
because they were registered. Enforce disclosure rules across prose, summaries, mapping, technical
JSON, evidence companions, provenance, feedback, attachments, and fallbacks. Exact canonical copies
must stay byte-identical and disclosure-permitted, not secretly filtered. A scope/disclosure failure
does not authorize an unscoped export or weaker evidence validation.

The exported reader is **not a self-contained evidence-validation bundle**. Re-verification that
needs omitted inputs depends on the retained internal workspace. Accurately distinguish internally
retained-but-unexported bytes from unavailable or commitment-only evidence; hashes and references
do not imply attachment delivery. Mentioning an excluded ID does not itself assess that check, but
separate disclosure prohibitions still apply. Reader grouping preserves all individual statuses,
evidence references and qualifications, including mixed results and explicit missing evidence.

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
