---
name: blazor-component-readiness
description: >-
  Assess released or release-candidate Blazor component packages or complete libraries for
  explicit vendor self-assessment, readiness, adoption, recommendation, or release decisions.
  Produces local JSON-first evidence, validated reports, and resumable library results. USE FOR:
  "assess this Blazor package", "is this component/library ready to adopt or release?", vendor
  readiness scorecards. DO NOT USE FOR: ordinary Blazor authoring/debugging, first-party framework
  review, generic NuGet help, CI/PR/issue triage, implementation-only work, or certification.
compatibility: Requires an active .NET 11 SDK; full-library mode requires top-level writable worker sessions.
---

# Blazor Component Readiness

## Outcome and safety boundary

Produce a bounded, evidence-backed self-assessment of an exact released or release-candidate
Blazor package. The June 26 requirements DOCX is normative for the partner correction profile;
its 121-ID operational crosswalk is not certification or a Microsoft acceptance decision.
Read local inputs and retrieve public inputs when needed; write only beneath the
user-approved local output root. Never modify the reviewed source tree or any remote system.

Deterministic validation proves artifact shape, canonical ordering, digests, and local byte
correspondence. It does not prove evidence truth, organizational approval, or release suitability.

## Applicability

Use for readiness assessment or revision of an exact Blazor package, component, or confirmed
library. Do not use for implementation, framework/repository work, certification, or cataloging.

## Prerequisites and required inputs

Require an active .NET 11 SDK. Ask before any machine-level installation. If .NET 11 is absent,
stop with an environment limitation; do not weaken the launcher isolation.

| Input | Required | Rule |
|---|---|---|
| Output root | Yes | User-approved local directory outside the reviewed repository. |
| Package | Yes | Exact published package/version or supplied release-candidate `.nupkg`; confirm identity and SHA-256. |
| Scope | Yes | One component, one package, or full library; full library requires confirmed inventory and isolated workers. |
| Components | Conditional | Unified/component/full-library require IDs/display names and every claimed mode; owner confirms before probes. Package-only may confirm `components: []`. |
| Source | Yes | Record `source-available`, `closed-source`, or `unresolved`; never infer closed source from retrieval failure. |
| Documentation | Yes | Discover official owner-controlled docs, package metadata/README, and source docs when available; owner confirms the set. |
| Dynamic children | Conditional | Declare whether the component groups, registers, selects, or composes children; required surfaces use the post-initialization lifecycle matrix. |
| Evidence inputs | Conditional | Confirm protocol documents and raw observation/log/inventory files by neutral basename, kind, size, and digest. |
| Owner evidence | Optional | Use `owner-supplied-internal-evidence` or `owner-supplied-public-evidence` with explicit provenance and digest; never treat feedback as evidence. |
| Feedback | Optional | Issue URL or Markdown; see [feedback contract](references/feedback-contract.md). |
| Exclusions/timebox | Optional | Record explicit exclusions and stop when the timebox expires. |

## Canonical contract

1. `references/rubric.json` is the source of current requirement IDs, wording, order, and
   60 `repository-wide` / 61 `component-specific` ownership split.
   The [crosswalk](references/docx-crosswalk.json) binds clause and basis; use the
   [crosswalk guide](references/docx-crosswalk.md) when interpreting those bindings. Each canonical ID
   occurs once across the pair. `TA-08` is noncanonical. Historical rubric bytes remain frozen.
   New assessments use rubric `2.0.0` and its 60+61 ownership split. Do not add
   `--rubric-version 1.3.0` unless the owner explicitly requests a legacy assessment or
   reproduction; a legacy selection for a current request is an invalid scope decision, not a
   harmless compatibility choice.
2. `references/checklist.md` is only the generated human-readable view. Never edit or derive IDs
   from it independently.
3. Use exactly: `verified`, `gap`, `owner evidence required`, `not tested`,
   `not applicable`. Follow [status boundaries](references/status-boundaries.md).
4. Keep all twelve scaffolder/AI rows visible. Explicitly declare each family's applicability;
   an absent AI skill can be N/A, and repository templates alone do not establish an in-scope
   promoted scaffolder. An omitted family is incomplete, not an automatic product defect. Read
   [conditional families](references/area-conditional-families.md) and the selected
   [scaffolder](references/overlay-scaffolder.md) or
   [AI-skill](references/overlay-ai-skill.md) overlay.
5. JSON assessment data is canonical. Markdown reports are deterministic renderings. Earlier
   revision directories are immutable.

## Resolve and run the bundled validator

Resolve `SKILL_DIR` from the directory containing this loaded `SKILL.md`; never search host caches
or hardcode repository/install paths. Put validator build files in a writable local scratch
directory outside the plugin tree and reviewed repository.

Bash:

```bash
SKILL_DIR="<directory-containing-the-loaded-SKILL.md>"
OUTPUT="<user-approved-local-output-root>"
mkdir -p "$OUTPUT/.validator-cache"
READINESS_TEMP="$OUTPUT/.validator-cache" \
  bash "$SKILL_DIR/scripts/validator/run-validator.sh" help
```

PowerShell:

```powershell
$SkillDir = "<directory-containing-the-loaded-SKILL.md>"
$OutputRoot = "<user-approved-local-output-root>"
$env:READINESS_TEMP = Join-Path $OutputRoot ".validator-cache"
New-Item -ItemType Directory -Force $env:READINESS_TEMP | Out-Null
& (Join-Path $SkillDir "scripts/validator/run-validator.ps1") help
```

Use the same launcher prefix below. Exit `0` means completion, not that all rows are positive;
`1` is deterministic validation failure, `2` invalid usage, and `3` environment/tool failure.

## Select the mode

1. **Package-only**: use `assessment init --kind package`, then report/reader validation.
   May confirm `components: []`; no component worker or library inventory/index. Owns 60 current
   package rows, including package contents, dependency, and SBOM checks.
2. **Single component, unified**: default when no already validated package revision exists. Assess
   all 121 canonical rows for one component/package in one isolated context.
3. **Single package, split**: create one 60-row package assessment, then a bound 61-row component
   assessment per confirmed component.
4. **Full library**: create package assessments and one top-level writable worker per component.
   Nested custom agents are not workers. If separate sessions are unavailable, fail before
   inventory confirmation with
   `unsupported host: full-library assessment requires isolated workers`; never use a shared-context
   or serialized fallback.
5. **Targeted follow-up**: only for named rows or a bounded correction. It is not a complete
   readiness result; record selection and exclusions using
   [targeted profiles](references/targeted-profiles.md).

## Workflow

### 1. Discover, confirm, and freeze inputs

1. Inspect the package:

   ```text
   <launcher> package inspect --nupkg <exact.nupkg> --output <output>/package-inspection.json
   ```

   Read the retained six-field JSON; never redirect or filter launcher stdout (build diagnostics
   can precede it).

2. For published packages, follow [artifact acquisition](references/artifact-acquisition.md).
   Default to discovering the latest stable version, then ask the owner to confirm it. An explicit
   package/version remains authoritative; a failed retrieval is an attempt, not proof of a gap.
3. Discover official sources using [documentation discovery](references/documentation-discovery.md).
   Classify source as `source-available`, `closed-source`, or `unresolved`.
4. Package-only needs no component selection; otherwise discover components and every claimed
   mode (`static-ssr`, `interactive-server`, `interactive-webassembly`, `interactive-auto`, or
   `standalone-webassembly`).
5. For each selected component, declare whether grouped, registered, selected, or composite children
   require the dynamic-child lifecycle matrix. Do not infer not-applicable from a missing probe.
6. For source-available components, capture wrapper/API, runtime, interop, styles/assets, tests,
   and samples. An archive alone is not closure. For library analyzer/trim/AOT checks, require the
   original project/source closure; see [library assessment](references/library-assessment.md).
7. Show package/version/digest, sources, documents, inputs, modes, exclusions, and feedback before
   scoring. Ask owner.
8. Use [candidate construction](references/input-candidates.md): `inputs candidates` owns the JSON;
   never hand-author it. Then run `inputs discover`, `inputs confirm`, and `inputs validate`.

For a library, use the inventory commands and [library assessment](references/library-assessment.md):

```text
<launcher> inventory discover --root <output> --candidates <inventory-candidates.json> --output <output>/inventory.draft.json
<launcher> inventory confirm --root <output> --draft <output>/inventory.draft.json --output <output>/inventory.confirmed.json
```

### 2. Acquire evidence without overstating it

Apply the precedence and ownership rules in
[provenance and integrity](references/area-provenance-integrity.md). Prefer the exact package,
reproduced probes, exact mapped source, current public source/configuration, then documentation or
owner evidence. Lower-ranked evidence cannot override contradictory higher-ranked evidence.

Build immutable ledgers, bind every input to confirmed locators and digests, keep component
evidence isolated, and apply the status/protocol boundaries in the linked area playbooks.
Failed retrieval remains `unresolved`; owner declarations do not replace unrelated proof.
Unapproved extensions are not DOCX defects; package-owned `SEC-01` through `SEC-03` use one shared
library security packet.

Use exact grouped commands:

```text
<launcher> evidence ledger-build --kind repository --subject <repository-subject.json> --draft <evidence-draft.json> --nupkg <exact.nupkg> --output <repository-ledger.json>
<launcher> evidence ledger-build --kind component --subject <component-subject.json> --draft <evidence-draft.json> --nupkg <exact.nupkg> --output <component-ledger.json>
<launcher> evidence ledger-validate --ledger <source-ledger.json>
<launcher> evidence bundle --assessment <assessment-identity.json> --source-ledger <source-ledger.json> --ids <EV1-id,...> --output <evidence.json>
```

Read the applicable area playbooks while collecting evidence:
[security/privacy](references/area-security-privacy.md),
[accessibility](references/area-accessibility.md),
[Blazor runtime](references/area-blazor-runtime.md),
[trim/performance](references/area-trim-performance.md),
[CI/release](references/area-ci-release.md), and
[support/lifecycle](references/area-support-lifecycle.md).

### 3. Run applicable probes

Component assessments exercise every claimed render mode. Package-only still requires applicable
package/source/toolchain probes, but no component runtime or lifecycle matrix.

Create disposable consumer apps outside the reviewed repository. Use the exact package, not a local
rebuild. For each claimed mode, record restore/build/start commands, runtime observations, browser
and console/network evidence where applicable, prerequisites, and blockers. A build is not runtime
proof. Stop at the timebox and mark remaining applicable rows `not tested`.

For `net10.0`, pin and record the supported SDK before restore. A public NuGet v2 endpoint is an
allowed read-only fallback when v3 is unavailable; retain both outcomes and never edit reviewed
manifests or configuration.

Remove disposable apps and raw logs after extracting bounded commands, results, relevant snippets,
and digests into the local evidence set. Retain a failed probe only when needed for reproduction;
record why and avoid secrets, credentials, unrelated private URLs, and machine-specific absolute
paths in reports.

When `dynamic_child_lifecycle.applicability` is `required`, run the complete conditional matrix in
[Blazor runtime](references/area-blazor-runtime.md) after initial render. Bind each operation's raw
observation digest in one canonical lifecycle protocol. A blocked operation remains `not tested`
with its exact reason; never substitute an initial-state-only pass.

Before closing a unit, reconcile the immutable ledger with confirmed scope and show attempts for
each accessible family: package/artifact, source, documentation, and applicable consumer/runtime
or trim/toolchain checks. Row counts, hashes, and reader shape are not coverage. Apply each row's
status-specific evidence, provenance, and rationale contract; preserve legitimate `not applicable`
and owner-evidence paths. Generic records are not completion for a 60- or 61-row unit; create a
new immutable revision after missing checks. Do not inflate coverage by repeating one blocked probe.
Low record count alone is not a failure when shared evidence supports every cited claim.
For structured proof boundaries, use `source-proof-v1`, `public-absence-v1`, or
`direct-failure-v1`; free-text assertions are not substitutes. same-job source build plus
privileged signing/publishing is a gap. one mutable path is not a digest-bound immutable handoff.
component assignment through a public `[Parameter]` setter is mutation; mutable cascade proves
`PERF-05` applicability, not a gap.

### 4. Create and validate assessments

Initialize the appropriate row ownership:

```text
<launcher> assessment init --kind unified --root <output> --input <input.confirmed.json> --component <component-id> --output <unified.assessment.json>
<launcher> assessment init --kind package --root <output> --input <input> --output <assessment>
<launcher> assessment init --kind component --root <output> --input <input> --component <id> --package-revision <revision> --output <assessment>
<launcher> assessment canonicalize --assessment <draft> --output <canonical>
```

Omit `--rubric-version` for new work; the validator defaults to `2.0.0`. If a command contains
`--rubric-version 1.3.0`, confirm explicit legacy reproduction; never use it for current work.

Edit a **DRAFT**; canonicalize to **new** file before validation,
rendering, or revision. It checks JSON structure, not evidence/claims/bindings/completion.
Use schema 2; legacy v1 remains supported.
Follow [report contract](references/report-contract.md); deliver the
[reader](references/partner-preview.md) after validation:

```text
<launcher> assessment validate --root <output> --input <input.confirmed.json> --assessment <assessment.json> --evidence <evidence.json>
<launcher> report render --root <output> --input <input.confirmed.json> --assessment <assessment.json> --evidence <evidence.json> --output <revisions>
<launcher> report verify --root <output> --revision <revisions/0001>
```

Component validation/render/verify also requires `--package-revision <package-revision>` and, when
used, `--package-feedback <package.feedback.md>`. A worker returns the unit ID, revision, report,
validation-manifest SHA-256, and blockers.

### 5. Coordinate a full library

Skip this step for package-only. For full-library work, follow
[worker execution](references/worker-execution.md) and the complete
[library commands and resume contract](references/library-assessment.md).
Use `inventory status`, `library reconcile`, `library validate`, and `library index`.
After interruption, preserve completed revisions, mark active units incomplete, and reconcile;
resume only pending, blocked-after-input, or incomplete units in fresh isolated workers.
Reconciliation derives package/component kind; filenames alone cannot satisfy a handoff.
The factual index's authoritative generation is named by
`<output>/.readiness-index/current-generation.json`, not the compatibility caches.

### 6. Apply feedback or corrections

For feedback, use the exact user-owned format in
[feedback contract](references/feedback-contract.md). The CLI reads but never rewrites it. Render a
new revision with `--feedback`; preserve input, assessment, and evidence bytes exactly.

For a factual correction, add evidence, copy the prior assessment to a replacement file, change
only declared IDs, and run:

```text
<launcher> assessment revise --root <output> --input <input.confirmed.json> --assessment <replacement.json> --evidence <replacement.evidence.json> --output <revisions> --predecessor <sha256> --changed-ids <id,id>
```

Read [learning loop](references/learning-loop.md) only when asked to improve this workflow.

### 7. Optional decision guidance

Do not create guidance unless the user explicitly requests a verdict, prioritization, remediation
or next steps. Then write `decision-guidance.md` beside the relevant feedback file, outside
`revisions/`. Its header must contain the exact source validation-manifest SHA-256. It may derive
only from that validated revision, may include the requested verdict/priorities, and is deliberately
unbound and regenerable. It cannot alter rows, evidence, counts, report, or manifests. Replace it
only after another explicit guidance request.

### 8. Optional blinded comparison

Only for an explicit blinded accuracy/replay request, follow
[blinded comparison](references/blinded-comparison.md). Freeze and validate the exact allowed raw
input set before launching the blind worker. The worker fails closed on a missing or stale input and
never receives statuses, findings, recommendations, scorecards, feedback, or oracle conclusions.
Schema version 2 requires typed `available` or `blocked` accounting for every fixed vendor-neutral
coverage surface. This gate does not add requirements to ordinary readiness runs.

```text
<launcher> comparison inputs-freeze --root <bundle-root> --draft <comparison-inputs.draft.json> --output <comparison-inputs.confirmed.json>
<launcher> comparison inputs-validate --root <bundle-root> --manifest <comparison-inputs.confirmed.json>
```

## Validation before completion

Run automatically; do not report completion until all applicable checks pass:

1. `inputs validate` for every confirmed input.
2. `evidence ledger-validate` for every ledger and rebuild/validate the selected bundle.
3. `assessment validate` and `report verify` for every current revision.
4. For split mode, verify every component binds the exact validated package revision.
5. For library mode, `library reconcile`, `library validate`, and `library index`; require all
   confirmed units complete.
6. Recompute each handoff validation-manifest digest and compare it with the run manifest.
7. Confirm disposable probes were removed or explicitly retained with a bounded reason.
8. Report structural validation separately from unresolved factual limitations.
9. For lifecycle-required components, verify all ten operation dispositions and raw observation
   bindings.
10. For blinded comparisons, revalidate the confirmed comparison-input manifest before worker
    launch, reconcile every required coverage surface, and reject any undefined final disposition.

If any check fails, preserve valid immutable revisions, mark the unit blocked/incomplete, and
report the exact command, exit code, and smallest next action. Never claim readiness from an
unverified report.
