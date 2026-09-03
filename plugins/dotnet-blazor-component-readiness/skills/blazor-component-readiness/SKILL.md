---
name: blazor-component-readiness
description: >-
  Assess released or release-candidate Blazor component packages or complete libraries for
  explicit vendor self-assessment, readiness, adoption, recommendation, or release decisions.
  Produces local JSON-first evidence, validated reports, and resumable library results. USE FOR:
  "assess this Blazor package", "is this component/library ready to adopt or release?", vendor
  readiness scorecards. DO NOT USE FOR: ordinary Blazor authoring/debugging, first-party framework
  review, generic NuGet help, CI/PR/issue triage, implementation-only work, or certification.
compatibility: Requires an active .NET 11 SDK. Full-library mode additionally requires a host that can launch isolated workers.
---

# Blazor Component Readiness

## Outcome and safety boundary

Produce a bounded, evidence-backed self-assessment of an exact released or release-candidate
Blazor package. The 110-row public baseline is not certification or a Microsoft acceptance
requirement. Read local inputs and retrieve public inputs when needed; write only beneath the
user-approved local output root. Never modify the reviewed source tree or any remote system.

Deterministic validation proves artifact shape, canonical ordering, digests, and local byte
correspondence. It does not prove evidence truth, organizational approval, or release suitability.

## When to Use

- The request explicitly asks for vendor self-assessment, readiness, adoption, recommendation, or
  release evaluation of a released or release-candidate Blazor component package.
- The request explicitly covers one component, one package, or a confirmed full-library inventory.
- The owner wants a factual scorecard, evidence-backed correction, feedback re-render, or optional
  decision guidance derived from an existing validated revision.

## When Not to Use

- Ordinary Blazor authoring, debugging, feature implementation, or implementation-only work.
- First-party framework review, generic NuGet assistance, CI failure analysis, pull-request review,
  issue triage, or repository maintenance.
- Formal certification, compliance attestation, or an acceptance decision on another party's
  behalf.
- Catalog exploration without explicit readiness intent. Use an inventory-only task instead.

## Prerequisites and required inputs

Require an active .NET 11 SDK. Ask before any machine-level installation. If .NET 11 is absent,
stop with an environment limitation; do not weaken the launcher isolation.

| Input | Required | Rule |
|---|---|---|
| Output root | Yes | User-approved local directory outside the reviewed repository. |
| Package | Yes | Exact published package/version or supplied release-candidate `.nupkg`; confirm identity and SHA-256. |
| Scope | Yes | One component, one package, or full library; full library requires confirmed inventory and isolated workers. |
| Components | Yes | IDs/display names and every claimed render mode; owner confirms before probes. |
| Source | Yes | Record `source-available`, `closed-source`, or `unresolved`; never infer closed source from retrieval failure. |
| Documentation | Yes | Discover official owner-controlled docs, package metadata/README, and source docs when available; owner confirms the set. |
| Owner evidence | Optional | Local public/internal evidence with explicit provenance and digest; never treat feedback as evidence. |
| Exclusions/timebox | Optional | Record explicit exclusions and stop when the timebox expires. |

## Canonical contract

1. `references/rubric.json` is the sole source of the 110 requirement IDs, wording, order, and
   46 `repository-wide` / 64 `component-specific` ownership split.
2. `references/checklist.md` is only the generated human-readable view. Never edit or derive IDs
   from it independently.
3. Use exactly: `verified`, `gap`, `owner evidence required`, `not tested`,
   `not applicable`. See [status boundaries](references/status-boundaries.md).
4. Select overlays only when the confirmed deliverable contains that feature. Read
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

Use the same launcher prefix for every command below. Exit `0` means the command completed, not
that all rows are positive; `1` is deterministic validation failure, `2` invalid usage, and `3`
environment/tool failure.

## Select the mode

1. **Single component, unified**: default when no already validated package revision exists. Assess
   all 110 core rows for one component/package in one isolated context.
2. **Single package, split**: create one 46-row package assessment, then one 64-row component
   assessment per confirmed component, each bound to the package revision.
3. **Full library**: create one package assessment per exact package/version and exactly one
   isolated worker per confirmed component. If isolated workers are unavailable, fail before
   inventory confirmation with `unsupported host: full-library assessment requires isolated
   workers`; never use a shared-context or serialized fallback.
4. **Targeted follow-up**: only for named rows or a bounded correction. It is not a complete
   readiness result; record selection and exclusions using
   [targeted profiles](references/targeted-profiles.md).

## Workflow

### 1. Discover, confirm, and freeze inputs

1. Inspect an available package:

   ```text
   <launcher> package inspect --nupkg <exact.nupkg>
   ```

2. For published packages, follow [artifact acquisition](references/artifact-acquisition.md).
   Default to discovering the latest stable version, then ask the owner to confirm it. A failed
   retrieval is a recorded attempt, not proof that the package or product has a gap.
3. Discover official sources using [documentation discovery](references/documentation-discovery.md).
   Classify source as `source-available`, `closed-source`, or `unresolved`.
4. Discover components and every claimed mode (`static-ssr`, `interactive-server`,
   `interactive-webassembly`, `interactive-auto`, or `standalone-webassembly`).
5. Show package/version/digest, acquisition mode, source mapping/availability, official documents,
   owner inputs, component inventory, claimed modes, and exclusions. Ask the owner to correct and
   confirm the draft.
6. Canonicalize and freeze the manifest:

   ```text
   <launcher> inputs discover --root <output> --nupkg <exact.nupkg> --candidates <candidates.json> --output <input.draft.json>
   <launcher> inputs confirm --root <output> --draft <input.draft.json> --output <input.confirmed.json>
   <launcher> inputs validate --root <output> --manifest <input.confirmed.json>
   ```

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

- Build immutable repository and component ledgers, then select only cited `EV1-` records into the
  assessment bundle.
- Reuse repository-wide evidence only for the same exact package ID, normalized version, nupkg
  digest, and source commit when present.
- Keep component evidence within its confirmed component and allowed source paths.
- Owner-supplied evidence may support `verified` when directly applicable, digest-bound, and
  labeled `owner-supplied-internal-evidence` or `owner-supplied-public-evidence`.
- An owner declaration can establish `owner-declared-closed-source` or
  `owner-declared-unavailable`; it cannot substitute for unrelated runtime or artifact proof.

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

### 3. Exercise every claimed render mode

Create disposable consumer apps outside the reviewed repository. Use the exact package, not a local
rebuild. For each claimed mode, record restore/build/start commands, runtime observations, browser
and console/network evidence where applicable, prerequisites, and blockers. A build is not runtime
proof. Stop at the timebox and mark remaining applicable rows `not tested`.

Remove disposable apps and raw logs after extracting bounded commands, results, relevant snippets,
and digests into the local evidence set. Retain a failed probe only when needed for reproduction;
record why and avoid secrets, credentials, unrelated private URLs, and machine-specific absolute
paths in reports.

### 4. Create and validate assessments

Initialize the appropriate row ownership:

```text
<launcher> assessment init --kind unified --root <output> --input <input.confirmed.json> --output <unified.assessment.json>
<launcher> assessment init --kind package --root <output> --input <package.input.confirmed.json> --output <package.assessment.json>
<launcher> assessment init --kind component --root <output> --input <component.input.confirmed.json> --component <component-id> --package-revision <package-revision> --output <component.assessment.json>
```

Populate every selected row from evidence. Follow [report contract](references/report-contract.md).
Validate before rendering:

```text
<launcher> assessment validate --root <output> --input <input.confirmed.json> --assessment <assessment.json> --evidence <evidence.json>
<launcher> report render --root <output> --input <input.confirmed.json> --assessment <assessment.json> --evidence <evidence.json> --output <revisions>
<launcher> report verify --root <output> --revision <revisions/0001>
```

Component validation/render/verify also requires `--package-revision <package-revision>` and, when
used, `--package-feedback <package.feedback.md>`. A completed worker returns the unit ID, revision
directory, report path, validation-manifest path and SHA-256, plus blockers.

### 5. Coordinate a full library

Follow [library assessment](references/library-assessment.md). Dispatch exactly one isolated worker
for every confirmed package unit and exactly one isolated worker for every confirmed component
unit; never place sibling source, docs, owner evidence, or reasoning in a component worker context.
Validate every handoff path and digest before accepting it.

After interruption, leave completed revisions untouched, mark active units incomplete, run:

```text
<launcher> inventory status --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json
<launcher> library reconcile --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json
```

Resume only pending, blocked-after-input, or incomplete units in new isolated contexts. When all
units validate, run:

```text
<launcher> library validate --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json
<launcher> library index --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json --json <output>/library-index.json --markdown <output>/library-index.md
```

The index is factual only: packages/versions, completion state, status counts, report links,
missing inputs, and blocked probes.

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

Do not create guidance unless the user explicitly requests a verdict, prioritization, remediation,
or next steps. Then write `decision-guidance.md` beside the relevant feedback file, outside
`revisions/`. Its header must contain the exact source validation-manifest SHA-256. It may derive
only from that validated revision, may include the requested verdict/priorities, and is deliberately
unbound and regenerable. It cannot alter rows, evidence, counts, report, or manifests. Replace it
only after another explicit guidance request.

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

If any check fails, preserve valid immutable revisions, mark the unit blocked/incomplete, and
report the exact command, exit code, and smallest next action. Never claim readiness from an
unverified report.
