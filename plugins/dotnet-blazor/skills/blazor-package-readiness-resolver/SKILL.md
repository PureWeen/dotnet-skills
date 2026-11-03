---
name: blazor-package-readiness-resolver
description: >-
  Run deterministic offline Blazor package checks on exact .nupkg bytes and checked evidence
  packets. USE FOR: package resolver invocation, replaying digest-bound evidence, JSON row
  results, license/notice/provenance checks without network or executing package code.
  DO NOT USE FOR: full component or library readiness reports (use blazor-component-readiness),
  ordinary NuGet restore troubleshooting, running samples, or legal/certification decisions.
compatibility: Requires Python 3.10+ and an installed stable .NET 10 SDK with its reference/runtime packs. No downloads.
---

# Blazor Package Readiness Resolver

## Purpose and routing

Produce evidence-bound machine-readable row results from the bundled deterministic resolver.
The installed tool is [scripts/run-resolver.py](scripts/run-resolver.py); no repository checkout,
Git, `eng/` directory, network, package dependency restore or package-code execution is needed.
It builds **only its own trusted bundled source** against installed framework packs with empty
package feeds. This is not a sandbox and never authorizes executing assessed code.
The launcher pins the newest installed stable .NET 10 SDK in its temporary build directory;
it never changes the caller's `global.json` or SDK selection. No native apphost is built.
The separate full-report validator still requires the caller's active .NET 11 SDK.

This skill owns deterministic package/evidence checks, not a complete readiness report.
For a full package/component/library report load the sibling skill
`blazor-component-readiness`, which consumes these static
outputs without turning them into component evidence or certification.

## Inputs

| Input | Meaning |
|---|---|
| An exact local `.nupkg` | `package` checks all 11 implemented rows with package bytes only. Missing checked evidence stays unresolved. |
| A local `request.json` plus relative input files | `resolve` admits pinned roles/paths/SHA-256 and dispatches without expected answers. |
| An `inputs.json` pinning a package and retained source/dependencies | `inspect` preserves broader literal observations and exact source matches without inventing complete/admitted row evidence. |
| An `inputs.json` pinning a root, schema-2 assessment and raw SPDX SBOM | `admit-sbom` separates structural admission from the bound caller authoritative release-wide inventory designation; it does not prove completeness or publication. |
| A frozen `cases.json` and its checked inputs | `replay` additionally requires exact complete expected results and evidence pointers. |
| No assessment inputs | `coverage` lists 60 package rows: 11 implemented, 49 TBD. It is not an assessment. |

Never infer absent/private source, inventory completeness, obligation applicability, owner
approval or notice coverage from filenames, SPDX metadata, package presence or a successful exit.
Acquisition and evidence admission are separate from offline classification.

## Workflow

1. Resolve `SKILL_DIR` as the directory containing this loaded `SKILL.md`. Inspect the supplied
   local artifacts and requested scope. Do not search host caches or download missing inputs.
   Missing package bytes or malformed bindings are failures, not positive results.
2. Select one operation per invocation. These commands work in PowerShell, Bash or another shell with
   Python available; replace the script prefix with its resolved installed path:

   ```text
   python "<SKILL_DIR>/scripts/run-resolver.py" coverage
   python "<SKILL_DIR>/scripts/run-resolver.py" package "<supplied.nupkg>"
   python "<SKILL_DIR>/scripts/run-resolver.py" resolve "<request.json>"
   python "<SKILL_DIR>/scripts/run-resolver.py" inspect "<inputs.json>"
   python "<SKILL_DIR>/scripts/run-resolver.py" admit-sbom "<inputs.json>"
   python "<SKILL_DIR>/scripts/run-resolver.py" replay "<cases.json>"
   ```

   Redirect stdout to a user-approved output file if requested. Stderr is diagnostic, not JSON.
   There is deliberately no acquisition command exposed by this launcher.
3. For supplied checked evidence, use `resolve`, not invented expected answers. Its contract is:

   ```json
   {
     "schema_version": 1,
     "cases": [{
       "case_id": "notice-check",
       "row_id": "LP-04",
       "inputs": [
         {"role": "package", "path": "package.nupkg", "sha256": "<64 lowercase hex characters>"}
       ]
     }]
   }
   ```

   This is a shape example, not checked positive evidence. Preserve the packet's actual roles and
   byte digests; never substitute these placeholders. Input paths are canonical ASCII relative
   paths beneath the request directory, without `.`/`..`, absolute paths or linked members.
   Additional packet roles are row-specific; supply all retained files rather than guessing
   complete/approved booleans. Package-only filenames follow the same portable path profile.
   Admission bounds: 1 MiB request, depth 16, 1-256 cases, at most 512 inputs per case,
   64 MiB per file, 256 MiB total checked bytes; row-specific bounds may be stricter.
4. Preserve raw JSON and the exact command/exit alongside the assessment's input pins. Exit 0
   means dispatch/replay completed; it does **not** mean verified. Exit 2 means invalid/unreadable
   input/contract; exit 3 means unavailable environment/build/timeout. Do not produce guessed row
   results after either failure. Report the actual blocker and keep other valid results intact.
5. Read every result's `branch_id`, `decision`, `applicability`, `finding`, `missing_fact`,
   `required_input`, `next_category`, `inputs`, `evidence_references` and `evidence_contract`.
   Output is `{"schema_version":1,"cases":[{"case_id":"...","result":{...}}]}`.
   A deterministic decision can be adverse. An escalated result is not a gap merely because
   evidence is missing. Cite the preserved result and its checked bytes when handing off.

## Validation and interpretation

When raw source/dependencies are retained but no admitted row packet exists, follow
[evidence inspection](references/evidence-inspection.md). Missing stronger evidence is not a
reason to discard supported dependency declarations, source/project observations or exact text
matches. `inspect` does not relax the `resolve` contracts or assign statuses.

Implemented handlers are LP-01 through LP-10 and PI-01, at their frozen versions. Other rows
remain TBD. Coverage never establishes package compliance. The resolver preserves per-row
precedence and qualified claims; do not broaden them into a full report.

LP-03 `lp03-dependency-licenses/1.4.0` uses the caller-designated release-wide SBOM
and exact inventoried nupkgs' or npm tarballs' own declarations through the actual LP-01 classifier.
See [SBOM admission](references/sbom-inventory.md) for schema 2, the narrow retained
SPDX 2.2 JSON profile and bounds. An admitted structure alone is not authoritative:
the exact raw digest/root-bound caller designation is a separate trust boundary.
Ordinary grants, reviews and owner approval are not prerequisites; missing or unsupported
evidence stays `not tested`. PI-06/PI-07 remain unimplemented and unassigned.
Every LP-03 outcome states that npm hashes bind caller-designated bytes, not publisher
authenticity. LP-02 1.2.0 admits literal `$` only in bounded source archive members.
Require each NuGet root dependency's exact version or range to be satisfied by an inventoried
version, not merely its ID. Bare versions are minimum bounds; `[v]` is exact.
LP-10 1.1.0 accepts the five-input provenance packet only through the trusted autofill
helper's process-local admission. Caller-authored Sigstore/gh JSON or locally imported source
archives cannot authorize a positive. Read [provenance admission](references/provenance-admission.md)
before using this path: exact-commit helper acquisition, bound receipts and positive
per-entry source/project correspondence are prerequisites. Do not construct receipts or
set the helper admission key yourself.

For LP-04 `lp04-notice-coverage/2.1.0`, default single-input requests pass the assessed package only. Follow
[D-lite bundled web assets](references/lp04-notices.md) for the bounded layout/suffix profile,
complete retained inventory, digest and six unresolved reasons (`not tested`, including an empty supported-profile scan; it does not prove the absence of other web code).
The helper-admitted provenance path requires a digest-bound per-asset source/component map
and complete SPDX-specific notices. Mode B remains unverified: exact repository bytes do
not prove authorship. Native `provenance-notices-verified` is not a report-validator bypass;
separately admitted structured notice evidence is still required. Missing evidence resolves
`provenance-notices-unverified` (`not tested`).
V1 roles/packets are refused, never converted or used as a verified/gap fallback.
Preserve `bundled_web_assets` alongside the compact observation.

Full-report status vocabulary remains `verified`, `gap`, `owner evidence required`, `not tested`,
`not applicable`. Consume the row's complete qualified result; a caller must not invent a status
solely from `decision` or exit code.

## Pitfalls and nonclaims

- Never install SDKs, fetch packages, restore assessed dependency graphs, run package build
  targets/analyzers, extract and execute assets, or call the separate acquisition utility.
- Do not manufacture policy, inventory, owner, review or mapping assertions to obtain positives.
- Do not erase conflicts by dropping evidence roles or editing packaged bytes.
- This is no legal advice, license acceptability beyond a row's explicit profile, source/build
  correspondence, copyright ownership, vulnerability/support conclusion, authenticated review,
  release approval or certification. Preserve each row's stronger/more specific nonclaim wording.
- If an installed file is missing, inspect the known bundled scripts directory once and report
  the installation failure. Do not fall back to an arbitrary host checkout or success-shaped prose.
