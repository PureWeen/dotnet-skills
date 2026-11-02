# Deterministic eleven-row package handoff

Use the shipped `scripts/autofill-eleven.py` in a full plugin installation for LP-01 through
LP-10 and PI-01. It collects static bytes, runs the sibling resolver's `inspect` and `resolve`,
and fills those eleven rows through the existing input/evidence/assessment producers. It never
calls a model, executes assessed code, or completes the other 49 rows.

## Run from confirmed scope

Confirm the exact local package, external output root and current input set first using
[input candidates](input-candidates.md). `--candidates` is the latest original candidate file,
not a confirmed manifest copied back into discovery; the script checks that it reproduces
`--confirmed`. The output root must already exist, outside the installed plugin and reviewed
repository. Python 3.10+, stable .NET 10 and active .NET 11 must already be installed.
No SDK, parser or dependency restore is performed for assessed inputs.

```text
python "<SKILL_DIR>/scripts/autofill-eleven.py" run --root "<output>" --nupkg "<output>/package.nupkg" --candidates "<latest-candidates.json>" --confirmed "<input.confirmed.json>" --offline --source-archive "<retained-source.zip>" --dependency-directory "<retained-dependencies>"
```

`--source-archive` and `--dependency-directory` are optional; repeat `--dependency <file.nupkg>`
for individual exact dependency files. Add `--release-sbom "<raw-release.spdx.json>"` only to
**explicitly designate those exact bytes/root as the caller's authoritative release-wide inventory**.
This is a caller scope/completeness trust boundary, not independent publication/completeness proof,
an owner attestation or a fabricated capture receipt. Directory enumeration is immediate `.nupkg` files only,
not a host-cache search. Omitted acquisition mode defaults to offline. Files are copied to a
new immutable capture subtree; source and package contents are read only as ZIP/XML data.
Unsafe or unsupported optional content is retained with an explicit invalid-content record,
not admitted as inspection evidence. An inspector/admission failure blocks the handoff.

Replace `--offline` with `--allow-network` only after acquisition authorization. Source is a
GitHub codeload ZIP at the exact 40-hex package-declared commit; no branch/tag lookup or arbitrary
URL is accepted. An explicit confirmed closed-source boundary suppresses source acquisition,
not dependency inspection. Dependencies default to NuGet's public flat-container endpoint.
Use `--nuget-feed dotnet-public` to select the public Azure DevOps mirror configured in the
repository's `eng/evaluation/nuget.config`:
`https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json`.
Its advertised `PackageBaseAddress/3.0.0` is pinned in the script. `--nuget-feed nuget.org`
preserves the default; there is no silent fallback or arbitrary feed URL.

Initial transport hosts are `api.nuget.org`, `codeload.github.com`, and the one pinned
`pkgs.dev.azure.com` feed. HTTP, alternate ports, credentials, query/fragment input locators,
environment proxies and cookies are rejected. Automatic redirects remain disabled.
Only the selected Azure feed may issue one explicit HTTPS redirect to a bounded
`*.vsblob.vsassets.io` blob path. The provider-signed query stays in worker memory, never
in command lines or retained receipts. Cross-feed redirects, other hosts and redirect chains
are rejected. Certificate/hostname checks remain enabled. There are no automatic retries.

Every artifact fetch or local import has a retained attempt with subject, locator, method,
actual UTC, result, detail code, byte count and retained digest/path when available. Results use
the existing six acquisition tokens. Completed download workers also retain `http_requests`
with each hop's host, actual UTC and response status, without signed locators. A hard-killed
worker reports an unknown hop list rather than inventing a physical-request count.
Eligibility/budget skips are diagnostics, not fictional
requests. Attempts are projected through typed `add-retrieval`; acquisition failure is never
a product `gap`, closed-source inference or success-shaped fallback.

Collection supports at most 128 distinct dependency versions with a release SBOM
(64 without), 8 MiB per package archive, 64 MiB source
and 256 MiB checked bytes, including retained invalid/partial outcomes and supplied row packets.
Raw local SBOM intake is capped at 1 MiB and consumes the same retrieval-record/byte budgets;
native admission request/result/scope bytes are counted too. LP-03 has a stricter 64 MiB row cap.
Each download has a 60-second hard deadline including DNS/TLS;
socket operations also have a 10-second timeout. Collection has a 15-minute aggregate deadline.
ZIPs are bounded to 4,096 entries and 64 MiB expanded bytes, with safe paths and no links.
Existing validator limits also apply: 64 retrieval records and 32 supplemental files/64 MiB
**combined with existing owner/evidence inputs**. Three document registrations and their bounded
byte budget are reserved before fetching. Budget exhaustion is explicit bounded incompleteness.

Without `--release-sbom`, dependency selection is intentionally not NuGet resolution: `[v]` is exact; bare numeric `v`
selects bytes at its literal minimum and is labelled a sample. Traverse exact matching root-TFM
groups, otherwise ungrouped declarations; record unsupported groups, ranges and version forms.
Preserve all literal declarations, including unfollowed groups, in the inspection packet.
One successful single-hop anonymous codeload capture produces a pinned LP-02
`source-observation` from its actual request UTC and checked archive digest. A local
source import, offline mode, failed fetch or budget skip never creates that observation.
LP-02 `lp02-public-source/1.2.0` verifies availability at the exact package-declared
repository/revision with a checked nonempty root-bound archive. Project type,
PackageId, conditional settings and inherited build files are not requirements.
The package declaration supplies the association, not independent source relevance,
binary-to-commit correspondence or branch/tag membership.
Only source archive member paths may contain interior ASCII spaces and literal `$`
(for example `Comparer$1.ts`); package and checked-input paths remain strict.
Traversal, leading/trailing spaces or dots, Windows reserved names, duplicate/case
collisions, links, drive/UNC/colon syntax and oversized members still reject.
Archive names are never shell arguments.
No restored graph, grant/review, notice map, owner approval or
compiled-build correspondence is fabricated. Frozen LP-01 policy 1.0.0/SPDX 3.27.0 are bundled
byte-exact reference assets, not owner approval or new license policy.

With `--release-sbom`, the helper first retains raw bytes/digest and calls the shared native
`admit-sbom`, never a second Python SPDX parser. Supported SPDX-2.2 structure and the caller's
separate bound designation must both admit. Every root nuspec dependency group is screened,
including malformed identities in an otherwise nonempty inventory. No per-TFM gate is imposed.
All inventoried exact NuGet and npm versions, including build tooling, count.
The helper selects only admitted members for LP-03, preserving sorted role indices/holes;
extra supplied samples remain available to inspection but are not LP-03 members.
When acquisition is authorized, only missing exact SBOM-listed versions are fetched anonymously
from the selected `--nuget-feed` flat container: no minimum sampling, index lookup,
retries, range solving, alternate-version or feed fallback. `dotnet-public` never
falls back to `api.nuget.org`. All members, including missing/oversized outcomes,
are retained in `inventory_member_outcomes` with their exact acquisition attempts.
Native admission failures do not trigger dependency acquisition. Local SBOM/source/nupkg imports
never fabricate anonymous observations. Missing bytes stay `not tested`; synthetic mocked successes
are not real package acquisition claims.

LP-03 `lp03-dependency-licenses/1.3.0` classifies exact members' own nuspec expressions or
npm tarball `package.json` string licenses through
the actual pinned LP-01 classifier. All allowed AND/OR alternatives pass without ordinary grants,
reviews or owner approval. Missing/ambiguous/file-only/URL-only/NOASSERTION declarations stay
`not tested`; positive copyleft/non-OSI declarations support `gap` only after complete evidence
gates. The former owner-only branch is retired. Positive findings disclose caller designation.
Raw checksum mismatches remain separate diagnostics, not a PI-10 result. PI-06/PI-07 remain
unassigned. The complete shipped schema/bounds are in the sibling resolver's
`references/sbom-inventory.md`.

Use `--npm-archives <manifest.json>` only with `--release-sbom` for caller-designated
pre-downloaded exact tarballs. The root/raw-SBOM-bound manifest and every imported byte
are retained. Native roles preserve the historical ordinal NuGet `id/version` order,
then npm `name/version` order; missing members keep holes. Local npm imports share
byte/component caps, not the 64 retrieval-record budget; `npm_evidence_imports` records
their outcomes. No npm requests, extraction, scripts or reconstructed CDN packages.
All LP-03 outcomes explicitly state: npm archive hashes bind caller-designated bytes
and do not authenticate publisher archives. Unknown license evidence stays not tested.
LP-03 observations label inspection license groups as NuGet-only and report inventory
and missing-byte counts separately for NuGet and npm. An npm candidate counts as retained
only when its member outcome matches a checksum-matched import's path and digest.
These import counts do not classify npm licenses; that decision comes from the native resolver.

Optional `--row-packets <resolve-request.json>` consumes explicitly supplied checked evidence
for these same rows. It rechecks/copies exact pins and the root digest; no expected-answer
fields are accepted. Supplied packets replace only their named row's default request.

## Outputs and fixed mapping

Each invocation creates a new `eleven-NNNN` directory and root-level revision-named
`resolver-results`, `observations` and `acquisition` documents; no existing file is overwritten.
Command arguments, stdout/stderr, exits and digests are retained. The final stdout receipt
names the current confirmed manifest, latest candidates, canonical incomplete assessment and
`eleven-state.json`. Read those files, not launcher build output.

The script registers and confirms only its three derived documents plus actual attempts.
It initializes/exports identity, produces row-specific evidence drafts through registered
`reviewer-generated-analysis`, builds/validates a repository ledger, makes an input-bound
bundle, emits `decisions.json`, applies it and canonicalizes. Raw archives remain nested and
pinned; registering three documents does not pretend 50 dependency archives are individually
confirmed source artifacts.

`scripts/eleven_rows.py` owns the explicit 175 `(row, branch)` mappings. Bundled resolver source
and data fingerprints are checked before collection; a changed file inventory, unknown branch,
version, decision, applicability or input binding fails closed pending mapping review.
`verified`, `gap` and `not applicable` require the appropriate direct deterministic branch;
an escalation can only yield `not tested` or `owner evidence required`. Exit zero or the
`decision` token alone never chooses status. Partial inspection facts enrich the observation
without upgrading the status. Full result contracts and exact byte pointers remain retained.
LP-01 `approved-non-copyleft` maps to `verified` with null `owner_action` and
`assessment_follow_up`: every offered alternative in the exact package SPDX declaration
is OSI-approved and non-copyleft under the pinned policy. No owner-authorized or
release-scoped grant is required for this branch. Its observation retains declarations,
named candidates and exact source-byte matches without an owner-authority missing-fact
sentence. File-only and missing-license branches still require owner evidence; the separate
`owner-evidence-accepted` branch and all other branch statuses are unchanged.
LP-04 accepts only `lp04-notice-coverage/2.0.0`: its default request passes package
bytes only, without TFM/all-root-entry scope. All six D-lite reasons (`missing-package`,
`input-invalid`, `legacy-protocol`, `surface-unsupported`, `no-supported-layout-assets`,
`origin-review-missing`) map to `not tested`, with substantive missing-fact/action follow-up;
when `--release-nupkg`, `--provenance-bundle`, and `--source-archive` are supplied, autofill passes
the 5-input SLSA v1 packet to LP-04 as well as LP-10, mapping `provenance-notices-verified` to
`verified` and `provenance-notices-unverified` to `not tested`.
The complete bounded `bundled_web_assets` inventory is checked and retained in `results.json`;
the observation gives suffix counts, bytes and inventory digest, never truncated asset lists.
An empty scan states: "No JS/CSS assets detected in the supported package layouts; other
representations were not assessed." It is not proof of no web code or universal N/A.
V1 packets are refused, not converted. See the sibling resolver's `references/lp04-notices.md`.

LP-01 and PI-01 accept only `1.1.0`; LP-02 accepts `1.2.0`, LP-03 `1.3.0`,
LP-04 `2.0.0` and LP-10 `1.0.1`; other rows retain `1.0.0`.
LP-10's single-input package-only path requires a separate attribution assessment; when `--release-nupkg` and `--provenance-bundle` are supplied with `--source-archive`, autofill verifies the SLSA v1 bundle with `gh attestation verify` and resolves `provenance-attributed` or `provenance-unverified`. LP-01 and PI-01 recognize the empty nuspec namespace and
all six official NuGet schema namespaces (2010/07, 2011/08, 2011/10, 2012/06,
2013/01 and 2013/05). Metadata must still match its root namespace; LP-01 also
requires the license element to match. The collector recognizes the same namespace
set, including 2011/10; unknown namespaces remain unsupported.
Handoff producer `eleven-row-handoff/2.1.0` rejects older saved states rather than
silently reinterpreting their row decisions. Preserve old captures; make a fresh run
or explicitly supply already checked acquisition packets to evaluate the new contract.
This is a minor additive intake/profile extension: the handoff envelope is unchanged;
existing producer/version pinning already requires fresh captures, so no major bump is needed.
Observations preserve literal small license texts/headings and repository declarations,
root/dependency/source notice-candidate facts for other rows, plus per-PE declared
assembly metadata and signing fields. LP-04 uses only its bounded package inventory. Candidate text
above 4,096 bytes or outside strict UTF-8 retains an explicit state and exact digest, never a
clipped grant. Large lists use measured counts and exact inspection-packet pointers; declared
assembly attributes are not authenticated ownership or binary-to-commit build proof.
Oversized row text fails rather than silently clipping evidence.

Exit 0 means the incomplete eleven-row handoff was produced; 2 means admission/mapping failure;
3 means environment/trusted-tool failure. None means package readiness or certification.
The other 49 rows remain initialized and unassigned; findings and summaries are initially empty.

## Continue without re-deriving eleven rows

Apply decisions for only the other 49 IDs to the returned canonical draft, then canonicalize.
Use a separate evidence ledger for the remaining work, against the exported identity. Bundle
both ledgers once with the union of selected IDs. Do not include duplicate copies of a stable
record. Supply full current findings/summaries/completion when applying decisions: those
collections replace rather than merge existing values.

Before normal assessment validation, run:

```text
python "<SKILL_DIR>/scripts/autofill-eleven.py" check --root "<output>" --confirmed "<returned-confirmed.json>" --state "<eleven-state.json>" --assessment "<continued.canonical.json>"
```

`check` does not edit retained artifacts. It checks all saved byte pins, recomputes the reviewed
mapping, and checks current manifest/assessment identity, unchanged eleven rows, current input
validity and ledger integrity.
It creates/cleans a bounded trusted-tool build scratch directory beneath the approved root.
It does not validate the other rows, claim factual truth or replace ordinary final
assessment/report/bundle validation.

When adding explicitly unrelated supplemental evidence, construct/discover/confirm a new
manifest, then:

```text
python "<SKILL_DIR>/scripts/autofill-eleven.py" rebind --root "<output>" --confirmed "<new.confirmed.json>" --state "<old-eleven-state.json>" --unrelated-evidence "<added-basename.json>"
```

Repeat `--unrelated-evidence` for **every** added unrelated basename. Previous registrations
must remain unchanged. Source, owner, documentation, package-source, scope or raw/packet byte
changes require a fresh `run`; new relevant evidence must not be labelled unrelated.
`rebind` uses the existing producers and original capture time to regenerate the eleven rows
against the new identity. Rebuild the other ledgers and regenerate their ID references too.
Unchanged records under the same subject keep EV1 IDs when a ledger is appended/reordered;
a changed manifest/subject or claim/provenance may change them. Always read producer IDs.
Never transplant an old assessment identity or old EV1 references.

The sibling resolver remains offline. Missing sibling installation stops autofill
before acquisition; ordinary single-skill input/init remains available with explicit unresolved
static conclusions, as described by [the manual handoff](package-resolver.md).
