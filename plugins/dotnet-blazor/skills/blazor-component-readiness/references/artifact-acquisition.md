# Artifact acquisition

Use this before assessing a distributed package. Transport failure must not redefine a release as
source-only.

## Published package

1. Record the configured public package source and requested ID/version.
2. Discover the latest stable only as a draft default; ask the owner to confirm the exact version.
3. Use the package source's standard metadata and content endpoints to confirm and retrieve the
   exact original nupkg. Use a bounded alternate endpoint only when the primary route fails.
4. Record every attempt with subject, locator, retrieval method, result, and bounded detail.
   Allowed results are `succeeded`, `not-found`, `access-denied`, `unavailable`,
   `invalid-content`, and `network-failure`.
5. Hash before extraction. Canonical ID/version come from the nuspec inside those exact bytes.
6. A package cache is acceptable only when origin and exact original bytes are established. A local
   rebuild is not the published artifact.

Network, proxy, authentication, DNS, or tool failure is a retrieval result, not a product `gap`.
Continue with only claims the retained evidence can support; affected applicable rows are
`not tested` or `owner evidence required`.

## Release candidate

Use the owner-supplied local `.nupkg`, record acquisition as `release-candidate`, bind its SHA-256,
and start a distinct package root when bytes change even if the semantic version does not.

## Source archive capture

When the selected source is an already retained GitHub archive, extraction is an acquisition step,
not a checkout. For a GitHub codeload archive, record the repository URI, exact commit, archive
locator, top-level entry prefix, mapping rationale, and confidence. First inventory actual regular
archive entries, then choose relevant entries by their numeric IDs; the inventory is structural
source-file selection, not a component or library assessment inventory:

```text
<launcher> source inventory-archive --root <root> --archive <root-relative.tar.gz> \
  --source-root <root-relative-extracted-repository-root> --archive-prefix <github-top-level-directory> \
  --archive-format tar.gz --output <new-inventory.json>
```

`source-root` is the actual local repository root where each repository-relative `source_path`
exists; it is not necessarily the extraction destination. `archive-prefix` applies only to archive
entry names. For example, if the archive contains `bundle/src/a.txt`, then
`tar -xzf archive.tar.gz -C extracted` is captured with
`--source-root extracted/bundle --archive-prefix bundle`. If extraction uses
`--strip-components=1`, use `--source-root extracted` but still keep `--archive-prefix bundle`,
because the retained archive bytes did not change. Do not flatten the tree with `unzip -j`.

For a large retained inventory, an optional read-only `jq` projection makes the actual numeric IDs
and repository-relative paths inspectable without rewriting the machine-owned JSON:

```bash
INVENTORY="<retained-inventory.json>"
LISTING="<disposable-inspection-listing.tsv>"
(set -C; jq -r '.entries[] | [.id, .source_path] | @tsv' "$INVENTORY" > "$LISTING")
```

Use a bounded file-view range to inspect `$LISTING`, then pass only actual IDs from that listing to
`capture-inventory`, which still revalidates the original inventory. Set `$LISTING` to a separate
new file; the subshell refuses to overwrite an existing file. The listing is disposable, not an
inventory replacement or evidence of completeness, provenance, or component/library classification.
If `jq` is unavailable, use an available JSON/file viewer instead; no installation is required.

Use the retained inventory's actual IDs with:

```text
<launcher> source capture-inventory --root <root> --inventory <inventory.json> \
  --entry-id <1-based-entry-id> --repository-uri <repository-uri> --source-commit <40-hex-commit> \
  --source-mapping "<mapping-rationale>" --source-confidence <low|medium|high> \
  --acquisition-locator <codeload-archive-url> \
  --output <new-receipt.json>
```

Read the retained inventory and receipt, not launcher stdout. Repeat `--entry-id` for each
selected file. IDs are local inventory references, not evidence IDs. The inventory is machine-owned:
do not edit or reformat it. Inventory mappings are recomputed against the retained archive before
capture; do not guess filenames or reconstruct paths manually.
`declared_source` records supplied provenance;
`archive` and `source_artifacts` record observed hashes and selected-file correspondence. The
helper never invokes Git, extracts bytes, executes archive contents, or establishes remote commit
truth. It does not establish complete project/import closure. Keep the receipt outside the extracted
source tree. ZIP archives use `--archive-format zip`; `--expected-sha256` can bind an independently
retained archive digest. Existing `source capture-archive` remains available when exact source paths
are already known.

Use the same declared repository/commit/mapping/confidence in `inputs candidates init`. For each
captured file, pass its `source_path` and `content_path` to
`inputs candidates add-source-artifact --input <previous-candidate> --source-path <source_path> --path <content_path> --output <new-candidate>`.
Do not copy receipt JSON or hashes into candidates; discovery computes the final digests. Retain
actual retrieval attempts separately; the helper does not perform or attest a download.

## Minimum package inspection

Persist the canonical six-field package identity before inspecting its contents:

```text
<launcher> package inspect --nupkg <exact.nupkg> --output <output>/package-inspection.json
```

Read that retained JSON artifact rather than redirecting or filtering launcher stdout, because
launcher build diagnostics can precede command output.

- nuspec identity, license, repository, authors, project, and source-commit metadata;
- files, target frameworks, dependencies, bundled scripts/styles/fonts/themes/notices;
- every shipped managed assembly, keeping strong-name, Authenticode, and package signatures
  separate;
- SBOM/provenance correspondence to the exact final package digest;
- source mapping to a reachable exact commit when source is available.

Input schema 1 records each captured source file in `source_artifacts` with its canonical
repository-relative `source_path`, local `content_path`, and exact SHA-256. Confirmation re-reads
the local capture. Component and unified evidence may select only confirmed source artifacts that
also appear in that component's `allowed_source_paths`; package evidence may use any confirmed
repository-wide source artifact.

For a source-available component, build an implementation closure rather than selecting only the
public wrapper. Include the component API/wrapper, inherited base/runtime types, referenced browser
interop handlers and modules, package-owned style/theme assets, and the component tests and samples.
Record an exact blocker for any missing category. In a blinded comparison, bind those categories to
the schema-v2 coverage surfaces before worker launch.

Selected evidence is re-bound during every assessment validation:

- official documentation requires the exact confirmed URL and content digest;
- package metadata requires the exact nupkg or recomputed entry digest, plus the matching captured
  package-source digest when that entry was retained separately;
- owner inputs require exact basename, digest, and either
  `owner-supplied-internal-evidence` or `owner-supplied-public-evidence`;
- source evidence requires exact `source:<source_path>` and captured digest.

Runtime observations and owner declarations remain claim-bounded. Failed source retrieval is
`unresolved`, never evidence that a product is closed source.

## Offline release facts

Use `release facts` only for already retained, confirmed inputs. It does not retrieve releases,
fetch JSON-LD contexts, use credentials, authenticate signatures, score requirements or establish
publication freshness. Internal provenance comparisons are not additional partner obligations.

```text
<launcher> release facts --root <approved-root> --input <pre-output-confirmed.json> \
  --release-package <registered-release.nupkg> \
  --spdx22 <registered-spdx22.zip> --spdx22-entry spdx_2.2/manifest.spdx.json \
  --spdx30 <registered-spdx30.zip> --spdx30-entry spdx_3.0/manifest.spdx.json \
  --provenance <registered-provenance.json> --sbom-statement <registered-sbom.json> \
  --output <new-release-facts.json>
```

The target package comes from the manifest, not another command-line identity. The other five
roles select distinct, unique root-level registrations in `evidence_inputs` or `owner_inputs`.
The target may be nested to preserve identical target/release filenames. Register actual public
release files with `inputs candidates add-evidence`, not as owner attestations. Input and output
paths must remain beneath `--root`; outputs never overwrite existing files. All confirmed inputs
are revalidated before collection, and selected bytes must still match their registered digests
and sizes. No caller hash override, authority flag or conclusion filter is accepted.

This is a finite literal parser, not full SPDX, RDF, Sigstore or SLSA validation:

- SPDX-2.2 UTF-8 JSON: one `documentDescribes` package, unique element IDs, and one file whose
  `fileName` is the target basename or `./<basename>`, present in that package's `hasFiles`.
  Capture document/package/file declarations, package verification code and file SHA256.
- SPDX3: the single context reference `https://spdx.org/rdf/3.0.1/spdx-context.json`, one
  `SpdxDocument` and one exact-name `software_File`. `verifiedUsing` supports inline objects
  or uniquely resolved local graph-ID strings, with `Hash` or `PackageVerificationCode` types
  and `sha256`/`sha1` algorithms. Top-level `spdxId` and `@id` aliases must not collide.
  Selected document/file identities and aliases must also be unique across inline occurrences.
  Inline records are literal occurrences at exact JSON pointers, not globally merged identities.
  A required ID reference must have exactly one top-level target and one declaration occurrence
  across the document; repeated inline IDs do not authorize arbitrary reference resolution.
- Sigstore bundle v0.3, DSSE `application/vnd.in-toto+json`, in-toto Statement/v1 and predicates
  `https://slsa.dev/provenance/v1` or `https://spdx.dev/Document/v2.2`. The exact target basename
  selects one subject with one SHA256. SLSA workflow/v1 source dependency must uniquely match
  `git+<workflow.repository>@<workflow.ref>` with one `gitCommit`. Signatures are checked only
  for base64 encoding, never authenticated. The embedded SPDX2 document is also parsed.

Missing, null, duplicate, unresolved, unsupported or malformed required values are fatal; they
are never disguised as `not-comparable`. A complete collection may contain `match`, `mismatch`
and `not-comparable`. The latter applies only to supported, unambiguous operands with incompatible
declared kinds/algorithms. In particular, file-associated `PackageVerificationCode` is **not**
a package-file checksum. Its separately labeled literal-value equality makes no identity or
authentication claim. Embedded-SBOM comparison uses structural JSON equality (object order
ignored, array order and absent/null retained), not byte equality or RDF equivalence.

Result schema 1 (`producer_version: release-facts/1.0.0`, `normalization_version: 1`) contains
the confirmed manifest's raw digest/path, six role references to existing manifest pointers,
typed `facts`, eleven `comparisons` with full operands/reasons, all ten required `operations`,
`diagnostics`, cumulative `accounting`, and `execution`. Every fact has a packet-local ID,
kind, algorithm (or null), value and `{role, container, pointer}` source locator. Containers
identify raw bytes, exact ZIP entries, `nuspec:<entry>` or decoded `dsseEnvelope.payload`;
pointers are JSON pointers, except the inspected nuspec metadata paths. Fact IDs are not EV1 IDs.
The result retains declared verification IDs/types without claiming graph-wide consistency.
Success means every required operation actually ran. Failures emit a bounded operation trace
(`succeeded`, `failed`, `not-attempted`) and byte accounting on stderr, without publishing a result.
Existing exits remain 0 success, 1 validation, 2 usage and 3 environment.

Existing limits still apply: 256 MiB target, 32 registered supplemental/owner files totaling
64 MiB. An additional collective 64 MiB producer allowance charges all five selected raw inputs,
all actually expanded supplemental ZIP entries (including release-package content and sidecars),
decoded DSSE payloads/signature encodings and the literal embedded-predicate form, then exact
serialized output including diagnostics. Target expansion is separately bounded to 256 MiB.
Every ZIP is limited to 100,000 entries, safe regular paths, no duplicate/colliding names, and
declared/actual expanded-length checks. Every parsed document is limited to depth 64 and
100,000 JSON tokens. A 16 KiB allowance is kept available for fatal diagnostics; it is not
charged as consumed content. Accounting uses fixed-width decimal strings and counts cumulative
content, **not** total process memory or workspace storage. Successfully decoded bytes are
charged even when a subsequent canonical-base64 check rejects their original encoding.

For repeatability, `ReleaseFactsResult.NormalizedProjection()` replaces only
`execution.started_at_utc`, `execution.completed_at_utc`, `execution.duration_ms` and
`execution.root` with null. It preserves every input, fact, comparison, operation and accounting
field. Repeat into new files using the same confirmed input/root. Different physical root
lengths can change exact serialized-byte accounting; that accounting is intentionally not hidden.

Avoid output self-reference: collect against a pre-output confirmed manifest, then use
`inputs candidates add-evidence --path <result-basename> --kind offline-release-facts` on the
latest candidates and discover/confirm a **new** manifest. Initialize/export the final assessment
identity afterward. Consume the retained result with existing `evidence draft-add --kind
reviewer-generated-analysis --locator <result-basename> --content <result-path>`, an accurate
mechanical method/capture instant, and specific fact/comparison IDs in the claim or method.
Continue with existing `ledger-build`, `ledger-validate` and `bundle`; never copy old EV1 IDs
across changed input identities. An integration-only unscored identity skeleton is not a vendor
assessment. Do not add excluded internal provenance facts to accepted partner-report rows.

Honor validator ceilings: 256 MiB nupkg, 1 MiB nuspec, 4 MiB authored ledger, 64 MiB serialized
artifact, and at most 32 supplemental evidence inputs totaling 64 MiB.

Extract and probe outside the reviewed repository. Remove disposable extraction/probe trees and raw
logs after retaining bounded commands, results, relevant snippets, and digests.
