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
locator, top-level entry prefix, mapping rationale, and confidence, then verify selected files with:

```text
<launcher> source capture-archive --root <root> --archive <root-relative.tar.gz> \
  --source-root <root-relative-extracted-source> --archive-prefix <github-top-level-directory> \
  --archive-format tar.gz --repository-uri <repository-uri> --source-commit <40-hex-commit> \
  --source-mapping "<mapping-rationale>" --source-confidence <low|medium|high> \
  --acquisition-locator <codeload-archive-url> --source-path <repository-relative-path> \
  --output <new-receipt.json>
```

Read the retained receipt, not launcher stdout. `declared_source` records supplied provenance;
`archive` and `source_artifacts` record observed hashes and selected-file correspondence. The
helper never invokes Git, extracts bytes, executes archive contents, or establishes remote commit
truth. It does not establish complete project/import closure. Keep the receipt outside the extracted
source tree. ZIP archives use `--archive-format zip`; `--expected-sha256` can bind an independently
retained archive digest. Repeat `--source-path` for each selected file.

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

Honor validator ceilings: 256 MiB nupkg, 1 MiB nuspec, 4 MiB authored ledger, 64 MiB serialized
artifact, and at most 32 supplemental evidence inputs totaling 64 MiB.

Extract and probe outside the reviewed repository. Remove disposable extraction/probe trees and raw
logs after retaining bounded commands, results, relevant snippets, and digests.
