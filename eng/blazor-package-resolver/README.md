# Deterministic Blazor package resolvers

This dependency-free .NET CLI is a **non-scoring dispatch foundation**, not
an assessment, readiness authority, or component resolver. Its canonical production source
and data now ship in
[`blazor-package-readiness-resolver`](../../plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/SKILL.md).
The local project imports that source directly; there is no second production copy.
The installed cross-platform launcher builds only the trusted tool with empty feeds and
external temporary outputs; it never restores or executes assessed code.
It pins the newest installed stable .NET 10 SDK in that temporary directory, using the
SDK's matching installed packs rather than an ambient newer SDK's net10 pack defaults.
It runs the managed DLL without a native apphost, with fresh isolated package storage and
empty feeds. A missing SDK/pack is an environment failure, never an online restore or an
assessment result. Caller SDK selection and the report validator's active-.NET-11
prerequisite are unchanged.

The [compact corpus contract](tests/CORPUS.md) explains byte-locked generation, automatic
temporary-root replay, exact parent comparison and the **narrowed PI-01 independence claim**.
Every `tests/fixtures/...` path below is a preserved **logical materialized path**, not a
required checked-in tree. Historical contracts remain raw seeds under `tests/corpus/seeds/`,
with the reviewed LP-01 declaration and LP-02 public-availability corrections documented
in `tests/CORPUS.md`. The 868 row scenarios and two foundation scenarios and all
input bytes are preserved; only the named row-specific expected-result deltas are allowed.

The full 112-row
normative rubric and JSON crosswalk/basis are copied byte-for-byte from
`fefdaccbfdc0f34cec3d3ca5b8f7ea3fce4a68e3`, the tip of
`https://github.com/dotnet/skills` branch `shneuvil-public-blazor-readiness`
at copy time. Branch tips can move; the copied bytes remain independently
pinned by the original paths, Git blob IDs and SHA-256 digests in
the canonical runtime's `data/provenance.json`. The loader checks both digests, crosswalk clauses,
source version and all core scopes. Only the 60 `repository-wide` core rows
enter the registry; the 52 component rows and the separate TA-08 extension
are excluded. LP-01 through LP-10 have deterministic checked-byte
handlers: `lp01-license-policy/1.0.0`, `lp02-public-source/1.1.0`,
`lp03-dependency-licenses/1.1.0`,
`lp04-notice-coverage/1.0.0`,
`lp05-license-expression/1.0.0`, `lp06-repository-url/1.0.0`,
`lp07-repository-commit/1.0.0`, `lp08-authors/1.0.0`,
`lp09-project-url/1.0.0`, `lp10-binary-attribution/1.0.0`, and
`pi01-strong-name/1.0.0`. The other 49 package rows remain `tbd`.
`tbd` and `implemented` are
**work states**, not evaluation results.

LP-01's independently reviewed Phase A package-license policy
freeze is at `tests/fixtures/lp01/README.md`. It pins SPDX license-list
3.27.0 and an explicit versioned, conservative non-copyleft policy,
198 synthetic cases/197 archives, six separately frozen pre-dispatch input
rejections, a prevalidated caller-accepted owner record with a separately
checked grant per distinct normalized SPDX license ID, and two opt-in retained-package MIT
classifications that yield **deterministic** findings mapped to LP-01 `verified`.
An eligible package expression needs no owner grant or release/source scope evidence
under this requirement. The production resolver replays those exact expectations;
the finding classifies the exact package declaration, not other repository files
or other releases, and does not establish owner authority.
Coverage is eleven implemented and 49 TBD.
Run `python eng\blazor-package-resolver\tests\lp01_expectations.py`
to check the frozen oracle and policy bytes independently of production.

LP-03's offline handler now uses approved option B-prime: a checked raw SPDX-2.2
release inventory plus a **separate bound caller designation** of that exact
SBOM/root as the caller's authoritative release-wide inventory. Structural parsing
does not independently prove completeness or publication. The shared native
`admit-sbom` operation exposes these separate states and is reusable without
assigning PI-06/PI-07 (both remain TBD). Every malformed/ambiguous dependency identity
across every root nuspec group blocks positive admission, including nonempty inventories.
Known direct IDs must be represented; no TFM/range solving or assessed restore occurs.

Every inventoried exact NuGet dependency, including build tooling, needs retained
matching nupkg bytes and its **own nuspec expression** classified by the actual
shared LP-01 policy/classifier (policy 1.0.0 / SPDX 3.27.0). All allowed AND/OR
alternatives pass. No ordinary grant file, reviewer packet or owner approval.
The former owner-only LP-03 branch is retired; custom LicenseRefs are unresolved.
All present identity conflicts precede missing bytes; missing/unsupported license
evidence precedes an incompatible declaration gap. Unsupported or incomplete
evidence is `not tested`, never promoted from a sampled/partial graph.

The complete schema, strict field profile, branch table, exact-member role ordering
and limits ship in the resolver's
[SBOM reference](../../plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/references/sbom-inventory.md).
Bounds include 1 MiB raw SBOM, 64 KiB scope, depth 16/8, 32,768 JSON values/properties,
66 packages, 64 dependency versions, 512 relationships, 64 files, 8 MiB/nupkg and
64 MiB checked row bytes. Duplicate identities/properties, wrong root/version,
external/dangling references and unsupported shapes reject. Published file-checksum
differences are separate disclosed observations, not an LP-03 final-file-equality
gate or PI-10 result. There is no independent completeness/publication/build proof.

The helper's explicit `--release-sbom` intake retains the raw bytes and designation,
calls native admission, and, only when authorized, retrieves missing exact members
anonymously from nuget.org's flat container within the existing record/deadline/byte
budgets. It neither samples minima in this mode nor silently switches a selected
mirror. Local/offline imports never invent acquisition observations.

The historical [Phase A contract](tests/corpus/seeds/lp03__README.md), original
oracle, recipes, input/grant/review bytes and 66/77 guard/witness ledger remain
unchanged as history, **not current positive coverage**. Named
`lp03-sbom-declarations-1.1.0` changes only the 45 expected LP-03 results:
42 schema-1 refusals, one missing-package refusal and two retained root-only
scope refusals; input pins, rationales and pointers are preserved. `--parent`
admits exactly this named delta, not arbitrary LP-03 changes.

`python -B eng\blazor-package-resolver\tests\lp03_expectations.py` (also `-O`)
selects the new independent stdlib/LP-01-oracle specification. Native
`ResolverChecks -- lp03` runs prescribed current-profile specimens and additional
hostile native mutations, the real reusable admission API, all 43 legacy refusals,
original pre-dispatch loaders and retained binding negatives. The unchanged historical
oracle is retained but no longer claimed as current-profile conformance.
`test_shipping.py --lp03` exercises a copied installed helper end-to-end with the
real native resolver/report validator, offline/mock transport, exact selection,
state/rebind pins and untouched PI rows. Its test-only launcher adapter uses prebuilt
trusted DLLs (build with `--no-restore` first); it does not re-test unchanged bootstrap restores.
Both roots still return `scope-missing` / `not tested`, with no positive or gap.
Absent/partial/misspelled/missing-file/wrong-size/wrong-digest bindings are
separately rejected. Supply the corresponding `LP01_*` and `LP02_*` pairs to
include their retained regressions in the full suite.

LP-04's **offline production handler** implements the accepted
[`notice-coverage-v1` Phase A contract](tests/corpus/seeds/lp04__README.md), frozen at
`68893eb6d5bf8ebab919a8787069c9870a110039`. All accepted Phase A files remain
byte-identical, including historical pre-production status statements.
Production reads only checked buffers, never fixture names, ledgers, case IDs,
expected outcomes or the Python oracle. The 43 replay expectations, five loader
rejections, two optional retained roots and 331 checked inputs / 735351 bytes
remain the same 50 named expectations.

The handler requires the exact root and explicit TFM/all-root-entry scope,
admitted complete dependency and bundled-asset inventories, retained
whole-subject preservation-obligation reviews, and exhaustive mappings to
exact packaged entries or explicitly accepted aggregate byte segments.
Dependency license acceptability is not notice applicability. Files, metadata,
SPDX expressions and detected sidecars alone never establish coverage.
An omitted review document remains unresolved even for empty inventories;
only an explicitly retained captured empty review document can establish an
empty reviewed surface. All supplied bindings are checked before missing
subject bytes or unresolved evidence. Unresolved reviews precede unresolved
mapping, genuinely owner-private evidence, and a supported gap, in that order.
Direct missing/incomplete representation gaps require complete admitted
inventories/reviews/mappings plus observed absence or a strict nonempty proper
prefix. Arbitrary modified text or unsupported forms remain unresolved.

The result contract is unchanged:

> Qualified exact-byte notice coverage for the checked root and explicit TFM/all-root-entry scope.
> Admitted complete dependency and asset captures, prevalidated whole-subject obligation reviews,
> and exhaustive reviewed mappings are trust boundaries, not authenticated by hashes or references.
> No legal advice, LP-03 acceptability, build/source correspondence, ownership, vulnerability/support
> conclusion, or proof that the supplied obligation review is legally correct.

Bounded helpers reuse the checked-input/registry/result/canonicalization
foundation, strict XML/nuspec reader, and LP-01 raw ZIP name/range/CRC/encoding
validation. Normal inspection streams hashes of all root entries without
materializing their bodies; separately retained checked evidence supplies the
selected notice bytes. Archive limits remain 8 MiB each, 64 MiB total checked
bytes, 4096 entries, 1 MiB nuspec and 64 MiB expanded per archive. Normalized
JSON remains 64 KiB / depth 8, four TFMs, 64 dependency versions/assets,
128 root entries/reviews/mappings/total edges per target, and 1-16384 strict
UTF-8 reference/entry bytes. The narrower limits and complete schemas remain
in the frozen contract. Unsupported paths, aliases, duplicate fields and
outside-profile observations fail closed; no solver, scanner, acquisition,
network, execution or legal-authority mechanism is added.

`ResolverChecks -- lp04` executes all 128 critical guard families / 166
witnesses, 108 explicit weakened variants / 148 executions (32 existing-case
and 116 native fixed-memory recipes), 256 registration/empty-witness
meta-checks, five loader rejections, six retained binding negatives and 218
strict parser/resource/checked-buffer/culture runtime boundaries. It compares
complete canonical results, not just branch counts. Counterfactual controls are
friend-assembly test entry points compiled only with `RESOLVER_TEST_HOOKS`, admitting only the 108 frozen labels;
unknown labels are rejected and normal dispatch has no weakening option.
The shared ZIP validator's alias bypass is
used only by those explicit counterfactual checks; all existing/default callers
retain strict name validation and every counterfactual retains raw range/CRC
validation. Python only materializes locked fixture bytes, never classifications. Run the unchanged independent
`python eng\blazor-package-resolver\tests\lp04_expectations.py` (also `-O`)
separately. Optional paired `LP04_SYNCFUSION_NUPKG` /
`LP04_INFRAGISTICS_NUPKG` bindings verify exact retained bytes/identities and
still return `scope-missing` / `not tested`, never a vendor positive or gap.

LP-01 checks archive-wide entry identity using a pinned Unicode 15.0.0
casefold table (generated from Python Unicode 15.0.0 `str.casefold()` for
all changed scalar values; `data\lp01-casefold-15.0.0.json`, SHA-256
`1c1dd710665f23ad059dc9c5c986d48f9cad77c3f58de6cf0cad4590e066e7e7`)
before reading any ZIP entry by name. Its bounded nuspec reader prohibits
DTD/entities before expansion, accepts clean UTF-8 (with or without BOM) and
BOM-marked UTF-16 LE/BE, and rejects unsupported declared encodings.
LP-01 additionally checks raw central/local ZIP names and flags using strict
flagged UTF-8 or unflagged CP437, rejects NUL/control names and casefold
aliases, and streams every entry to verify its declared length and CRC before
inspecting license evidence. License version accepts only two to four ASCII
digit components no greater than 1.0.0.0; grant completeness uses the
frozen Python whitespace semantics, including U+001C--U+001F.
The ZIP validator requires disjoint, contiguous local-header/data/descriptor
ranges from byte zero to the central directory, with the directory ending
exactly at a comment-free EOCD. It rejects Zip64 records and markers,
unsupported flags or compression methods, backslash entry names, malformed
extra-field framing, and Unicode name-remapping extra fields instead of
allowing archive readers to select different package contents.
The 20 bytes preceding the EOCD cannot start with a Zip64 locator signature,
even when those bytes are framed as another field or entry data. Signed and
unsigned data descriptors are checked against the declared CRC and lengths
and the next physical boundary; a CRC equal to the descriptor signature does
not choose the signed form by itself.
Policy 1.0.0 and SPDX 3.27.0 are checked input bytes pinned independently
by their SHA-256 identities, not downloaded or inferred from LP-05.
An eligible package declaration without an owner record reaches the deterministic
`approved-non-copyleft` branch and maps to LP-01 `verified`, with no owner action or
assessment follow-up. Every offered alternative must be OSI-approved and non-copyleft
under the pinned policy. The separate `owner-evidence-accepted` branch still requires
a canonical, checked owner record and complete, separately checked grants for every
normalized license ID. For that branch, caller prevalidation accepts owner authority,
grant sufficiency and release/source correspondence; the resolver does not
cryptographically establish authority, inspect the repository or legally
interpret grant text. The 198-case replay, six pre-dispatch loader rejections,
Unicode/encoding boundaries and opt-in retained replays run in ResolverChecks.

The consumer's optional `autofill-eleven.py` orchestrates acquisition and the existing typed
report producers. The resolver remains offline; apart from the reviewed LP-01 approved
declaration correction and the LP-04 standard-packaging fix described below, its row
classifiers are unchanged except for the explicit LP-03 B-prime change above. Its fixed 178-branch report
mapping is tested against every frozen result, including deterministic/escalated boundaries.
Run `python eng\blazor-package-resolver\tests\test_autofill.py` for offline collector/mapping
tests and `python eng\blazor-package-resolver\tests\test_shipping.py --autofill` for the
installed producer chain, unchanged-row checks, rebinding and single-skill rejection.
The full shipping suite also includes that integration. No test makes network or model calls.
The two frozen policy/catalog copies are shipping reference assets with the same digests as
the corpus seeds, not new policy or owner attestations. Resolver source/data fingerprints
deliberately require report-mapping review when the bundled tool changes.
For explicitly authorized network collection behind a blocked nuget.org endpoint,
`--nuget-feed dotnet-public` selects the repository's public Azure DevOps mirror, with
one restricted provider-blob redirect and no retained signed query. Default feed behavior
and offline operation are unchanged.

Run from the repository root with the normal SDK in `global.json`:

```text
dotnet run --project eng/blazor-package-resolver/BlazorPackageResolver.csproj -- coverage
python eng/blazor-package-resolver/tests/corpus.py verify --parent
python eng/blazor-package-resolver/tests/test_corpus.py
python eng/blazor-package-resolver/tests/corpus.py replay foundation
python eng/blazor-package-resolver/tests/corpus.py replay lp01
python eng/blazor-package-resolver/tests/corpus.py replay lp02
python eng/blazor-package-resolver/tests/corpus.py replay lp03
python eng/blazor-package-resolver/tests/corpus.py replay lp04
python eng/blazor-package-resolver/tests/corpus.py replay lp05
python eng/blazor-package-resolver/tests/corpus.py replay lp06
python eng/blazor-package-resolver/tests/corpus.py replay lp07
python eng/blazor-package-resolver/tests/corpus.py replay lp08
python eng/blazor-package-resolver/tests/corpus.py replay lp09
python eng/blazor-package-resolver/tests/corpus.py replay lp10
python eng/blazor-package-resolver/tests/corpus.py replay pi01
dotnet run --project eng/blazor-package-resolver/tests/ResolverChecks.csproj
dotnet run --project eng/blazor-package-resolver/tests/ResolverChecks.csproj -- lp03
dotnet run --project eng\blazor-package-resolver\tests\ResolverChecks.csproj -- lp04
dotnet run --configuration Release --project eng\blazor-package-resolver\tests\ResolverChecks.csproj -- lp04
```

Installed use needs only the complete plugin:

```text
python plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/scripts/run-resolver.py package <supplied.nupkg>
python plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/scripts/run-resolver.py resolve <checked-request.json>
python plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/scripts/run-resolver.py inspect <checked-inputs.json>
```

`resolve` admits a bounded schema-version-1 request with `case_id`, `row_id` and pinned
`inputs`, without requiring or inventing expected answers. It uses the unchanged handlers
and canonical result writer. Native checks compare this path against all 870 accepted
foundation/row outcomes. Invalid bindings, duplicates, unknown fields, links and resource
limits fail explicitly. The installed launcher does not expose acquisition.

`inspect` preserves broader evidence without changing the row classifiers: one checked root,
an optional source ZIP and up to 64 distinct checked dependency nupkgs produce literal license
and dependency/repository declarations, bounded literal license/notice text and source notice
candidates, root entry hashes, Razor/project/inherited-build observations, exact source-byte
matches and per-PE assembly identity/signing fields through the existing strict PE inspector.
It does not manufacture anonymous retrieval, full resolved closure,
grant applicability, notice obligations or binary build mapping. See the shipping
[inspection contract](../../plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/references/evidence-inspection.md).
The consumer registers the packet as supplemental evidence and preserves useful facts even
when the deciding row remains unresolved. LP-02 1.1.0 verifies public availability
at the package-declared exact revision using an anonymous capture and checked nonempty
root-bound archive, without a project/MSBuild relevance gate. The declaration supplies
the association; independent source relevance, binary correspondence and branch/tag
membership are not established. The eleven-row helper creates the observation from its
existing single successful anonymous download, never from a local import alone.
LP-04/10 admission/attribution boundaries are unchanged; LP-03 uses the separate B-prime inventory/declaration protocol above.

`dotnet run --project eng\blazor-package-resolver\tests\ResolverChecks.csproj -- breadth`
runs the unchanged LP-04 frozen matrix plus ordinary NuGet OPC/directory regressions and checked
evidence-inspection tests. Standard root `[Content_Types].xml` is a packaging exception, not
permission for bracketed checked-input paths or unsafe/nested archive paths.

`coverage` emits ordered, canonical UTF-8 JSON with the two source digests and
per-row scope, text, clause, and work state. `replay` reads a `schema_version: 1`
suite with any number of cases; it validates each case's unique ID, rationale,
evidence pointers, and all relative pinned input paths and SHA-256 identities.
Roles can include package, repository snapshot, release assets, workflow, corpus,
and owner record. Conflicting roles, missing files, digest changes, unexpected
fields, and mismatched frozen expected results fail explicitly. The output is
canonical JSON; no readiness status, score, or verdict is emitted.
Each handler receives role-keyed `CheckedInput` entries with the same read-only
bytes used for SHA-256 verification; handlers consume those bytes rather than
reopening a path. Results retain only relative paths, roles, and digests, so
replays do not depend on the checkout location.

LP-02 establishes only qualified public source availability at the exact
package-declared revision. Its offline handler binds the package identity,
GitHub HTTPS repository and exact commit to a machine-generated anonymous
codeload receipt and nonempty root-bound retained archive. Optional supplemental
file digests are checked, not evaluated for relevance. Source paths admit interior
ASCII spaces using the existing inspection predicate, not leading/trailing
spaces or traversal. It does **not** establish that the published
binaries were built from that revision, repository ownership, complete build
closure, reproducibility or readiness. Codeload can serve fork-network commit
objects through the declared repository URL, so successful retrieval also
does not prove membership in that repository's branches or tags; LP-02 does
not perform a membership check. Missing/blocked/not-found/auth-required
and unsupported observations remain unresolved (`not tested`), never
closed-source or a gap. The narrowly scoped, separate `acquire-lp02`
command disables application credentials, cookies, proxies, redirects and
decompression; replay never retrieves anything. The full contract,
acquisition procedure, schema, numerical limits, 33 oracle cases,
18 focused runtime cases (51 total named synthetic cases) and two opt-in retained escalations are in
[the retained LP-02 contract](tests/corpus/seeds/lp02__README.md).
The accepted base has no readiness skill acquisition infrastructure; this
implementation reuses the existing checked-input/digest/replay and bounded
archive/nuspec surfaces instead of importing a second evidence framework.

LP-05 through LP-09 inspect only the checked package bytes through their shared
nuspec reader. It bounds package and ZIP directory size, entry count,
entry-name length and nuspec read size; rejects
ambiguous or missing root nuspecs, foreign NuGet namespaces and
DTD/entity-bearing XML; and does not extract files. A root-level child whose
local name is exactly `metadata` but whose namespace differs from a recognized
root's namespace makes metadata ambiguous when recognized metadata is also
present, regardless of sibling order. All five rows escalate without a field
finding or field evidence; the frozen cases cite the archive-level ambiguity.
This takes priority over duplicate recognized metadata when a foreign sibling
is present. A case-variant `Metadata` child is not this exact-local-name
ambiguity; zero or duplicate recognized metadata without a foreign sibling
retains its existing invalid-metadata behavior. A nonblank recognized
`license type="expression"` establishes only that `PackageLicenseExpression`
is populated. The supported `type` is case-insensitive; optional `version`
must parse as `System.Version` and not exceed `1.0.0`. XML namespace
declarations are not license metadata attributes; unknown ordinary attributes
escalate. A `licenseUrl` does not affect that field. The frozen 32-case LP-05
synthetic matrix, the opt-in identities of both retained vendor packages,
and replay instructions are in
`tests/fixtures/lp05/README.md`. Runtime-generated boundary checks in
`tests/Lp05BoundaryChecks.cs` exercise each production byte/count/size limit
and malformed ZIP directory/entry data without checked-in giant fixtures.
LP-06 establishes only whether the single recognized direct metadata
`repository` element has a nonblank `url` attribute. It does not validate
URL syntax, reachability, repository correctness, source correspondence or
commit identity. Its frozen 33-case synthetic matrix, the opt-in retained
identities and replay instructions are in `tests/fixtures/lp06/README.md`.
Tests check that repository elements elsewhere in the nuspec do not count,
and exercise the same ZIP/package/nuspec resource limits for LP-06.
LP-07 inspects the single direct recognized `repository` element's `commit`
attribute independently of its URL, type or branch. It reports a declared
nonzero full 40-hex SHA-1 or 64-hex SHA-256 object ID, not object existence,
repository correctness, or package/source correspondence. Its frozen 55-case
synthetic matrix, opt-in retained identities and replay instructions are in
`tests/fixtures/lp07/README.md`. Tests cover ASCII-only hash boundaries,
normalized commit-only duplicate comparison and the same resource limits.
LP-08 reports only whether one direct, recognized nuspec `authors` element
has a nonblank comma-separated entry. It trims outer whitespace but preserves
case, internal whitespace and Unicode; `owners` and malformed/foreign metadata
cannot establish Authors. It does not verify identities, publisher, ownership,
package validity or source correspondence. Its frozen 52-case synthetic matrix
and opt-in retained identities are in `tests/fixtures/lp08/README.md`;
`tests/Lp08BoundaryChecks.cs` adds namespace, Unicode and decision-order
probes, and the shared resource-limit checks exercise LP-08 too.
LP-09 reports whether a single direct, exact-case `projectUrl` element in
the metadata's namespace has nonblank XML-decoded text after outer trim.
It preserves internal text and does not validate URI syntax, scheme,
reachability, source identity or correspondence to the independent LP-06
RepositoryUrl. Case variants, foreign namespaces, duplicates and malformed
element shapes escalate rather than selecting a value. Its frozen 67-case
matrix and opt-in retained identities are in `tests/fixtures/lp09/README.md`;
`tests/Lp09BoundaryChecks.cs` adds decision-priority, namespace, XML text,
Unicode and culture probes. The shared ZIP/package/nuspec resource-limit
checks exercise LP-09 too. `tests/MetadataSiblingChecks.cs` probes
cross-row metadata sibling order, namespace, case, priority, culture and
repeatability without changing the frozen archives.
LP-10 independently inventories every non-manifest packaged entry, using
bounded ZIP/XML reads and magic-first executable detection; it never
executes, evaluates, or recursively unpacks packaged code. It classifies
compiled PE/ELF/Mach-O/WASM, script/JS and active MSBuild or markup text,
and escalates unsafe, opaque, or incomplete inventory before attribution.
Repository metadata, declared dependencies, signatures, PDBs, SourceLink
and SBOMs do not establish ownership or source correspondence. Code
branches require per-entry public release-commit build, exact source blob
or pinned transform, or referenced-package/upstream byte maps; safely
passive-only packages yield a package-specific vacuous no-code finding.
MSBuild inspection joins direct text and CDATA across comments and processing
instructions before testing active functions and hashing locators; prolog
recognition remains bounded and fail-closed. Supplemental oracle-derived
probes cover these boundaries, XML declaration case, Unicode root prefixes
and UTF-8-BOM library XML.
The frozen 174-case matrix, numerical limits and two opt-in retained
identities are documented in `tests/fixtures/lp10/README.md`.
`tests/Lp10BoundaryChecks.cs` independently checks inspected-byte path
independence, culture, uncompressed resource thresholds, and both retained
results when `LP10_SYNCFUSION_NUPKG` and `LP10_INFRAGISTICS_NUPKG` point
to the exact pinned local archives. Both must be set together; proprietary
bytes stay outside the repository.
PI-01 inventories the entire checked package for managed assemblies, bounds
ZIP/manifest/entry reads, and fails closed on opaque containers, native
bundle candidates, malformed metadata, unaccounted PE overlays, or unsupported
certificate profiles. It distinguishes unsigned, delay-signed, public-signed,
cryptographically invalid and verified strong-name signed assemblies; the
positive branch requires an unambiguous complete inventory. Strong-name RSA
verification uses the assembly public key and detects changed signature or
signed PE bytes. Its Authenticode certificate inspection accounts for
certificate-table bytes but does **not** establish publisher identity or
certificate-chain trust (the separate PI-02 requirement). Complete metadata
table/signature/CustomAttribute decoding and full assembly-qualified enum
identity checks precede decisive signing states; untrusted packaged code is
never executed or loaded. Valid managed modules with no Assembly table are
non-assemblies; malformed modules or modules claiming strong-name signing
cannot establish a complete inventory. ZIP names require flagged valid UTF-8
or unflagged ASCII with matching local and central records. PI-01 alias checks
fail closed for unsupported Unicode folds, and its evidence uses Python-style
lowercase ASCII escapes and Unicode scalar path ordering without changing
other rows' canonical JSON. The 138-case frozen matrix, evidence contracts and
opt-in retained identities are in `tests/fixtures/pi01/README.md`.
`tests/Pi01BoundaryChecks.cs` checks the package-only byte/count thresholds,
culture and checked-buffer path independence; when both `PI01_SYNCFUSION_NUPKG`
and `PI01_INFRAGISTICS_NUPKG` bind the exact local archives it also verifies
their frozen results. Unsupported external enum identities require additional
evidence rather than an inferred backing type.
Portable retained-package replay identities and result hashes are in each
row's `tests/fixtures/lp05/acceptance-results.json` and
`tests/fixtures/lp06/acceptance-results.json` and
`tests/fixtures/lp07/acceptance-results.json` and
`tests/fixtures/lp08/acceptance-results.json` and
`tests/fixtures/lp09/acceptance-results.json`. LP-10 has frozen
`tests/fixtures/lp10/acceptance.json` outcomes but no committed
acceptance receipt. The real-package
acceptance replays are opt-in, separate from ordinary CI and from any
readiness decision. LP-02 separately retains both declared-source-unverified
expectations until an actual anonymous capture and bounded source mapping
are supplied.

Each case's `expected` is a structured `CaseResult`: `row_id`, `resolver_id`,
`resolver_version`, stable `branch_id`, `decision` (`deterministic` or `escalated`),
`applicability` (`applicable`, `not-applicable`, or `unknown`), exact `inputs`,
`evidence_references` and/or `evidence_contract`, plus either a factual `finding`
or a specific `missing_fact`, `required_input`, and `next_category`. Branches of
the same future row may take different paths. Deterministic branches need a
finding and evidence; unknown applicability must escalate. A known applicable
branch may also escalate when a named fact/input remains missing. The dispatcher
escalates the other 49 unimplemented rows as `package-dispatcher`, not as a claimed row
resolver. Registry construction rejects missing/extra IDs, component or extension
IDs, handlers without registrations, implementation declarations without matching
handlers, and handlers on TBD rows.

## Sequential row workflow

Freeze reviewed case expectations and pinned input digests **before** implementing
one row. Add synthetic applicable, not-applicable, unknown, missing, and conflict
branches as relevant. Implement and register that row's handler only after its
expectations are fixed; rerun the replay and tests. A mismatch is a failing
contract, **not** permission to update expectation and implementation together.
Review an expectation change independently and explain its source evidence.
When separately supplied, real Syncfusion **and** Infragistics pinned acceptance
inputs must replay for that row; commercial inputs are opt-in and never required
for ordinary CI. LP-01, LP-05 through LP-10 and PI-01 were replayed against both exact retained
packages; local detailed receipts and proprietary package bytes are not
shipped with the repository. Old protocols may inform later row work, but
port no old file without an active consumer and a test. No prior PR or
readiness branch is a dependency of this tool.
