# Release-wide SBOM admission and LP-03

## Trust boundary

LP-03 requires all transitive dependency licenses to be OSI-approved and non-copyleft;
the SBOM is the authoritative inventory. Native `admit-sbom` is reusable admission,
not independent proof of inventory completeness, publication, build correspondence
or legal sufficiency. It returns **separate** `structural_admission` and
`designation_admission` states. Only both admitted/designated permit a positive LP-03.
No PI-06/PI-07 status is assigned by this component.

The caller explicitly designates these exact raw SBOM bytes for this exact root
as its authoritative **release-wide** inventory. This designation supplies the
completeness/scope basis that structural parsing cannot prove. It is not an owner
attestation, cryptographic signature, publication receipt or authenticated producer
assertion. Missing, unknown, sample or partial designation stays `not tested`.
Never invent a designation while silently importing an arbitrary sample graph.
The helper's clearly documented `--release-sbom` is this explicit designation intake.

## Checked inputs

`resolve` takes the usual case/request envelope. LP-03 roles are:

| Role | Bytes |
|---|---|
| `package` | Exact assessed root nupkg |
| `assessment` | Schema-2 binding/designation below |
| `sbom` | Exact raw SPDX JSON, never reformatted before hashing |
| `policy`, `corpus` | Unchanged LP-01 policy 1.0.0 and SPDX 3.27.0 pinned bytes |
| `dependency-NNN` | Exact inventoried nupkg at its stable sorted index |

Sort the admitted distinct NuGet `lowercase-id/version` keys ordinally and assign
zero-based three-digit roles. Missing members retain their index holes. Supplied
extra samples are inspected separately, never added to LP-03 or silently substituted.
An extra LP-03 dependency role or a bound version mismatch is `binding-conflict`.

The schema-2 assessment has exactly these properties (placeholders are not evidence):

```json
{
  "schema_version": 2,
  "root": {"id": "example.controls", "version": "1.0.0", "sha256": "<root digest>"},
  "inventory_scope": "release-wide",
  "sbom_sha256": "<raw SBOM digest>",
  "designation": {
    "basis": "caller-authoritative-release-inventory/1",
    "scope": "release-wide",
    "root": {"id": "example.controls", "version": "1.0.0", "sha256": "<root digest>"},
    "sbom_sha256": "<same raw SBOM digest>"
  }
}
```

`designation` and `sbom_sha256` can be null to retain missing evidence, not obtain
a positive. Schema 1 belongs to the historical resolved-graph/grant/review contract;
it is explicitly refused with a request for a fresh schema-2 packet, not upgraded.

`admit-sbom` uses the same checked-input envelope as `inspect`, with only `package`,
`assessment`, `sbom` (at most three roles). Output is bounded JSON:
`schema_version: 1`, `producer: sbom-inventory/1.0.0`, original checked `inputs`,
and `admission` with disposition/code/detail, both separate states and, on success,
`inventory`. The inventory retains profile, root/raw digests, namespace, product/root
SPDX IDs, exact sorted components, relationships and diagnostic observations.
It does not classify dependency licenses or acquire anything.

## Narrow supported structural profile

The supported profile is `spdx22-release-nuget-union/1.0.0`, matching retained
SPDX-2.2 JSON, not generic SPDX, CycloneDX or every SBOMTool version.

- Exact top-level keys: `externalDocumentRefs`, `spdxVersion`, `dataLicense`,
  `SPDXID`, `name`, `documentNamespace`, `creationInfo`, `documentDescribes`,
  `packages`, `relationships`, `files`. Data license CC0-1.0; HTTPS namespace;
  document ID `SPDXRef-DOCUMENT`; creation info has `created`, `creators`.
- No external documents. Exactly one described SWID product whose name,
  version and `pkg:swid/<supplier>/github.com/<root>@v?<version>?tag_id=<uuid>`
  associate it with the checked root release. A separate exact NuGet root is required.
- Package fields: `name`, `SPDXID`, `downloadLocation`, `filesAnalyzed`,
  `licenseConcluded`, `licenseDeclared`, `copyrightText`, `versionInfo`,
  `externalRefs`, `supplier`; optional `hasFiles`, `packageVerificationCode`,
  `licenseInfoFromFiles`. Each has one PACKAGE-MANAGER/purl external reference.
  NuGet components require consistent `pkg:nuget/<id>@<version>`, name and version.
- NuGet IDs normalize ASCII case and use the existing bounded identity profile;
  exact versions have three numeric components (1-5 digits each, no leading zeros
  except zero). Prereleases, floating/ranged/purl-qualified versions are unsupported.
- SPDX IDs are unique across document/files/packages; canonical NuGet component keys
  are unique. Duplicate components are not collapsed. Unknown fields/types,
  conflicting aliases or unresolved references do not admit.
- Relationships are only one matching document DESCRIBES and package DEPENDS_ON
  edges. Reject duplicate/self/dangling edges; require product-to-NuGet-root
  association and reachability of **every** package from the product. Traverse
  the product, not just the NuGet root, whose outgoing edge set may be empty.
- Include all inventoried dependencies, including SourceLink, ILLink and other
  build tooling. Only validated product and exact NuGet root are excluded.
  A complete admitted release-wide union needs no per-TFM annotations.
- Every root nuspec dependency group is screened for malformed/ambiguous IDs,
  duplicate declarations/groups, unknown/foreign nodes/attributes and unsupported
  framework-reference declarations, even with a nonempty SBOM. Every known
  direct dependency ID must occur in the inventory. This is a narrow omission
  check, not TFM selection, version-range solving or independent completeness proof.
  An empty union can pass only if these checks find no root dependency declaration.
- Root dependency attribute **values** are checked in every group and in ungrouped
  declarations. A supplied `version` supports only the helper's existing literal
  forms: a bare numeric minimum or `[exact-version]`, using the shared bounded
  three-component version validator above (at most 19 characters including brackets).
  An omitted optional version remains unconstrained; an explicitly empty/whitespace
  value is unsupported. Other forms, including otherwise valid NuGet intervals,
  floating versions, prereleases, revisions and noncanonical numeric spellings,
  are outside this profile, not declarations that this component purports to solve.
  Malformed or unsupported values produce `closure-unresolved` / `not tested`,
  even when every retained dependency declares MIT. A minimum is never treated as
  the selected version; exact inventory versions still come from the bound SBOM.
- Optional `include`/`exclude` values support comma-separated, case-insensitive
  `runtime`, `compile`, `build`, `native`, `contentFiles`, `analyzers`, `buildTransitive`,
  or standalone `all`/`none`. Whitespace around tokens is allowed; empty/unknown/
  duplicate tokens, mixed `all`/`none`, other separators and values over 256 characters
  are unsupported / `not tested`. These syntax checks never filter inventory members,
  even for `include="none"` or excluded build assets. Other asset vocabulary needs
  explicit profile support, not permissive acceptance.
- SBOM license fields such as NOASSERTION are not the classification evidence.
  Retained file checksum discrepancies are exposed separately as diagnostics:
  no assertion that a published file equals the final assessed package, no LP-03
  hash-equality gate, and no PI-10 result.

## Classification, ordering and next actions

LP-03 calls the **actual shared LP-01 package-expression classifier**, not a second
LP-03 allowlist or caller-supplied classification. Every alternative of an AND/OR
expression must satisfy the same pinned LP-01 policy. The dependency's own safe
nuspec expression suffices; no grant file, reviewer packet or owner approval.
The former owner-only `LicenseRef-owner-grant` branch is retired: that expression
alone does not demonstrate a genuinely private missing fact.

| Branch | Report status / next action |
|---|---|
| `missing-package`, `scope-missing` | not tested; acquire exact root / supported assessment |
| `input-invalid` | not tested; repair bounded safe evidence; schema 1 needs fresh admission |
| `policy-unavailable` | not tested; obtain pinned policy/catalog |
| `binding-conflict` | not tested; reconcile exact root/raw/designation/member bindings |
| `evidence-missing`, `closure-unresolved` | not tested; acquire/admit supported release inventory and explicit caller designation |
| `dependency-bytes-missing` | not tested; acquire the named exact inventoried archives |
| `license-evidence-unresolved` | not tested; acquire unambiguous supported own-package license declaration |
| `incompatible-dependency-license` | gap; a checked inventoried declaration positively proves copyleft/non-OSI licensing |
| `dependencies-policy-satisfied` | verified under the disclosed caller-designation trust boundary |

All present identity conflicts precede missing member bytes; missing bytes precede
unsupported/ambiguous licensing; unresolved licenses precede a supported gap.
NOASSERTION alone, missing/unknown/custom/deprecated/mixed licenses and license-file-only
or deprecated licenseUrl-only evidence are not tested, not gaps or owner escalations.
A valid expression plus a deprecated licenseUrl is classified from the expression only.
Every positive discloses reliance on caller designation and that structure does
not independently prove completeness or publication.

## Resource limits

Native admission: raw SBOM 1 MiB; scope 64 KiB; strict UTF-8/no BOM; depth 16/8
(JSON reader depth), 32,768 JSON values/properties, 16 KiB generic string/property
byte bound and narrower ASCII field bounds. Max 66 packages (product + root + 64
dependency versions), 512 relationships, 64 files, 8 external refs per package
(only one unambiguous purl admitted), 64 `hasFiles`, 16 creators and 1,024 root
dependency declarations. Recursive duplicate JSON properties reject.

LP-03: 8 MiB/root or dependency nupkg; 64 MiB all checked row bytes; safe ZIP/XML
profile (4,096 entries, 1 MiB nuspec, existing CRC/alias/path checks and bounded
expanded data), sequential archive inspection. No assessed restore, network or execution.
The shared admission also caps the serialized inventory at 240 KiB (headroom for pins
and envelope); excess is `input-invalid`/not tested, not a truncated admitted graph.
`admit-sbom` enforces per-role byte limits before buffering and caps its output at 256 KiB.
Other formats or limits need evidence/work outside this bounded profile, not relaxation.
