# Provenance and integrity

Applies to `LP-*` and `PI-*`. Follow `artifact-acquisition.md` first.

## Evidence precedence

When evidence conflicts, prefer:

1. exact published or supplied candidate nupkg;
2. deterministic consumer/browser observation against those bytes;
3. source at the exact mapped commit;
4. current public source/configuration;
5. official documentation or owner evidence;
6. unsupported inference.

Lower-ranked evidence cannot override contradictory higher-ranked evidence.

## Collect and separate

Collect exact package identity, nuspec, files, target frameworks, direct/transitive dependencies,
bundled assets and their license/notice evidence; map source to its exact commit when available.
Keep strong-name identity, Authenticode, package author signature and repository countersignature
separate.

| Decision point | Action and conclusion boundary |
|---|---|
| Selecting a package for a probe | Resolve its actual path and SHA-256 from the active confirmed manifest, relative to the confirmed root; use the new final manifest after reconfirmation. Recompute the file digest before passing that exact path. Stop the package probe on an identity mismatch rather than substituting a same-named copy. |
| Recording a command | Preserve the actual command and arguments, including package path, archive prefix/entry and options, with separately observed stdout/stderr and exit code for each operation. Capture a verifier's exit before a later command or pipeline masks it; a later shell exit is not the inner verifier's exit. An uncaptured exit stays unknown, and a corrected argument is a new attempt. |
| Comparing package copies or entries | Keep both whole-package digests and, for an entry observation, each containing package, exact entry path and recomputed entry digest. Same ID/version is not byte identity. Equal entry bytes establish only that entry correspondence; retain the original probe's attribution and do not transfer package-level or package-signature results. |
| Interpreting release/SBOM/provenance correspondence | Compare like identity kinds: a package-file checksum and a package-verification code are not interchangeable. Preserve any whole-package mismatch without assuming every entry differs. Assess publication, dependency/asset representation, notice coverage and exact-target correspondence separately; a mismatch does not erase other observed facts. |

Repository evidence may be reused only for the same package ID/version/digest and source commit.
Component evidence cannot prove repository-wide rows.

Every selected record must bind to the confirmed input manifest. Documentation binds exact URL and
captured digest; package evidence binds the exact nupkg or recomputed archive entry; source binds an
exact confirmed `source:<path>` capture and digest; owner evidence binds exact basename,
classification, and digest. Treat `owner-supplied-public-evidence` and
`owner-supplied-internal-evidence` as distinct first-class provenance kinds.

Distinguish configured build/sign/SBOM/release intent, published artifacts and completed
operations using [status boundaries](status-boundaries.md#decision-order). Use `gap` for
directly observed missing/contradictory required public artifacts. Use
`owner evidence required` for inaccessible private approval, retention, signing, or legal records.
A rebuilt package cannot verify the distributed artifact.

For `PI-06`, `PI-07`, `PI-10`, and `PI-11`, publication is the required surface. When complete
exact-package, public-release-asset, and release-workflow inventories contain no required
SPDX/CycloneDX SBOM or provenance artifact, use `gap`; the absence is direct evidence, not an unrun
probe. Use `not tested` when that coverage is incomplete or blocked.

For `PI-08` and `PI-09`, missing SBOM bytes alone are insufficient. First establish the applicable
third-party asset or notice surface, then inspect its representation. Use `gap` only when complete
typed asset/dependency/notice evidence directly shows missing or incomplete representation. Use
`not tested` when the representation evidence is absent or incomplete, and `not applicable` only
when complete inventories prove there is no applicable third-party asset or notice surface.

For `PI-08`, inventory the actual distributed JS/CSS surface, including vendored or inlined code
and nonempty `sourcesContent` in shipped source maps. Package-entry and content evidence establish
that those bytes are distributed, including an orphaned map that no bundle references. Bundle/map
linkage establishes correspondence to a bundle, not whether the map's embedded bytes shipped.
A source path without its bytes is not distribution evidence.
Inspect embedded content even under first-party-looking paths:
`node_modules` matches are only part of the surface, not proof of complete SBOM coverage.
Establish third-party attribution and identity/version from the content and corroborating release
records, not an arbitrary filename or copyright token. No runtime execution is needed to establish
that bytes are shipped. Compare each attributable component with the complete supplied SBOM,
including supported identity/version and correspondence. A demonstrated omission is `gap`; when
a necessary attribution or correspondence fact is genuinely missing, use `not tested`, not an
invented omission or version. An absent metadata field alone does not defeat otherwise evidenced
representation or create a new mandatory evidence format.
Use `verified` only when the applicable distributed surface is sufficiently represented. Preserve
supported positive dependency matches even when another embedded component is missing.

For `LP-03`, `verified` requires an admitted version-bound release-wide SBOM inventory
and each exact inventoried nupkg's own supported OSI-approved, non-copyleft nuspec expression,
classified by the same pinned LP-01 policy. The deterministic profile relies explicitly on the
caller's raw-digest/root-bound authoritative release-wide inventory designation; structural parsing
does not independently prove completeness or publication. Ordinary grant files, reviewer packets
and owner approval are not prerequisites. Missing/ambiguous/unsupported inventory, designation,
bytes or declarations (including NOASSERTION and file-only/URL-only licenses) stay `not tested`,
with evidence-acquisition follow-up; only a demonstrated incompatible declaration supports `gap`.
Build tooling in the SBOM counts. See [eleven-row intake](eleven-row-autofill.md); PI-06/PI-07
publication/enumeration outputs remain separate and unassigned. Passing LP-03 is not legal approval.

### Verified-boundary protocols

- `LP-04`: the current D-lite resolver (`2.0.0`) inventories only bounded JS/CSS/maps in
  supported assessed-package layouts. Every outcome is `not tested`, including an empty
  profile, with substantive follow-up; no origin, SBOM, applicability, legal or notice
  conclusion follows. Preserve the full sorted path/length/hash inventory and digest.
  V1 packets are retired/refused, never a deciding fallback. See [eleven-row intake](eleven-row-autofill.md).
- `PI-02`: a PE certificate table or signer subject proves only embedded signature material.
  `verified` requires an `authenticode-verification-v1` protocol covering every shipped DLL entry,
  the exact package-entry digest, expected and observed identity, file-digest verification, chain
  disposition, timestamp disposition, revocation disposition, and a digest-bound raw verification
  log.

The validator enforces these protocol shapes and package-entry coverage. It does not independently
replace the platform signature verifier or legal notice review; the protocol binds those direct
results so weaker metadata hints cannot be promoted to `verified`.

The validator retains its historical `protocol:notice-coverage-v1` gate for externally
supplied LP-04 verified/gap decisions only; D-lite cannot produce either and needs no
validator change. Do not generate that protocol for D-lite. New review protocols, npm
admission, verified/gap machinery and validator v2 are deferred. Register Authenticode protocols as
`reproduced-runtime-observation` with method `protocol:authenticode-verification-v1`. In both cases,
the locator is the confirmed protocol basename and its digest must match `evidence_inputs`.
The historical notice protocol accepts `complete` or `incomplete`; that is not a D-lite
decision path. Authenticode remains schema version 1 with
method `protocol:authenticode-verification-v1`. Its `file_digest_disposition` is `valid`, `invalid`
(signature/file-digest material is present but verification failed), or `absent` (direct verification
found no Authenticode signature/file-digest material, as with an unsigned DLL). For `absent`, require
`chain_disposition`, `timestamp_disposition`, and `revocation_disposition` all exactly
`not-applicable`. Keep `expected_identity` substantive and name the required signing identity, not
`not-applicable`; set `observed_identity` exactly to `not-applicable` because there is no signer to
identify. Retain the exact DLL digest and digest-bound raw verification log. Any absent artifact
makes the protocol result `failed`: it supports a `PI-02` `gap`, never `verified`. Do not label an
unsigned file's digest `invalid` or reinterpret retained legacy `invalid` records.

For `valid`/`invalid` file-digest dispositions, preserve the existing layer sets: chain is `valid`,
`invalid`, or `not-tested` (never `not-applicable`); timestamp and revocation also allow
`not-applicable`. `verified` requires matching expected/observed identity, valid file digest and
chain, and valid or not-applicable timestamp/revocation. Any absent artifact, identity mismatch, or
invalid layer makes the protocol result `failed`. If no failure exists but any permitted layer is
`not-tested`, the result is `incomplete`; only conclusive valid/not-applicable layers produce
`passed`. A `PI-02` `gap` requires a structured `failed` result, while `incomplete` supports
`not tested`, not `gap`.
When exact DLLs exist but the Authenticode protocol lacks digest, chain, timestamp, revocation, or
expected-identity results because the probe was unrun or incomplete, use `not tested`, not `absent`,
unless the unresolved prerequisite is specifically an owner-only identity declaration.

## Requested implementation guidance

For requested SBOM/signing/provenance recommendations, use
[remediation guidance](remediation-guidance.md#sbom-and-package-patterns) from the existing
validated revision, without recollection or new research. Preserve `PI-03`, `PI-05`, `PI-06`
direct obligations, `PI-07` through `PI-09` decomposition checks, and the separate `PI-10` /
`PI-11` versioned extensions. Recommend a pattern only for an established cause; missing
publication, coverage, signing or owner-decision evidence instead calls for that exact input.
Do not turn guidance into a new evidence protocol or change a canonical status.
