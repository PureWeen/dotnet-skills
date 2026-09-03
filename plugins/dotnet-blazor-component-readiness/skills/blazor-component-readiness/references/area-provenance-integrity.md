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

- exact package identity, digest, nuspec, files, target frameworks, dependencies, and bundled assets;
- source mapping and exact commit, when available;
- strong-name identity, Authenticode, package author signature, and repository countersignature as
  separate layers;
- SBOM/provenance correspondence to the final package digest;
- build/sign/SBOM/release evidence without assuming configured intent executed;
- license/notice evidence for direct, transitive, and bundled assets.

Repository evidence may be reused only for the same package ID/version/digest and source commit.
Component evidence cannot prove repository-wide rows.

Every selected record must bind to the confirmed input manifest. Documentation binds exact URL and
captured digest; package evidence binds the exact nupkg or recomputed archive entry; source binds an
exact confirmed `source:<path>` capture and digest; owner evidence binds exact basename,
classification, and digest. Treat `owner-supplied-public-evidence` and
`owner-supplied-internal-evidence` as distinct first-class provenance kinds.

Use `gap` for directly observed missing/contradictory required public artifacts. Use
`owner evidence required` for inaccessible private approval, retention, signing, or legal records.
A rebuilt package cannot verify the distributed artifact.

### Verified-boundary protocols

- `LP-04`: license files and detected sidecars prove only their own presence. `verified` requires a
  canonical `notice-coverage-v1` protocol whose complete dependency inventory, bundled-asset
  inventory, and notice mapping are each digest-bound confirmed inputs.
- `PI-02`: a PE certificate table or signer subject proves only embedded signature material.
  `verified` requires an `authenticode-verification-v1` protocol covering every shipped DLL entry,
  the exact package-entry digest, expected and observed identity, file-digest verification, chain
  disposition, timestamp disposition, revocation disposition, and a digest-bound raw verification
  log.

The validator enforces these protocol shapes and package-entry coverage. It does not independently
replace the platform signature verifier or legal notice review; the protocol binds those direct
results so weaker metadata hints cannot be promoted to `verified`.

Register notice protocols as `reviewer-generated-analysis` with method
`protocol:notice-coverage-v1`. Register Authenticode protocols as
`reproduced-runtime-observation` with method `protocol:authenticode-verification-v1`. In both cases,
the locator is the confirmed protocol basename and its digest must match `evidence_inputs`.
Notice coverage may resolve `complete` or `incomplete`; Authenticode artifacts may record valid,
invalid, not-tested, or not-applicable layer dispositions. `verified` requires the all-valid shape,
while `gap` requires a structured failed/incomplete outcome rather than a malformed protocol.
