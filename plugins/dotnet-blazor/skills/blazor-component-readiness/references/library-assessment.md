# Full-library assessment

This orchestration is not required for a standalone Library and release report. Package-only
uses `assessment init --kind package`, report verification, and the package reader without a
component inventory or library index. The original library source-closure requirement below
still applies to its analyzer, trim, and AOT checks.

## Capability gate

Full-library work requires separate top-level writable worker sessions. Nested custom agents are
text-only and cannot own validator artifacts. If separate sessions are unavailable, stop before
inventory confirmation with `unsupported host: full-library assessment requires isolated workers`.
Do not serialize all components through one shared model context.

## Inventory and ownership

Discover a draft containing every package/version or candidate digest, acquisition mode, package
input/revision paths, component ID/display name, component input/revision paths, allowed source
paths, claimed render modes, and exclusions. Show it to the owner and freeze only after correction
and confirmation.

Create:

- one package unit per exact package ID/version/nupkg digest, owning the 60 repository-wide/conditional rows;
- one component unit per confirmed component, owning the 61 component-specific rows and every
  claimed mode;
- exactly one top-level writable worker session per unit.

A component handoff receives only its unit inputs and exact package revision. Reject sibling
documents/source/evidence, duplicate unit IDs, changed package identities, missing modes, or
repository-wide rows in a component result.

Before library analyzer, trim, or AOT checks, acquire and record the original library source
closure for the exact package identity: repository/archive provenance, source revision, and the
actual library project or solution. A synthetic consumer that references the package is not the
reviewed library target. If the original project or closure is unavailable, record the bounded
missing input and keep the corresponding result incomplete.

## Run state and receipts

`inventory.confirmed.json` is immutable. `run-manifest.json` is an atomically replaced,
reconstructable cache with `pending`, `active`, `completed`, `blocked`, or `incomplete` units.
Each non-derived transition is backed by an append-only state receipt under the run root containing
run/inventory identity, unit ID, sequence, prior receipt digest/sequence, state, missing inputs,
blocked probes, transition time, and reason.

Completed units name the output revision, report path, validation-manifest path/digest, status
counts, and package-manifest binding when applicable. Never hand-edit these fields.

## Interruption and resume

Use the loaded skill's launcher and confirmed output root:

```text
<launcher> inventory status --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json
<launcher> library reconcile --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json
```

1. Leave completed revision directories untouched.
2. Record active work as incomplete; record bounded missing inputs and blocked probes.
3. Run `inventory status`.
4. If the run manifest is missing/invalid or after interruption, run `library reconcile`.
5. Recompute every completed manifest digest and accept only valid inventory-bound units.
6. Resume pending, blocked-after-input, or incomplete units in fresh top-level worker sessions.
7. Keep the library state `incomplete` until every confirmed unit validates.

## Completion

Run `library reconcile`, `library validate`, then `library index`. The index is generated only from
validated manifests and contains package/version identities, completed/incomplete components,
factual status counts, report links, missing inputs, and blocked probes. It contains no default
verdict, ranking, or remediation priority.

```text
<launcher> library validate --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json
<launcher> library index --root <output> --inventory <output>/inventory.confirmed.json --run-manifest <output>/run-manifest.json --json <output>/library-index.json --markdown <output>/library-index.md
```

Index publication is generation-based. Both authoritative files are committed together beneath
`.readiness-index/generations/<generation-id>/`, then one regular-file
`.readiness-index/current-generation.json` pointer is atomically replaced. The requested
`library-index.json` and `library-index.md` paths are compatibility caches; every index run detects
and repairs cache drift from the pointer while holding the run lock. Interrupted publication before
or after pointer replacement is recovered on the next run without exposing a mixed authoritative
generation.
