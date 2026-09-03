# Blinded comparison input gate

This is evaluation methodology, not an ordinary readiness requirement. Use it only when the user
explicitly requests a blinded accuracy, replay, or oracle comparison.

## Freeze before the blind worker starts

Create a conclusion-free draft that contains:

- exact package ID/version and the allowed nupkg input;
- every exact source snapshot identity, including availability, repository, commit, and source
  archive input when source is available;
- the complete allowed-input set with neutral IDs, kinds, relative paths, sizes, and CLI-computed
  digests;
- every raw package/document/source retrieval record;
- every raw probe input;
- named toolchain and browser identities with raw identity inputs when relevant;
- `available` or `blocked` disposition for every retrieval, probe, toolchain, and browser;
- an exact blocker for every `blocked` item.

Run:

```text
<launcher> comparison inputs-freeze --root <bundle-root> --draft <comparison-inputs.draft.json> --output <comparison-inputs.confirmed.json>
<launcher> comparison inputs-validate --root <bundle-root> --manifest <comparison-inputs.confirmed.json>
```

The gate fails when an input is missing, stale, unreferenced, outside the allowed set,
conclusion-bearing, or left `unresolved`. Available trim/AOT probes require a named available
toolchain. The blind worker must receive only the confirmed manifest and allowed files and must
re-run `inputs-validate` before reading the evidence or starting assessment work.

Do not include statuses, findings, recommendations, scorecards, feedback, oracle conclusions,
revealing filenames, or historical report text. Unblind and compare only after the worker's
assessment is frozen.
