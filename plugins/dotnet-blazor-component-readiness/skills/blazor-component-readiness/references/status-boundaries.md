# Status boundaries

Use exact, case-sensitive tokens:

| Status | Required boundary |
|---|---|
| `verified` | Direct applicable source, exact artifact/configuration, owner attestation, or reproduced behavior satisfies the row. Cite selected evidence. |
| `gap` | Direct evidence shows the product, artifact, documentation, behavior, or required public control conflicts with the row. Cite the observation. |
| `owner evidence required` | The row can be established only by an owner-held private record, attestation, approval, or inaccessible control. State the requested evidence. |
| `not tested` | The row applies, but acquisition/probe/evidence was unavailable, blocked, not run, or insufficient. State the blocker and smallest next probe. |
| `not applicable` | The row genuinely does not apply to the confirmed deliverable or explicit support claims. Give a rationale; unknown is not inapplicable. |

Calibration:

- A failed package/document/source retrieval is `not tested`, not a `gap`.
- Direct absence of required metadata in the exact nupkg is a `gap`.
- Missing private signing, review, retention, accessibility, or support evidence is
  `owner evidence required`.
- Source attributes may verify source structure; they do not verify browser semantics or formal
  conformance.
- A successful build does not verify runtime behavior.
- An environmental probe blocker is `not tested` unless direct evidence ties the failure to the
  package.
- An unsupported optional mode may be `not applicable` only when explicitly unclaimed and safe.
- A package signature verifies only that signature layer.
- License or notice sidecars verify only those exact files, not complete notice coverage.
- A PE certificate table or signer subject does not verify Authenticode file-digest, chain,
  timestamp, or revocation validity.
- Organization, author, or contact metadata does not verify accountable support ownership,
  backup, or escalation coverage.
- Feedback and decision guidance never establish a status.

Do not substitute alternate status words or abbreviations.
