# Deterministic discovery candidates

Use the bundled validator's `inputs candidates` commands to construct discovery input.
Supply observed facts as options; do not write candidate JSON, copy a confirmed manifest
back into discovery, add `content_sha256`, or generate your own candidate-building script.
The commands own the schema, object keys and field order. `inputs discover` computes
digests from retained bytes and applies the existing completeness and semantic checks.

Resolve `<launcher>` using the loaded skill. Full options are available with:

```text
<launcher> inputs candidates --help
<launcher> inputs candidates add-document --help
```

Start with the actual acquisition and source facts. For example, this fragment records a
published package acquired via the documented fallback and a source mapping not yet resolved:

```text
<launcher> inputs candidates init --acquisition published --package-locator https://www.nuget.org/api/v2/package/Example.Widgets/1.0.0 --package-method package-feed --source-availability unresolved --output candidates-00.json
<launcher> inputs candidates add-document --input candidates-00.json --url https://example.test/widgets/docs --path acquisition/docs.html --output candidates-01.json
<launcher> inputs candidates add-retrieval --input candidates-01.json --subject package --locator https://www.nuget.org/api/v2/package/Example.Widgets/1.0.0 --method package-feed --result succeeded --output candidates-02.json
```

This is a construction example, not a complete assessment or evidence that those example
resources exist. Replace example values with the actual facts. At initialization, use
`--repository-uri`, `--source-commit`, `--source-mapping`, and `--source-confidence`
when supported by the discovered source mapping. Do not infer closed source from a failed fetch.

`--package-method` and `add-retrieval --method` use the same fixed vocabulary exposed by
`inputs candidates --help` and enforced by discovery. NuGet v3 and v2 both use `package-feed`;
retain their distinct URLs, results, and fallback details. HTTP downloads of source archives,
documentation, or release metadata use `direct-download`, not provider-specific labels.
Git retrieval uses `repository-fetch`. Do not invent method names or treat public downloads
as `owner-supplied`. Invalid method values fail before any candidate is written.

Each add command reads the previous candidate file and writes a **new** file. Continue
from the latest output; preserve the earlier file. Paths embedded in candidates are relative
to the later `inputs discover --root`, not relative to the candidate file itself.
Quote shell arguments containing whitespace. The code does not retrieve files or establish
that a locator is official; it records the supplied facts without inventing provenance.

Use the relevant typed commands for the rest of the discovered input closure:

| Command | Facts recorded |
| --- | --- |
| `add-document` | Official URL and retained local content path. |
| `add-package-source` | Source kind, locator and retained path, such as extracted metadata or README. |
| `add-source-artifact` | Repository-relative source path and retained local path. |
| `add-retrieval` | Actual subject, locator, method, result and optional detail, including failed attempts. |
| `add-evidence` | Supplemental evidence path and its existing contract kind. |
| `add-owner-input` | Actual owner-input path and provenance; public downloads are not owner attestations. |
| `add-component` | Confirmed component identity, modes, source paths and explicit lifecycle applicability. |
| `add-exclusion` | Explicit subject and rationale. |

`add-component` accepts repeated `--mode`, `--source-path`, and `--lifecycle-trigger`
options. Only record real confirmed components when in scope; do not invent a component
to satisfy validation. Empty collections in a newly initialized candidate mean no records
have been added yet, not an owner-confirmed absence or an applicability decision.
For package-only scope, omit `add-component`; discovery and confirmation accept an empty selected
component list. It does not claim the package contains no controls. Package/source/evidence
requirements still apply, and full-library inventories still require confirmed components.

After the complete candidate record and owner confirmation required by the skill:

```text
<launcher> inputs discover --root <output> --nupkg <exact.nupkg> --candidates <latest-candidates.json> --output <input.draft.json>
<launcher> inputs confirm --root <output> --draft <input.draft.json> --output <input.confirmed.json>
<launcher> inputs validate --root <output> --manifest <input.confirmed.json>
```

Successful construction proves the serialized input shape, not source mapping truth,
completeness, owner confirmation or report readiness. Unknown options, malformed existing
candidate records and existing output paths are errors; do not strip fields or hand-repair
the generated files after an error. The existing raw-candidate discovery parser remains
strict and is not a substitute for the construction commands in ordinary assessment runs.
