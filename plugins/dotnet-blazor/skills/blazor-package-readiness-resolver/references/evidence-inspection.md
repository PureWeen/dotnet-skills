# Retained package evidence inspection

Use the installed `scripts/run-resolver.py inspect <inputs.json>` when the exact local package
and raw source/dependency archives are available but the stronger row-specific admission packets
are not. This preserves useful observations for LP-01/02/03/04/10 and PI-01; it is not another row resolver,
acquisition operation, license review or route to a more generous pass label.

The request is data, not an expected answer:

```json
{
  "schema_version": 1,
  "inputs": [
    {"role": "package", "path": "package.nupkg", "sha256": "<actual lowercase SHA-256>"},
    {"role": "source-archive", "path": "source.zip", "sha256": "<actual lowercase SHA-256>"},
    {"role": "dependency-000", "path": "dependency.nupkg", "sha256": "<actual lowercase SHA-256>"}
  ]
}
```

Only `package` is mandatory. Source is optional; supply each retained exact dependency once as
`dependency-NNN`, excluding the root. Missing dependencies must not be filled with fabricated
metadata or placeholder files. Reuse actual confirmed input paths/digests, never search host
caches or download missing inputs through this tool.

The same strict path/digest admission as `resolve` applies: ASCII relative paths beneath the
request directory, no links, duplicate roles, unknown fields or expected answers. Inspection
supports at most 64 distinct dependency versions, 66 inputs total, a 1 MiB request, 256 MiB total
checked bytes, and 8 MiB per nupkg. The optional source ZIP is at most 64 MiB with the existing
bounded safe ZIP/CRC/path/expanded-byte checks. This read-only source inspection additionally
admits interior ASCII spaces in archive path segments; leading/trailing spaces, traversal,
links and platform path syntax remain rejected. It never extracts entries, and the stricter
LP-02 verdict/admission path profile is unchanged. At most 64 source projects are inspected;
project XML is strict UTF-8, at most 1 MiB, with DTD/entity resolution prohibited.

The schema-1 output has producer `package-evidence-observations/1.0.0` and retains:

- every checked input role/path/digest;
- observed package/dependency identities, literal license declarations and dependency ranges
  with their declared target-framework groups;
- each root archive file's path, size and digest, plus named package/dependency/source
  license/notice candidates. Candidate text up to 4,096 bytes is retained as literal strict
  UTF-8; larger or unsupported text has a size/digest and explicit `text_state`, not a clipped grant;
- literal repository declarations, including duplicates rather than a favorable selected value;
- source archive digest/file count, literal declared-revision directory-prefix comparison,
  project SDK/PackageId declarations and ancestor build-file digests;
- exact nonempty root-entry/source-entry byte matches;
- root PE/CLI candidates, including renamed MZ images, checked through the existing strict
  PI-01 PE inspector before reading assembly identity, informational-version/repository
  attributes, public-key length, CLR signing flag and strong-name reservation size as data.
  Unsupported candidates have explicit states and null metadata, never invented unsigned fields;
- explicit diagnostics and claim limitations.

Razor SDKs, conditional declarations and inherited `Directory.Build.props`/targets are read as
data, not evaluated. All PackageId declarations are retained rather than selecting whichever
one would yield a favorable mapping. Unsupported or oversized project XML has an explicit
diagnostic and parse state; its digest and inherited-file inventory survive. An invalid archive,
binding or request fails explicitly. Output above 2 MiB fails rather than publishing a clipped
packet. Keep stdout, stderr and the actual exit: exits 2/3 are input/environment failures, not
product findings.

## What survives without a full-row decision

| Row | Useful observation | Still not established |
|---|---|---|
| LP-01 | Exact package license declaration and named retained text. The deciding resolver verifies an OSI-approved, non-copyleft expression for every offered alternative under the pinned policy. | Inspection alone does not classify the license. The affirmative resolver finding is declaration-scoped, not a legal interpretation of other files/releases or proof of owner authority; owner grant and release/source scope are not prerequisites for `approved-non-copyleft`. |
| LP-02 | Retained source archive, project/SDK/declaration facts and exact text matches. | Anonymous public retrieval, remote repository truth or compiled build correspondence. A matching archive prefix is only a local path comparison. |
| LP-03 | Supplied exact dependency versions and their literal licenses/ranges. | Complete resolved direct/transitive closure or applicable whole-version grants. A static minimum-version graph is not an admitted full resolved export. |
| LP-04 | Named license/notice entries, asset hashes and exact source matches. | Third-party attribution, complete obligations or exhaustive notice coverage. |
| LP-10 | Exact source-byte matches and per-PE declared assembly identity/version/repository metadata. | Authenticated authorship, referenced upstream identity or compiled binary-to-commit build mapping. |
| PI-01 | Each root PE/CLI candidate's checked signing state and fields. | Complete nested-assembly inventory or a package-wide verdict; those remain the deciding resolver's responsibility. An outer NuGet signature does not sign contained DLLs. |

No inspection property is a canonical readiness status, owner approval, legal conclusion or
replacement for a `resolve` evidence contract. A filename match is only a candidate, a supplied
dependency list is not proof of completeness, and a source byte match is not a build receipt.

In the full-report workflow, retain this JSON as supplemental `document` evidence alongside
the raw inputs and complete `resolve` output. Follow the consumer's post-output confirmation
and input-bound ledger sequence. Carry the supported fact **and** the remaining deciding fact
into the row observation even when its status remains unresolved. If new admissible row packets
are subsequently obtained, run `resolve` again and revise affected provisional decisions.
