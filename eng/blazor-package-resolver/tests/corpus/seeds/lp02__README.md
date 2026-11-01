# LP-02 public-availability v1.1 contract

## Purpose and stage boundary

`lp02-public-source/1.1.0` establishes a **qualified public-source-availability
fact for the exact checked package**. Only `public-source-observed` is
positive. Its finding states the package-declared repository, exact commit
and capture time, the anonymous retrieval and checked nonempty archive root.
The package declaration supplies the release association; source relevance is
not independently established. The finding explicitly says that this does
**not** establish that the published binaries were built from that revision.
Clause 1.2 requires public source for shipped versions, not a particular SDK,
literal project PackageId, or MSBuild evaluation. Project facts are supplemental.

GitHub codeload can serve fork-network commit objects through the declared
repository URL. Successful retrieval therefore does **not** prove that the
commit belongs to that repository's branches or tags. The positive finding
states this qualification; LP-02 does not perform a network membership check.

Do not infer repository ownership, complete build closure, reproducible
builds, binary/source correspondence, license compliance or overall
readiness. Stronger correspondence/provenance belongs to LP-10/PI-11.
No release tag, private-source conclusion, build reproduction, embedded
source-repository manifest or caller acceptance boolean is part of LP-02.
The copied rubric/basis remain byte-pinned; this is the qualified operational
contract for this handler, not a rewrite of those source documents.

Acquisition may retrieve source; the deterministic resolver is **offline**.
It only consumes `CheckedInput` bytes already SHA-256-validated by dispatch.
It does not reopen paths, inspect Git state, read credentials, execute code,
invoke `gh`, evaluate MSBuild or access the network.

## Supported package and source profile

- Ordinary, bounded NuGet ZIPs: at most 64 MiB compressed and 64 MiB total
  uncompressed, 4096 entries, 8 MiB central directory, and safe ASCII relative
  entry paths of at most 256 characters. Source archives additionally admit
  interior ASCII spaces in path segments, reusing the existing safe inspection
  predicate; leading/trailing spaces remain unsupported. Package paths retain
  the stricter profile. Reject dot/dot-dot segments,
  backslashes, absolute paths, case aliases, symlinks, encryption, Zip64,
  unsupported flags/methods, inconsistent headers/lengths/CRCs and unsupported
  archive framing. ZIP storage and normal Deflate use the existing bounded
  archive validator, not a new codec or decompressor. The standard root
  NuGet packaging entry `[Content_Types].xml` is explicitly supported.
- Exactly one root nuspec, at most 1 MiB. Reuse the recognized NuGet namespace
  and metadata-sibling rules. Accept strict UTF-8 (optional BOM) or BOM-marked
  UTF-16 LE/BE; if present, the XML encoding declaration must say `utf-8`
  or `utf-16` respectively, case-insensitively. DTDs/entities are prohibited.
  Exactly one nonblank, simple direct ASCII id/version (at most 256 characters)
  and no ambiguous repository
  element may supply identity. Repository attributes are limited to unqualified
  `type`, `url`, `commit`, `branch`; URL/commit must both be nonblank.
- Repository profile: `https://github.com/{owner}/{repo}`, optionally normalizing
  a terminal `.git`. No userinfo, query, fragment, port, trailing slash,
  arbitrary host, path encoding or ref/tag lookup. Owner/repository use the
  documented implementation's bounded ASCII GitHub-name pattern. Commit is
  a full nonzero 40-hex SHA-1, normalized to lowercase. Other object formats
  and environments are unresolved, not evidence of closed source.
- Retain the complete bounded codeload ZIP. All files must be under the
  `{repo}-{commit}/` root (case-insensitive root comparison), and at least one
  file must exist. Empty and directory-only archives reject. Optional selected
  supplemental files have exact archive paths and SHA-256 digests, but project
  or implementation selection is not required. Source ZIPs may have
  GitHub's 40-byte exact-commit archive comment (or no comment); arbitrary
  comments are unsupported. Package ZIPs remain comment-free, preserving
  LP-01's existing validator behavior.
- Razor or other SDKs, conditional declarations, imports, targets and inherited
  build files do not gate public availability. No project XML or implementation
  bytes are evaluated for relevance. Selected supplemental files, if supplied,
  must still exist and match their exact digests within archive limits.
  The schema retains a nonblank ASCII `mapping_rationale` of at most 1000
  characters for compatibility; it describes the declaration/acquisition
  association, not an independently proven library-source mapping.

Outside-profile archives or acquisition evidence escalate conservatively.
Project language, package-ID inference and arbitrary build evaluation are not
part of this availability check.

## Acquisition procedure

The installed eleven-row helper produces an observation from its own single
successful anonymous codeload download, using the original request timestamp,
exact package ID spelling, and retained archive digest. It supplies an empty
supplemental inventory. Local imports, offline mode, unsuccessful downloads and
budget skips never generate public-retrieval observations. Explicitly supplied
checked observation/archive packets remain replayable offline.

The separate repository-only acquisition command remains compatible. If using it,
supply exact supplemental paths, including the commit root, and a short rationale:

```powershell
dotnet run --project eng\blazor-package-resolver\BlazorPackageResolver.csproj -- acquire-lp02 package.nupkg capture-new repo-COMMIT/src/Library/Library.csproj repo-COMMIT/src/Library/Widget.cs "The literal PackageId identifies this library; Widget.cs is adjacent library implementation."
```

The command reads and validates the package before constructing the one fixed
URL `https://codeload.github.com/{owner}/{repo}/zip/{commit}`. Its dedicated
HTTP handler disables default/explicit credentials, cookies, proxy discovery,
redirects and automatic decompression; it supplies only a fixed user agent.
It does not use browser state, `gh`, Git helpers, API tokens or ambient
application authentication. Normal TLS certificate validation and revocation
checks remain enabled. Environments requiring proxies or credentials are
unsupported; do not weaken the transport to obtain a positive.

One GET, no retries or fallback hosts, 60-second total timeout, 16 KiB
response-header setting and 64 MiB streamed response cap bound retrieval.
Only HTTP 200 without Content-Encoding retains `source.zip`.
404 -> `not-found`; 401/403 -> `auth-required`; 429/451 -> `blocked`;
5xx/network/timeout -> `unavailable`; redirects, other statuses, encoded or
oversized responses -> `unsupported`. Every such result generates
`observation.json`, with no success capture/inventory for unresolved attempts.
The destination must not already exist. Filesystem failures are CLI errors,
not successful captures. Preserve the generated receipt and archive together;
do not hand-author an access assertion.

The command hashes source files at the explicitly supplied paths; it does not
force them to be relevant. Missing explicit selections are acquisition errors,
not silently omitted inventory entries. The helper does not invoke this command
after downloading: that would perform a second GET outside the collector's budget.

## Observation schema and checked bindings

`observation.json` is strict UTF-8 JSON, maximum 16 KiB and depth 8, with
duplicate/unknown fields rejected. There are no acceptance booleans.
Malformed UTF-8, escaped Unicode or deferred JSON string/field decoding
failures produce `observation-invalid`, never an unhandled exception.

```json
{
  "schema_version": 1,
  "producer": "lp02-anonymous-github/1.0.0",
  "package_id": "Sample.Library",
  "package_version": "1.0.0",
  "package_sha256": "<64 lowercase hex>",
  "repository_url": "https://github.com/owner/repo",
  "commit": "<40 lowercase hex>",
  "retrieval_attempt": {
    "url": "https://codeload.github.com/owner/repo/zip/COMMIT",
    "observed_at_utc": "2026-10-30T12:00:00Z",
    "transport": "direct-https-no-credentials/1",
    "result": "retrieved",
    "http_status": 200
  },
  "capture_receipt": {
    "role": "source-archive",
    "sha256": "<64 lowercase hex>"
  },
  "source_inventory": [],
  "mapping_rationale": "The package declares this repository and revision; anonymous retrieval retained this archive."
}
```

Use checked roles `package`, `source-observation`, `source-archive` in the
existing schema-version-1 replay suite; pin each file's path and SHA-256.
The receipt binds exact package ID/version/digest, normalized repository,
commit and codeload URL; the capture digest binds the retained archive;
the optional inventory binds up to two unique selected paths/kinds
(`project`, `implementation`) and their actual bytes without semantic mapping.
An unresolved attempt instead has `capture_receipt: null` and an empty
inventory; the status must match its result. A transport failure has
`http_status: null`. UTC times must use `yyyy-MM-ddTHH:mm:ssZ`.

These are machine-generated acquisition observations at a checked-evidence
boundary, **not signed attestations**. Offline hash checks cannot prove that
a dishonest party did not fabricate a receipt/archive or independently attest
the transport's history. Use the supplied acquisition operation and preserve
its output; never substitute a hand-authored `public=true`, correspondence
assertion or a repository-embedded `.lp02-source.json`.

## Ordered branches and status

| Branch | Meaning |
|---|---|
| `missing-package` | Exact package absent |
| `package-unreadable` | Package/identity outside the safe unambiguous profile |
| `source-declaration-missing` | Package has no complete URL/commit declaration |
| `public-retrieval-unresolved` | Declaration outside retrieval profile, or retained attempt unresolved |
| `observation-missing` | Required checked observation or successful attempt's archive absent |
| `observation-invalid` | Unsupported/malformed receipt, inventory or source archive |
| `observation-binding-conflict` | Exact package/revision/archive/selected-byte bindings disagree |
| `source-relevance-unestablished` | A supplied supplemental selected file is missing (legacy branch name) |
| `public-source-observed` | The sole qualified positive |

Validation order follows package -> declaration/profile -> observation shape
-> package/retrieval binding -> attempt state -> archive binding/profile ->
optional selected-file bindings. Every nonpositive result is an
escalation with unknown applicability and no factual finding: unresolved /
`not tested`, **not** closed-source or a gap.

## Focused validation and retained replay

There are **51 named synthetic cases**: 33 oracle/replay cases and
18 runtime cases covering generated anonymous observations, unresolved HTTP
states, network failure, header/stream caps, receipt/archive resource
boundaries, path/root safety, optional inventory and missing explicit selections,
checked-buffer/culture determinism, non-gating Razor/MSBuild/encoding variants,
malformed receipt Unicode, empty/directory-only archive rejection, and interior
space admission with traversal/edge-space/platform-path rejection.
Runtime cases group related boundary/status assertions;
they are not an exhaustive cross-runtime differential matrix. The independent
Python oracle specifies expected branches and bytes without importing or
invoking production code. The ordinary tests never access the network.

```powershell
python eng\blazor-package-resolver\tests\lp02_expectations.py
dotnet run --project eng\blazor-package-resolver\tests\ResolverChecks.csproj -- lp02
python eng\blazor-package-resolver\tests\lp01_expectations.py
dotnet run --project eng\blazor-package-resolver\tests\ResolverChecks.csproj
dotnet run --project eng\blazor-package-resolver\BlazorPackageResolver.csproj -- coverage
```

`--write` on the Python oracle materializes its specified synthetic inputs
and expectations, never production results. `acceptance.json` separately
pins the two vendor packages using the already accepted LP-01 retained
identities. Supply both `LP02_SYNCFUSION_NUPKG` and
`LP02_INFRAGISTICS_NUPKG` to run actual retained replay. The runner verifies
their exact byte counts/digests, stages only those supplied bytes, and replays
the frozen expectations. The binaries remain outside Git. Both expected
outcomes are `observation-missing`, qualified **declared-source-unverified**,
until real checked anonymous acquisition evidence and the bound archive are supplied.
Do not infer a positive from their repository declarations.
