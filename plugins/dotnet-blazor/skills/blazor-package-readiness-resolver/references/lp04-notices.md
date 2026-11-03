# LP-04: D-lite inventory and provenance-assisted notice checks

`lp04-notice-coverage/2.1.0` package-only D-lite classifies bytes in the exact assessed nupkg under
`bundled-web-assets/1`. It does **not** make a legal determination, establish
origin, infer SBOM coverage, determine applicability or decide notice preservation.
Every D-lite result maps to **not tested**, with a missing fact and smallest next action.
The optional provenance-assisted path has a separate trusted-helper boundary:
see [provenance admission](provenance-admission.md). Do not apply D-lite's nonclaims
to that additional path or treat its observations as provenance admission.

## Surface and bounds

Select `.js`, `.mjs`, `.cjs`, `.css` and `.map` file entries under:

- `staticwebassets/**`
- `wwwroot/**`
- `contentFiles/<language>/<tfm>/wwwroot/**`

Match root segments and suffixes ASCII-case-insensitively. Preserve every distinct
original path, empty/minified/generated/isolated files, orphan/source maps and all TFM
copies. Equal bytes at different paths remain separate assets. Never inspect a restored
dependency, source repository or running package to derive this surface.

Recognized suffixes outside these roots, and one-layer `.gz`/`.br` variants of these
suffixes anywhere, are unsupported candidates. Retain their full sorted path list.
This is not an HTML, PE-resource, nested-archive or arbitrary renamed-payload scanner.

Admit at most 8 MiB compressed nupkg, 4096 entries, 64 MiB total expanded bytes,
512 selected assets and a 1 MiB root nuspec. There is no 1 MiB per-asset cap.
Preflight total expanded sizes and selected count before any entry is streamed.
Reuse raw ZIP range/name/encoding/CRC, traversal, symlink, duplicate/casefold-alias
and strict nuspec checks. Reject incomplete or unsafe input, never reinterpret it as empty.
Do not extract files to disk, restore packages or execute assessed code.

## Closed decisions

| Reason | Missing fact / smallest action |
|---|---|
| `missing-package` | Exact package unavailable; obtain its bytes. |
| `input-invalid` | Safe bounded complete input unavailable; repair/reacquire it. |
| `legacy-protocol` | Retired v1 evidence supplied; rerun a package-only request without v1 roles. |
| `surface-unsupported` | Listed representations unassessed; assess their origin/obligations separately. |
| `no-supported-layout-assets` | Applicability still unknown; assess other representations or obtain explicit applicability evidence. |
| `origin-review-missing` | Selected assets' origin/obligations unknown; review the retained inventory. |

The empty observation includes exactly:

> No JS/CSS assets detected in the supported package layouts; other representations were not assessed.

An empty supported profile is **not proof of no bundled web code**, and never universal
not applicable. D-lite produces no verified, gap, owner-evidence or not-applicable outcome.
After missing/invalid package checks, recognized v1 roles are refused, not converted.
There is no active v1 deciding fallback, per-TFM graph, all-root classification, dependency
archive, whole-subject obligation review or notice-packet deciding path.

## Retained inventory

Surface results retain `bundled_web_assets` in the checked resolver result:
`profile`, ordinally sorted `assets` (`path`, `length`, `sha256`),
`unsupported_candidates`, and `inventory_sha256`.
The helper registers and digest-binds that whole result as evidence; the row observation
only displays counts by suffix, total selected bytes and the digest, never a clipped inventory.
The observation must fit 4096 UTF-8 bytes or the helper fails rather than truncating.

Digest canonicalization is UTF-8 without BOM: `bundled-web-assets/1` plus LF,
then each selected asset in .NET ordinal path order as
`path` + TAB + invariant decimal byte length + TAB + lowercase SHA-256 + LF.
Safe paths cannot contain TAB/LF. ZIP record order and timestamps do not affect this digest.
Unsupported paths are retained separately; the selected-asset digest is not a digest of them.

## Provenance-assisted path

The five input roles are `package`, `release-package`, `provenance-bundle`,
`provenance-attestation` and `source-archive`. Source acquisition and verification
receipts must be helper-admitted, not caller assertions. Mode A requires a digest-bound
per-asset source/component map, lockfile runtime closure and SPDX-specific complete
canonical notice clauses. All runtime dependencies require notices, including SSR shims.
Mode B stays unverified because source equality and absent banners do not prove authorship.
Missing facts yield `provenance-notices-unverified`, preserving the full asset inventory.

Native `provenance-notices-verified` is not a report-validation bypass. The validator
still requires its separately registered `protocol:notice-coverage-v1` for verified/gap;
the weak native-result fallback has been removed. No v2 notice protocol is introduced.
