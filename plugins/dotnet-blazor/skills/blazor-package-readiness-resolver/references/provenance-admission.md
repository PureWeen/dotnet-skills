# Trusted provenance admission

Use the installed `blazor-component-readiness` autofill helper for provenance-assisted
LP-04/LP-10. Do not construct verification receipts or set the admission-key environment
variable yourself. Direct `run-resolver.py resolve` calls with caller-authored Sigstore or
`gh` result JSON cannot authenticate it and return an unverified branch.

The trusted boundary comprises the installed helper, its resolver child, `gh`, their
executable/environment integrity, the HTTPS transport, and the helper's private working
directory. It does not defend against an attacker who can replace those executables,
inspect child process secrets or modify the trusted process. Never execute assessed source.

The helper:

1. Downloads the exact package-declared 40-hex commit from the canonical repository's
   anonymous codeload endpoint, reusing LP-02's checked acquisition record. Retain the URL,
   commit, SHA-256, byte size and actual request time. A local `--source-archive` import
   does not establish this acquisition, even if its directory prefix looks correct.
2. Runs `gh attestation verify` on the retained release nupkg and Sigstore bundle for
   the canonical repository and SLSA v1 predicate, without inherited GitHub host/token
   overrides. A nonzero verification exit produces an unverified receipt; timeout is a
   tool failure. Decode output as UTF-8 with replacement.
3. Issues a process-local HMAC admission over the complete verification/acquisition
   payload, binding assessed package, release package, bundle and source archive hashes.
   The random key travels only through the resolver child's environment, never receipts,
   command lines or state files. Receipts cannot be replayed as a standalone authorization;
   a new resolution needs a fresh helper admission. `check` checks the retained handoff,
   not a new cryptographic verification.

The resolver checks admission, signed identity claims, public GitHub-hosted execution,
declared repository/commit/workflow and all non-signature ZIP entry equivalence. After
case-insensitive validation of the expected archive root, use the archive's actual prefix.
It then requires **positive per-entry correspondence**:

- Executable text: an exact SHA-256 source-archive file match, or an attested-package
  `readiness-bundler-manifest.json` mapping that asset's exact digest to exact source inputs.
  Mere package.json/lockfile/JS presence never attributes an unmatched bundle.
- PE/CLI DLLs: the shipped filename stem and CLR AssemblyDefinition name must agree, and a
  safely parsed source `.csproj` must have that output name. Its exact-case root `Project`
  must use either no namespace or `http://schemas.microsoft.com/developer/msbuild/2003`,
  and must have no `Condition` attribute (local-name comparison is OrdinalIgnoreCase,
  regardless of attribute namespace). Detect **all** descendant `AssemblyName` elements
  using OrdinalIgnoreCase on the local name, regardless of element namespace.
  Accept exactly one literal, attribute-free leaf with exact-case canonical
  `AssemblyName` / `PropertyGroup` spelling, matching the root namespace, and with that
  `PropertyGroup` directly under root `Project`. No ancestor may have a `Condition`
  attribute under the same case-insensitive detection rule. Noncanonical spelling,
  multiple/conflicting names, unsupported placement, and MSBuild property/item/metadata
  expressions reject that project's correspondence. Use the project filename stem only
  when **zero case-insensitive `AssemblyName` elements exist anywhere in the project**
  and its root satisfies the namespace/unconditional requirements. Target/ItemGroup and
  lowercase/foreign-namespace names never permit a filename fallback.
  Existing repository/commit/informational-version
  metadata must be consistent and the source tree must not contain the prebuilt DLL.
  This is a bounded project/output association, **not** proof that a workflow step invoked
  the project, evaluated MSBuild imports, selected particular source files, or reproduced
  the DLL. Non-DLL/native/unsupported code stays unverified.

## Digest-bound bundler manifest

This narrow profile accepts a root `readiness-bundler-manifest.json` in the attested
package. It must have `schema_version: 1` and an `assets` array with unique `path` entries.
Each selected entry has `path` and `sha256` for the packaged asset, nonempty `inputs`
(`path` relative to the source root, `sha256` of that source file), and `components`
(`name`, exact `version`). The package attestation binds the manifest; callers cannot
submit a separate unauthenticated map. This is a producer declaration tied to signed
bytes, not independent exhaustive verification of bundler internals.

LP-04's supported source dependency profile validates every property name and string
value in both entire source dependency JSON documents before use, including ignored
metadata, nested arrays and unvisited lock entries. Malformed strings, including escaped
unpaired surrogates, remain unverified; valid surrogate pairs are permitted. Every object
also rejects duplicate decoded property names using ordinal comparison, even for equal
values or ignored fields. Different-case names are distinct; repeating a name in separate
objects is permitted. The same
whole-document check applies to the bundler manifest, provenance bundle/decoded statement
and helper admission envelope/decoded payload. SPDX/npm admission already walks every
name and string with strict UTF-8 conversion and rejects ordinal duplicates per object.
Root `optionalDependencies` must be an empty
object; `bundleDependencies` / `bundledDependencies` may only be `false` or empty arrays
for a positive. Nonempty declarations and other shapes stay unverified. In every
lockfile package entry (including root and unvisited entries), present `dependencies`
and `optionalDependencies` must be objects with nonempty string keys/values. Unsupported
optional dependencies in the runtime closure remain unverified.

LP-04 Mode A requires this map for **every** selected web asset, with nonempty component
sets consistent with the lockfile. It conservatively requires notices for the entire
runtime closure, including SSR-named packages; no name/absence heuristic proves exclusion.
Every covered lock entry must carry one `license` field containing a simple SPDX ID
string (at most 128 characters, ASCII letters/digits/dot/hyphen, starting with a
letter/digit; expression operators and NONE/NOASSERTION are unsupported). The
version-matched notice heading's SPDX ID must exactly equal that string, case-sensitively.
Missing, non-string, duplicate, expression or mismatched declarations stay unverified;
repeated name/version entries at different paths must agree on the license.
These are producer-declared metadata, not independent authentication of a dependency's
actual license or a legal-sufficiency finding.
Every version-matched notice's declared SPDX identifier must also match the complete canonical
clauses of MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC or 0BSD. Only whitespace/case
variation is normalized; unsupported/custom/incomplete text remains unverified. No
dependency-archive equality exception is currently implemented. This check is not a legal
opinion or proof that additional upstream NOTICE obligations were discovered.

Mode B is **unverified**. Exact repository bytes, non-vendored paths, no foreign banners,
Razor CSS correspondence and a repository notice declaration do not establish authorship.
Silent vendoring remains possible. Do not promote those observations into first-party origin.

The report validator has **no native-result JSON shortcut** for LP-04. Its historical
registered `protocol:notice-coverage-v1` gate still applies to verified/gap report decisions;
a native positive alone cannot bypass it. D-lite/provenance-unverified rows remain
`not tested`. A native Mode A positive requires separately admitted structured notice
evidence before a report can be validated as verified.
