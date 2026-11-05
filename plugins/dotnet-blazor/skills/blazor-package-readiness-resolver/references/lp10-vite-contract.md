# LP-10 Vite configuration contract

**The Vite positive path is deferred in full. There is no supported configuration
subset.** Retaining a subset would require further interpretation of JavaScript
bindings, complete object values, callbacks and source-import/output correspondence.
This is not a hook-body grammar or a vendor exception.

| Clause | Boundary and enforcing code |
|---|---|
| Trust | Genuine helper-acquired, HMAC-attested source/workflow bytes remain prerequisites for provenance (`HelperAdmission.Open`, `Lp10BinaryAttributionResolver.TryVerifyProvenanceAttestation`, `TryVerifyProvenanceContext`). Third-party code in the lock closure, including Vite/rolldown, is assumed trusted; this does not establish vendor-config behavior. Even under those assumptions, `TryResolveAttestedViteBuildPlan` returns `false` with a null plan. |
| Accepted statements and imports | None: no default/named/namespace/type imports, specifiers (including `vite`, fs/path, direct dependencies or relative/absolute paths), declarations, type annotations, callbacks or other statements establish attribution (`TryResolveAttestedViteBuildPlan`). The former preamble walker and `TryParseViteConfig` are removed, not repaired with a spelling blacklist. |
| Accepted keys and values | None at root, build, rolldownOptions, output or nested levels; even a pure literal spine is deferred. Unknown keys, `resolve.alias`, and `publicDir` (including `false`, omission or a present `public/` tree) cannot authorize outputs (`TryResolveAttestedViteBuildPlan`). |
| Permitted effects | None. Plugins (even `plugins: []`), invoked/uninvoked factories, every hook, `emitFile` and config-load/hook `cpSync` provide no evidence. Bundle mutation and filesystem rename/delete effects cannot be separated from other outputs; the whole plan is rejected (`TryResolveAttestedViteBuildPlan`). No initializer/copy evidence extraction or plan construction remains. |
| Not tested | Config-derived scripts, CSS and generated notices without independent correspondence remain unsupported. LP-10 `ResolveProvenance` returns `provenance-unverified` for unmatched text; LP-04 `VerifyBundledNpmNoticeCoverage` returns `provenance-notices-unverified` without a digest-bound manifest. These escalated branches map to **not tested**, not a finding of bad provenance or missing legal coverage. |
| Independent evidence | Genuine source-blob matches, matching compiled project outputs and digest-bound bundler manifests retain their existing checks; merely having a Vite config does not invalidate independently established evidence (`ResolveProvenance`, `TryBundlerAsset`, LP-04 `VerifyBundledNpmNoticeCoverage`). |

The retained plan type and consumers are compatibility scaffolding only:
`TryResolveAttestedViteBuildPlan` cannot produce a plan or populate any field.
Re-enabling a positive path requires a separately justified closed contract and
tests; the historical hook/copy positives are now explicit fail-closed controls.
