# LP-10 & LP-04 Vite configuration contract (cooperative vendor model)

**Threat model and scope:** `blazor-package-readiness-resolver` evaluates component
packages under a **cooperative vendor self-assessment / partner readiness model**, not
an adversarial malware-analysis sandbox. Vendors are not required to emit a custom
`readiness-bundler-manifest.json` in their `.nupkg`. Configs written to deliberately
spoof or obfuscate outputs (`eval`, hostile prototype mutation, or arbitrary runtime JS
traps) are out of scope; the recognizer exists to deterministically verify real-world
attested Vite/Rolldown builds offline while failing closed to `not tested` on
unrecognized configuration shapes.

| Clause | Boundary and enforcing code |
|---|---|
| Trust & Threat Model | Genuine helper-acquired, HMAC-attested source/workflow bytes remain prerequisites (`HelperAdmission.Open`, `Lp10BinaryAttributionResolver.TryVerifyProvenanceAttestation`, `TryVerifyProvenanceContext`). Third-party packages in the `package-lock.json` closure and the vendor's attested repository are evaluated under a cooperative (non-adversarial) model. Findings state that attribution is established through the attested Vite build configuration, not a reproducible-build byte proof. |
| Accepted statements and imports (`C10-A`) | Top-level preamble statements are consumed start-to-end (`TryParseViteConfig`): bounded `import` clauses from `vite`, `node:fs`/`fs`, or `node:path`/`path` (cannot cross statement boundaries via semicolonless imports), bounded `: <type>` annotations on `const` declarations (`outDir`, `initializer`, `licenseManifest`, `entries`, `fixedNames`), validated `function <fn>()` plugin factories, and top-level `cpSync(...)` calls. |
| Plugin factory invocation (`C10-B`) | Every declared plugin factory in `validPluginFns` must be invoked exactly once in `plugins: [...]` (`invokedPluginFns.Count == validPluginFns.Count` in `TryParseViteConfig`). Uninvoked factories or duplicate calls fail closed. |
| Hook body statement grammar (`C10-C`) | Plugin objects allow only `name` and `generateBundle` / `closeBundle` / `writeBundle` hooks validated by `IsValidViteHookBody`: `closeBundle`/`writeBundle` allow only `cpSync(...)` (matched against `copiedDirs`) and optional `renameSync(\`${outDir}/${licenseManifest}\`, \`.../${licenseManifest}\`)`; `generateBundle` allows only the entry-chunk lookup / import-graph visitor statements and requires an unconditional top-level `this.emitFile({ ... })` call. Bundle code mutations (`bundle[...].code = ...`) and conditional `if (false) this.emitFile(...)` are rejected. |
| LP-04 decoupling from LP-10 | `Lp04NoticeCoverageResolver.VerifyBundledNpmNoticeCoverage` verifies third-party notice coverage via (1) a digest-bound `readiness-bundler-manifest.json`, (2) an `AttestedViteBuildPlan` from `TryResolveAttestedViteBuildPlan`, or (3) a bundler-generated root notice file (`IsGeneratedViteLicenseNotice` + `HasBundlerScriptInPackageJson`) covering the `package-lock.json` closure and inline `@license` comments for top-level bundled scripts even when `vitePlan` is null. |
| Not tested | Configs outside the recognized Vite subset return `provenance-unverified` (`not tested`) in LP-10 rather than a false gap. |
| Independent evidence | Exact source-blob matches, compiled project outputs, and digest-bound bundler manifests retain their independent checks (`ResolveProvenance`, `TryBundlerAsset`, `VerifyFirstPartyWebAssetNoticeCoverage`). |

