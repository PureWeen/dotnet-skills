# Blazor component readiness recovery proof

The final fidelity repair was recovered from Git auto-preservation commit
`5c08efb8a0561d749da9eb8db404d92e9a3f9c95`. Its parent is the known
pre-repair commit `b276d7624ecb7f364d848198c8851a05fb475101`.

The regenerated parent-to-child patch is exactly 264,477 bytes and has
SHA-256
`e271bd4d0b40325e48b9890a0d24631a1cbac892fa3195b96a4a771b5f1c0daa`,
matching the independently retained identity of the deleted repair patch.
The commit changes exactly 30 files. All 19 changed runtime files also match
the sealed blind-v5 runtime snapshot byte-for-byte.

`recovery-manifest.tsv` records the original path, mode, size, SHA-256,
recovered commit, and recovery disposition for every repaired file. The
manifest has SHA-256
`b01ffc309865520e842071d24e5a1cbed35fb949f76dd9bf60212f8c5689bc55`.

## Workload migration invariants

- Runtime content is moved from the retired
  `dotnet-blazor-component-readiness` plugin into `dotnet-blazor` without
  rewriting the recovered skill, agent, reference, or validator bytes.
- The three `dotnet-blazor` manifests remain byte-identical and register both
  readiness agents.
- Marketplace manifests and the root plugin table expose only
  `dotnet-blazor`; the retired standalone plugin is not installable.
- Readiness evals and deterministic tests live under `tests/dotnet-blazor`
  so repository discovery, CI ownership, and the workload plugin agree.

## Deterministic contract traceability

| Boundary | Primary deterministic coverage |
|---|---|
| Plugin manifests, marketplace registration, retired-plugin absence, rubric IDs and scope | `../readiness-validator/Program.cs` |
| Skill activation boundaries, required references, coordinator and worker wiring | `../readiness-validator/WorkflowTests.cs` |
| Historical schema-v1 verification and schema-v2 assessment identity | `../readiness-validator/EvidenceTests.cs`, `../readiness-validator/AssessmentTests.cs` |
| Path resolution, aliases, external artifact roots, launcher parity, .NET 11 guard | `../readiness-validator/FoundationTests.cs` |
| Typed provenance, stable IDs, package digest binding, bundle selection and ambiguity | `../readiness-validator/EvidenceTests.cs` |
| Status/evidence ownership, report byte binding, revision integrity, feedback preservation and mutation races | `../readiness-validator/AssessmentTests.cs` |
| Dynamic lifecycle applicability, direct-failure/public-absence boundaries, toolchain disposition and blind input gate | `../readiness-validator/EnforcementTests.cs` |
| Package/component isolation, interrupted-run recovery, revision chaining and index publication | `../readiness-validator/LibraryTests.cs` |
| Positive activation, explicit coordinator/worker behavior, blind gates and ordinary-work dormancy | `agent.blazor-component-readiness/eval.yaml`, `blazor-component-readiness/eval.yaml` |

The BCL-only workflow tests retain the documented under-500-line `SKILL.md` boundary
and progressive-reference checks. Actual `cl100k_base` BPE size profiling and advisories
belong to the shipping `skill-validator check`; chars/4 is only a reference estimate,
not a second hard gate.

Every integrity boundary keeps positive acceptance coverage and fail-closed
negative or mutation coverage in the referenced suites. Model evaluations
measure activation and workflow behavior; they do not replace deterministic
validator tests.
