# Trimming, AOT, and performance

Applies to `TA-*` and `PERF-*`.

Restore the exact package into a disposable consumer. Publish with trimming and trim analysis;
separate package-attributable warnings from app/toolchain warnings, then load and exercise the
published output. Inspect reflection, dynamic code, serialization, and JS interop. Configuration
alone does not prove runtime behavior; successful publish without browser exercise is incomplete.

Run native WebAssembly AOT only when claimed or explicitly requested, and keep its evidence
separate from trimming.

Before performance measurement, define representative item count/depth/templates/interactions and
relevant server circuits, WebAssembly startup, bundle, payload, allocation, latency, and retained
state. Source may identify risks but cannot verify a budget.

Use `gap` for demonstrated identity instability, repeated/unbounded work, retained-state problems,
or a measured budget failure. Use `owner evidence required` for private targets/budgets/records and
`not tested` when an applicable deterministic benchmark or runtime probe was not performed.

For a comparison that adjudicates `TA-02` or `TA-04`, name the supported SDK/workload/toolchain and
target framework. A `verified` or `gap` result backed by supplied toolchain logs uses a canonical
`toolchain-probe-v1` protocol with the exact command, supported-toolchain disposition, result, and
raw-log digest. Otherwise finish the row as `not tested` and put the exact toolchain, workload, or
diagnostic blocker in the observation plus the smallest rerun in `assessment_follow_up`. Never emit
or retain an undefined `unresolved` final status.

Register the protocol as `reproduced-runtime-observation`, use its confirmed basename as locator,
and set `provenance.method` to `protocol:toolchain-probe-v1`.
