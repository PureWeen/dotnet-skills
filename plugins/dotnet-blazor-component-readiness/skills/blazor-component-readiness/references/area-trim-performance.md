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
