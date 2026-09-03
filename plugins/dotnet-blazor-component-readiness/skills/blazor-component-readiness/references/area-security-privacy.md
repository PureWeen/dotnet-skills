# Security and privacy

Applies to `SEC-*`.

Before claiming a vulnerability, state assets, actor capability, trust boundaries, preconditions,
bounded impact, confidence, and unknown controls. Cover the .NET host, browser DOM/events/storage,
JS modules and serialization, remote assets, server-rendered boundaries, repository/build
authority, signing, and dependency ingestion.

Collect direct evidence for threat modeling/review completion, disclosure route, exact-release
dependency scanning, patch/emergency release capability, telemetry/remote assets, and authorization
assumptions. Browser-originated state is application input, never authorization evidence.

Use `gap` only for concrete insecure behavior, an unsafe documented contract, or a directly missing
required public control. Missing private review records are `owner evidence required`. A current
scan does not prove release-time gating, and absence in inspected source does not prove every
distribution is telemetry-free.

For a concrete exploit claim, use an available security specialist read-only with the exact
package/source snapshot and reproduction, then independently adjudicate it. Do not broaden the
assessment or expose private evidence.
