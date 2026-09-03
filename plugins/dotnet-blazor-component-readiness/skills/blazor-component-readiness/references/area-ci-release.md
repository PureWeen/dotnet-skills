# CI, documentation, and release validation

Applies to `CI-*`.

Trace pull-request validation and release separately through source/dependency acquisition,
restore/build/test/package/browser checks, accessibility/security gates, immutable artifact
handoff, signing, SBOM/provenance generation, release, retained evidence, and revalidation.

Collect the exact workflow revision used for the assessed package, required-check evidence when
available, package-based tests, browser coverage for each claimed render mode, compiling
documentation samples with behavioral assertions, toolchain prerequisites, artifact digests before
and after privileged stages, and requirement-mapped release results.

Workflow configuration shows intent. Successful required execution against the exact artifact is
evidence. A passing build does not prove runtime, accessibility, or package integrity. Current
default-branch automation does not prove an older release.

Use `owner evidence required` for inaccessible protection/environment/release records. Use `gap`
for an observable missing required public release control, rebuilding after verification, or
signing/releasing different bytes than were validated.
