# Blazor runtime behavior

Applies to `BEQ-*`.

## Render-mode matrix

Exercise every confirmed claimed mode using the exact package:

- `static-ssr`: prerender and useful noninteractive semantics;
- `interactive-server`: state changes, callbacks, reconnect/disposal boundaries;
- `interactive-webassembly` or `standalone-webassembly`: browser runtime and asset loading;
- `interactive-auto`: behavior before and after interactivity.

A build is not runtime proof. Confirm rendering/interactivity with public behavior plus browser
console/network evidence where applicable.

## Cheap preflight

Before broad or expensive probes: verify prerequisites and documented tool versions; confirm the
route/assets; build/start the smallest consumer; assert one target renders; run one critical
interaction; expand only after that smoke gate. Missing prerequisites, stale routes, absent assets,
or host startup failures are probe blockers unless direct evidence ties them to the package.

Retain the fixture's supported-context basis before scoring: applicable hosting mode, container
or form restrictions, registration, and the exact API/version used. Distinguish a documented
supported setup from an intentional unsupported-mode diagnostic or other negative control.
Current documentation may identify a caveat without proving the assessed release's contract.
If a contrast depends on a prohibited or unestablished setup, preserve it as a qualified
observation and repeat the smallest relevant supported-context case before attributing a defect.
Do not erase a valid unsupported-mode diagnostic when that diagnostic is itself the requirement.

Establish useful capture, not merely a successful automation command. At initial use and after
navigation or visibility changes, retain the actual target, renderer, delivered input event, and
corresponding state/callback or attributable failure. Accepted debugger/automation commands with
no delivered event do not demonstrate failed component input handling. Record target coverage
and page visibility, and compare a known input target when needed to distinguish delivery from
component behavior. Programmatic API calls or DOM changes may supply separately labeled evidence;
they do not replace a missing native interaction or prove visible UI.

## Inspect and exercise

- public parameters, mutation, binding pairs, required parameters, docs, and compatibility;
- callback awaiting, exception routing, renderer affinity, and rerendering;
- timers, subscriptions, cancellation, object/module/listener ownership, and async disposal;
- JS initialization, module scope, serialization, DOM sinks, and custom-element upgrade;
- component-style isolation, absence of inline style attributes, and documentation and
  prefixing of any global CSS surface;
- initial/update render, late children, keyed reorder, selected removal/disablement, navigation,
  reset, detach/reattach, repeated initialization, callback failure, and cancellation;
- typed values in both directions for every claimed supported shape.

Trace source through the public wrapper, inherited base/runtime types, and browser module handlers.
Direct source that synchronously inspects or discards an asynchronous callback/cleanup task can
establish a `gap` even when a separate runtime probe is blocked. A blocked runtime probe still
remains relevant for behavior that source cannot establish.

When a dynamic-child lifecycle row also has direct source proof, retain and cite the lifecycle
protocol. Use a canonical `source-proof-v1` protocol bound to the exact confirmed component source
artifact; free-text analysis is insufficient. For `BEQ-12`, use proof kind
`async-callback-not-awaited`. For `BEQ-15`, use `async-cleanup-not-awaited`. A source-proven gap is
valid only when the mapped lifecycle operation is failed or not tested. A passed mapped operation
contradicts the source proof and must be reconciled instead of bypassed.

`source-proof-v1` is currently limited to components whose dynamic-child lifecycle is required.
Keep non-dynamic callback/cleanup source proof fail-closed until a separate protocol defines how it
reconciles without the lifecycle matrix.

For `BEQ-20`, associate relevant declarations with their selectors in the reached exact shipped
CSS, including custom properties on document-root selectors. Distinguish document-root from
component/helper scope; neither a name list nor prefixed helper selectors alone establishes
global prefix coverage. Direct evidence of an applicable global surface missing a required
prefix establishes a bounded static `gap`, even when documentation correspondence is unresolved.
Record that uncertainty separately, without claiming documentation is absent. Remediation must
satisfy both documentation and prefixing; do not infer an unobserved runtime CSS collision.

For documentation requirements, direct absence from the confirmed complete public corpus is a
`gap`. For disjunctive requirements such as safe failure **or** documentation, do not call a gap
until every remaining applicable alternative is directly contradicted. Conditional render-mode
rows are `not applicable` when that mode is not a confirmed support claim.

For a `BEQ-05` direct documentation-absence gap, use `public-absence-v1` bound to a
`public-document-corpus` input.

Implementation-mechanism rows require mechanism evidence. A successful behavior probe does not
prove `@key`, awaited callbacks, renderer affinity, `StateHasChanged`, or async disposal. Complete
source may establish that no compile-time-required parameter exists for an `[EditorRequired]`
surface; otherwise leave applicability unresolved as `not tested`.

For `BEQ-09`, inspect every component-owned assignment to each public `[Parameter]` property,
including assignments in event handlers, callbacks, conditional branches, and inherited members.
Any such assignment is parameter mutation and establishes a `gap`. Using a backing field on other
paths, invoking the paired callback, or avoiding the setter during ordinary rendering does not
cancel a direct assignment through the public parameter setter.

For navigation over disabled/hidden items, include all-disabled/no-focusable cases and assert
termination. Report a shared-runtime problem at its owning layer while retaining the assigned
component as demonstrated scope. Never generalize one component's result to siblings.

## Conditional dynamic-child lifecycle matrix

Apply this matrix only when the confirmed component groups, registers, selects, or composes child
items. The input manifest must declare `dynamic_child_lifecycle.applicability` as `required` with
one or more matching triggers. A component with no such surface declares `not-applicable` with a
specific rationale and is not forced through these probes.

After initial render and upgrade, obtain a raw observation for every operation:

1. add one child;
2. remove one child;
3. reorder keyed children;
4. disable or remove the selected child;
5. reconcile membership;
6. propagate name, default, value, and selected state;
7. transfer and restore focus ownership;
8. preserve exactly one expected roving tab stop;
9. route callbacks and callback failures;
10. clean up registrations, listeners, references, and async disposal.

The lifecycle protocol must contain all ten operations in canonical order. Each operation is either
`observed`, with a `passed` or `failed` outcome and a digest-bound raw observation, or `not-tested`,
with an operation-specific blocker. Initial-state-only evidence, a prose checklist, or one aggregate
browser summary cannot verify the matrix.

Confirm the protocol and raw files under `evidence_inputs`. Register the protocol evidence as
`reproduced-runtime-observation` with the protocol basename as locator and
`protocol:dynamic-child-lifecycle-v1` as `provenance.method`.

For a claimed Interactive Auto mode, a verified BEQ-08 requires the named
`protocol:auto-renderer-transition-v1` protocol. Its cold visit must observe the Server renderer
and its warm full-document revisit must observe the WebAssembly renderer as distinct execution
identities. Identical DOM, downloaded WebAssembly assets, or an unchanged `interactive-auto`
label are not renderer identity evidence; if the identities cannot be observed, use `not tested`
or `gap` according to the status boundaries.

### Interactive Auto evidence protocol

Retain one canonical `structured-protocol` input for the protocol and one canonical
`raw-observation` input for each visit. The protocol shape is:

```json
{
  "schema_version": 1,
  "protocol": "auto-renderer-transition",
  "component_id": "Example.Calendar",
  "cold": {
    "visit": "cold",
    "expected_identity": "server",
    "observed_identity": "server",
    "raw_observation_sha256": {
      "algorithm": "sha256",
      "value": "<cold-capture-sha256>"
    }
  },
  "warm": {
    "visit": "warm",
    "expected_identity": "webassembly",
    "observed_identity": "webassembly",
    "raw_observation_sha256": {
      "algorithm": "sha256",
      "value": "<warm-capture-sha256>"
    }
  }
}
```

Each referenced raw visit is canonical JSON with this shape:

```json
{
  "schema_version": 1,
  "observation": "auto-renderer-visit",
  "component_id": "Example.Calendar",
  "visit": "cold",
  "mode": "interactive-auto",
  "observed_identity": "server"
}
```

Use `visit: "warm"` and `observed_identity: "webassembly"` for the second capture. The
`component_id`, visit, mode, and observed identity must agree across the protocol and its raw
capture. The protocol digest must equal the `structured-protocol` input digest, each raw digest
must equal its `raw-observation` input digest, and the selected evidence record must use
`protocol:auto-renderer-transition-v1` with the protocol basename as locator. Populate
`observed_identity` from the retained browser/console/network capture of that visit; never copy
`expected_identity` into the observed field. The validator binds these digests and identities but
does not turn a declaration into independent real-world proof.
