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

## Inspect and exercise

- public parameters, mutation, binding pairs, required parameters, docs, and compatibility;
- callback awaiting, exception routing, renderer affinity, and rerendering;
- timers, subscriptions, cancellation, object/module/listener ownership, and async disposal;
- JS initialization, module scope, serialization, DOM sinks, and custom-element upgrade;
- CSS isolation or documented global styles;
- initial/update render, late children, keyed reorder, selected removal/disablement, navigation,
  reset, detach/reattach, repeated initialization, callback failure, and cancellation;
- typed values in both directions for every claimed supported shape.

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
