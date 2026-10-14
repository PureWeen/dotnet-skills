# Source route-reading gate

Use this gate for source-based conclusions whose deciding behavior can differ between component
inputs or helpers, including outbound serialization. It is a reading/completion discipline, not
a universal data-flow proof or an additional requirement in the answer key.

1. **Inventory before following one convenient writer.** Start from the exact component wrapper
   and its inherited/partial types. Record source-backed public input declarations, property
   setters/accessors, callable methods, overrides and initialization hooks that could reach the
   selected check. Include attributes and bodies, not just names or signatures. Account for
   omitted generated code, unknown bases and build/preprocessor configuration explicitly.
   A file inventory or a human grouping is not an exhaustive API or route count.
2. **Choose routes using the check and obtained source.** Distinguish different outbound shapes,
   flags and branches rather than treating every string setting as the ordinary scalar-value
   route. Explain confirmed relevance; do not make an unknown route disappear because its name
   looks unrelated. The candidate set can be broader than the actually applicable routes.
3. **Read complete declarations and follow the next deciding body.** Obtain whole properties
   including accessors, and every relevant helper body, recursively. Resolve overloads using the
   actual arguments and source context; if dispatch remains ambiguous, inspect the plausible
   candidates or record the exact uncertainty. Traverse lambda/local-function calls and
   collaborator objects. A neighbor method ending just before the callee, a signature hit or
   a truncated body does not satisfy that read.
4. **Follow stored values through transport.** A helper that queues a message is not itself the
   serializer. Inspect the enqueue, drain, message formatting and send/receiving boundaries
   needed for the claim. Keep field-mediated, generated, interface or reflection dispatch
   explicit when a syntax index cannot establish it. An outer encoded string does not by itself
   establish safe representation of the JSON or markup contained inside it.
5. **Persist the unfinished frontier and apply the status boundary below.** Reconcile new calls,
   overloads and branches discovered during reading before closing the route. Do not verify
   from an agent-authored empty worklist or a broad index's `ready` label.

Keep a small disposable route worklist outside confirmed-input/revision directories. Bind it to
the component, source digests and known configuration. For each route, record its input declaration,
next deciding declarations, actually obtained original path/range, claim supported by those reads,
and unresolved body/dispatch/configuration boundary. Revalidate those bindings on resume.
Worklist existence, a packet written to disk or a successful extraction is not obtained evidence:
only source text actually exposed by a successful, untruncated read counts. Record the original
tool/result identity when the host provides it; never invent read events or claim comprehension
from exposure alone.

| Obtained evidence | Status decision |
|---|---|
| A safe writer on one route; another identified, potentially applicable route is unread | Do not use `verified`. Read the deciding body, or use `not tested` with that exact missing evidence. |
| A direct applicable source conflict on an obtained route | A claim-bounded `gap` may stand without closing unrelated routes. Missing reads are not the conflict. |
| A missing private/owner-held fact is actually deciding | Use `owner evidence required`; do not substitute an owner request for accessible unread source. |
| All applicable routes and relevant boundaries are resolved, and the evidence satisfies the selected obligation | A positive conclusion may be justified. Reading completeness alone cannot establish conformance. |
| A parser/index has unresolved external, generated, configuration or semantic boundaries | Preserve the limitations. A conservative blocked index is neither a product gap nor proof that the entire check is untestable. |

Keep source and runtime findings separate. A static mechanism conflict does not establish
attacker control, reproduce shipped runtime behavior or certify a broader security-policy breach.
Vendor advice is not enforced input provenance. Apply the actual selected requirement and its
authority; do not silently promote a derived mechanism check to a different policy obligation.
