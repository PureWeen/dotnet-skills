# Support, servicing, and lifecycle

Applies to `SUP-*`.

Collect named package/product support ownership and contact route, response targets, supported
versions, patch cadence, end-of-life policy, public issue route, private security disclosure,
emergency servicing/release ownership, per-release requirement revalidation, and
suspension/recovery expectations.

Most controls are repository-wide; preserve rubric ownership exactly. Component-specific
revalidation must still show that the assigned component was covered.

Public commitments can be `verified`. Private staffing, escalation, incident, release, or
revalidation records are `owner evidence required`. Contradictory or directly missing required
public policy may be a `gap`. Recent issue activity is not an SLA, and a security-policy file alone
does not prove emergency release capability.

Ask for evidence owner, location/basename, scope, date, supported versions, response target, and
exact package/candidate applicability. Keep follow-up limited to supplied evidence and retesting the
same confirmed unit.

For `SUP-01`, organization, authorship, repository activity, or a contact route does not establish
accountable support ownership. `verified` requires a canonical `support-ownership-v1` owner record
with the current accountable role and owner, exact package/product scope, backup owner, escalation
path, and effective UTC time. The validator enforces this evidence shape; staffing truth and
organizational authority remain owner attestations.

Register the owner record with its confirmed public/internal owner provenance, the owner-input
basename as locator, and `protocol:support-ownership-v1` as `provenance.method`.
