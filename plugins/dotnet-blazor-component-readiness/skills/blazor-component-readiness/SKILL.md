---
name: blazor-component-readiness
description: Assess a vendor-owned released or release-candidate Blazor component package against the public readiness rubric and produce local evidence-backed artifacts. Use for explicit component readiness, adoption, release, or vendor self-assessment requests. Do not use for ordinary Blazor authoring or debugging, first-party ASP.NET Core review, generic NuGet help, or certification decisions.
---

# Blazor Component Readiness

## Purpose

Produce a bounded, evidence-backed vendor self-assessment of a Blazor component package. The
bundled rubric is a public self-assessment baseline, not certification or a Microsoft acceptance
requirement.

## When to Use

- A component vendor asks whether a released or release-candidate package is ready to ship,
  recommend, or adopt.
- The request explicitly asks for a readiness scorecard against the bundled rubric.

## When Not to Use

- Ordinary component implementation, application debugging, first-party ASP.NET Core review, or
  generic package-management work.
- Formal certification or an acceptance decision on Microsoft's behalf.

## Inputs

| Input | Required | Description |
|---|---|---|
| Package | Yes | Exact published package identity or a local release-candidate `.nupkg`. |
| Component scope | Yes | One bounded component, or a vendor-confirmed library inventory. |
| Evidence | No | Public or owner-supplied artifacts whose provenance can be recorded. |

## Workflow

1. Confirm that the request has explicit readiness intent and is vendor self-assessment work.
2. Read `references/rubric.json`; treat it as canonical. Use
   `references/checklist.md` only as its generated human-readable view.
3. Select the 110-ID core. Add an overlay only when the bounded deliverable explicitly includes
   that overlay feature.
4. Keep all outputs local and distinguish structural validation from factual truth.
5. For full-library work, stop with an unsupported-host result unless isolated workers are
   available. Do not serialize every component into one shared model context.

The complete production workflow, validator command sequence, and progressive reference routing
will be added in the planned workflow commit.

## Validation

- Every selected core ID comes from `references/rubric.json`.
- Statuses use only the five exact tokens declared by the rubric.
- The result states that the baseline is self-assessment, not certification.
- No remote system is mutated.

## Common Pitfalls

| Pitfall | Required response |
|---|---|
| Treating generated Markdown as canonical | Return to `references/rubric.json`. |
| Applying overlays automatically | Include only explicitly selected, applicable overlays. |
| Claiming certification | Describe the result as a bounded vendor self-assessment. |
| Running a full library in shared context | Fail early when isolated workers are unavailable. |
