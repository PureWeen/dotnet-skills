# Feedback contract

Feedback is user-owned Markdown beside the applicable package/component `revisions` directory. The
validator may read it but never creates, rewrites, normalizes, or deletes it.

Use exactly:

```markdown
# Assessment feedback

| Requirement IDs | Feedback |
|---|---|
| `PI-03`, `PI-04` | The signing evidence is retained in our internal release system. |
```

Rules:

- The heading, blank line, and two table-header lines are exact.
- Every data row has exactly two columns. Escape literal `|` characters in feedback.
- IDs are canonical, backticked, comma-separated, unique, and resolve to one normalized sorted set.
- Unknown IDs, IDs not selected by the assessment, duplicate sets, and overlapping sets fail.
- The raw feedback cell payload is rendered verbatim.
- Feedback is commentary, not evidence; it never changes status or factual observation.
- A feedback-only revision preserves input, assessment, and evidence bytes exactly and binds the
  feedback-file digest plus the new report digest.
- Keep feedback outside immutable revision directories.

To apply feedback, validate the file by rendering the next revision with `--feedback`, then verify
that revision with the same feedback path. If package feedback is used by a component assessment,
pass the same `--package-feedback` path while validating and verifying the component.

Decision guidance is separate from feedback. Create it only on explicit request, beside this file,
and follow `report-contract.md`; never place guidance text in the feedback table automatically.
