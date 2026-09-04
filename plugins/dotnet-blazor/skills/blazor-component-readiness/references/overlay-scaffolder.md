# Scaffolder overlay

Select overlay `scaffolder` only when the confirmed deliverable includes a supported scaffolder.
A sample generator or handwritten template is not enough without an explicit product claim.

Use the six `SCF-*` requirements exactly as defined in `rubric.json`. Collect evidence that the
scaffolder:

- integrates through a documented mechanism for its target ecosystem;
- produces output satisfying applicable core accessibility and Blazor requirements;
- uses only supported/approved dependencies;
- pins and verifies generated dependency versions and package identity;
- performs no undocumented arbitrary script execution;
- remains aligned with supported library versions.

Compile and exercise generated output rather than scoring only template source. Do not apply this
overlay to a package that has no confirmed scaffolder surface.
