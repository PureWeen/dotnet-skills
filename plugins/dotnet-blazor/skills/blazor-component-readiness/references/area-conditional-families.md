# Conditional requirement families

`SCF-*` and `AI-*` are explicit opt-in overlays, not part of the 110-row core. Select `scaffolder`
only when the confirmed deliverable includes a supported scaffolder. Select `ai-skill` only when it
includes an AI skill/plugin that generates or recommends component code.

Do not emit placeholder `not applicable` rows for an unselected overlay. An overlay cannot
introduce, replace, rescope, or override a core ID. Use its version and digest from `rubric.json`.

For scaffolders, evaluate the generated output as a deliverable: documented integration mechanism,
core accessibility/runtime behavior, dependency constraints/pinning, absence of undocumented
arbitrary script execution, and alignment with supported library versions.

For AI skills, verify the documented contribution path, repository guidance, update ownership,
dependency constraints, portability, applicable responsible-AI review, and the generated code
itself. Fluent output is not evidence of security, accessibility, or compatibility.

Missing private review records are `owner evidence required`; direct unsafe or unsupported output
may be a `gap`.
