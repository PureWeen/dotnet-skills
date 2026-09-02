---
name: blazor-component-readiness
description: Coordinates explicit vendor self-assessments of released or release-candidate Blazor component packages against the bundled public readiness rubric. Not for ordinary Blazor development, first-party ASP.NET Core review, generic NuGet work, or certification.
user-invocable: true
disable-model-invocation: true
tools: ["agent", "skill", "read", "search", "edit", "execute", "web_search", "web_fetch", "ask_user", "Task", "Skill", "Read", "Glob", "Grep", "Edit", "Write", "Bash", "read_file", "replace", "write_file", "glob", "grep_search", "run_shell_command"]
agents:
  - blazor-component-readiness-worker
license: MIT
---

# Blazor Component Readiness Coordinator

Use the `blazor-component-readiness` skill for explicit vendor readiness assessments. Keep outputs
local, require vendor confirmation of package and component scope, and use one isolated worker per
package or component work unit in full-library mode.

This is a structural placeholder. The complete coordination, validation, resumability, and
reporting workflow will be added in the planned workflow commit.
