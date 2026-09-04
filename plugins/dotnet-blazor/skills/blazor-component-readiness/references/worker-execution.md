# Worker execution

## Capability boundary

A readiness worker owns validator artifacts, so it must run as the selected top-level agent in a
separate writable session. Nested custom agents are text-only review/delegation contexts and cannot
serve as readiness workers. Do not stream assessment files through nested-agent response text or
let the coordinator reconstruct worker-owned evidence.

If the host cannot create a separate writable session, stop with:

`unsupported host: readiness worker requires a top-level writable session`

For full-library work, use the library-level unsupported-host message required by `SKILL.md`.

## Per-unit directory

Create one directory per confirmed unit below the approved run root. Before launch:

1. Copy only the exact confirmed input manifest, package bytes, validated package revision, the
   package-wide files referenced by that revision's input manifest, unit-specific
   source/documents/evidence, worker prompt, and a trusted plugin copy.
2. Keep sibling component files and the reviewed repository outside the worker directory.
3. Record the staged file inventory and SHA-256 values.
4. Give the worker permission to write only inside its working directory. Do not enable unrestricted
   path access or remote mutation.

The worker writes its revision beneath this directory and returns only the structured handoff.
Package-wide binding files are required so the worker can revalidate the package revision; they do
not authorize sibling component source, documentation, candidates, or evidence. Package inventory
entries inside the exact binding remain non-evidence for component work and must not be cited or
reproduced in component artifacts.

Use the unit directory as the validator input root. Keep confirmed package/component inputs and the
validated package revision directly beneath that root, and place new component artifacts beneath
the assigned output subdirectory. Do not use the output subdirectory as `--root` or relocate bound
inputs into it.

## Copilot CLI host

Select the qualified worker as a new top-level process. Use the installed plugin name from
`plugin.json`; do not guess an unqualified agent name.

```text
copilot --agent <plugin-name>:blazor-component-readiness-worker \
  --plugin-dir <absolute-staged-plugin-directory> \
  -C <absolute-unit-directory> \
  --model <owner-approved-model> \
  --allow-all-tools \
  --disable-builtin-mcps \
  --no-ask-user \
  --no-auto-update \
  --silent \
  -p <bounded-worker-prompt>
```

`--allow-all-tools` is required for non-interactive execution; it does not authorize paths outside
the worker working directory. Never add `--allow-all-paths`. Permit network URLs only when the
confirmed unit requires public retrieval and the owner approved those exact domains.

Resolve the plugin directory and unit directory to absolute paths before invoking the CLI. Some
hosts apply `-C` before resolving other relative arguments, which can make a valid staged plugin
undiscoverable. Launch once per unit attempt. Treat usage output, a nonzero exit, timeout, or
missing handoff as a failed attempt; do not retry in the same directory. A coordinator may
reconcile the failure by creating a fresh attempt in a new unit directory.

Use the host's equivalent top-level-session API when available. In an SDK host, create a new
session with the unit directory as `WorkingDirectory`, register/select only the worker persona and
required skill, and apply the same path and network restrictions. In Agency, use one job/session
per unit. VS, VS Code, or cloud hosts without a sibling writable-session primitive must fail closed.

## Acceptance

Treat worker output as untrusted until the coordinator:

1. Confirms exactly one process/session was launched, returned the exact assigned unit ID, and
   returned no blockers with success-shaped artifact paths.
2. Resolves every returned path below the assigned unit output root.
3. Recomputes the validation-manifest SHA-256 from final bytes.
4. Runs deterministic report verification with the exact confirmed input and package revision.
5. Confirms row ownership, package binding, claimed-mode dispositions, and absence of sibling
   evidence.

Normalize accepted handoff paths relative to the confirmed output root, without `./` or the
output-root directory name as a prefix. Row-level blocked probes are represented by `not tested`
rows and their assessment follow-up; they are not handoff blockers once a complete revision
validates. Write the handoff only after all checks pass. A unit-level blocked, timed-out,
duplicated, or digest-mismatched worker remains incomplete and produces no success-shaped handoff.
