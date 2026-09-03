# Accessibility and localization

Applies to `A11Y-*`.

Keep these evidence layers distinct: source markup/handlers/CSS, automated scan, browser
interaction, accessibility tree, assistive-technology behavior, formal conformance assessment, and
owner attestation. One layer does not silently prove another.

For each claimed render mode, exercise applicable pointer/keyboard behavior, focus entry/exit and
restoration, selection/expansion/validation/async states, computed name/role/state, localized
strings, LTR/RTL, and forced-colors/high-contrast behavior. Record control state, browser, mode,
input sequence, expected result, and observed result.

Use `gap` for reproducible semantic, keyboard, focus, announcement, localization, or contrast
failure. Use `owner evidence required` for private formal assessment or support-matrix records. Use
`not tested` when an applicable interaction or assistive-technology probe was not run.

Source ARIA does not establish computed semantics or conformance. An automated scanner pass does
not override a deterministic browser or assistive-technology failure.
