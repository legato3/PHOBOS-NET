## 2026-05-23 - Accessibility Patterns in Configuration Forms
**Learning:** Found inconsistencies in form labeling patterns. Some inputs used implicit nesting (`<label><input></label>`) while others used explicit `for`/`id` but missed connecting helper text.
**Action:** When auditing forms, always ensure:
1. Explicit `for` and `id` attributes are used for robust screen reader support.
2. Helper text is programmatically associated using `aria-describedby`.
3. Keyboard shortcuts are announced using `aria-keyshortcuts` on the triggering elements.

## 2024-05-24 - Keyboard Accessibility for Interactive Divs
**Learning:** High-traffic navigation elements (stat cards) were implemented as clickable `div`s without keyboard support, excluding keyboard-only users from primary navigation.
**Action:** When using `div` for interactive elements (if `<button>` isn't feasible due to layout), always add `role="button"`, `tabindex="0"`, and keydown handlers for Enter/Space.
