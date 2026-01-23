## 2026-05-23 - Accessibility Patterns in Configuration Forms
**Learning:** Found inconsistencies in form labeling patterns. Some inputs used implicit nesting (`<label><input></label>`) while others used explicit `for`/`id` but missed connecting helper text.
**Action:** When auditing forms, always ensure:
1. Explicit `for` and `id` attributes are used for robust screen reader support.
2. Helper text is programmatically associated using `aria-describedby`.
3. Keyboard shortcuts are announced using `aria-keyshortcuts` on the triggering elements.
