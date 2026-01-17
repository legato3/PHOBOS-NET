## 2024-03-24 - [Accessibility Improvements]
**Learning:** Adding `aria-label` to icon-only buttons and unlabelled inputs significantly improves screen reader accessibility without affecting visual design.
**Action:** Always check for missing labels on form controls and icon buttons during UI implementation.

## 2024-05-22 - [Form Accessibility]
**Learning:** Inputs that rely solely on `placeholder` attributes are inaccessible to screen readers. Adding `aria-label` provides necessary context without changing the visual design.
**Action:** When designing compact forms without visible labels, always include `aria-label` attributes describing the input's purpose.

## 2026-01-11 - [ARIA Tabs Pattern]
**Learning:** When using Alpine.js for tab interfaces, `aria-selected` must be bound with a colon (`:aria-selected`) to evaluate the boolean expression. Using a static attribute results in the string "activeTab === 'x'" being read by screen readers.
**Action:** Verify all dynamic ARIA states in Alpine.js templates use `x-bind` (colon prefix). Also, use proper `role="tablist"` and `role="tab"` for view-switching sidebars instead of generic navigation roles.

## 2026-01-22 - [Collapsible Sidebar Accessibility]
**Learning:** Collapsible sidebars that hide text labels using `display: none` render the navigation buttons inaccessible to screen readers (who hear nothing or just an icon) and confusing for mouse users (no hover context).
**Action:** Always add static `aria-label` and `title` attributes to sidebar navigation buttons. This ensures the accessible name persists even when the visual text label is hidden via CSS.

## 2026-01-26 - [Dynamic Accessible Labels]
**Learning:** For interactive elements with visual badges (like notification counts), ensuring the `aria-label` dynamically reflects the count is critical for screen reader users who cannot perceive the badge.
**Action:** Use Alpine's `:aria-label` binding to include status/count information in the accessible name, e.g., `:aria-label="'Alerts (' + count + ' active)'"`.
