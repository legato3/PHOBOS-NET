## 2024-03-24 - [Accessibility Improvements]
**Learning:** Adding `aria-label` to icon-only buttons and unlabelled inputs significantly improves screen reader accessibility without affecting visual design.
**Action:** Always check for missing labels on form controls and icon buttons during UI implementation.

## 2024-05-22 - [Form Accessibility]
**Learning:** Inputs that rely solely on `placeholder` attributes are inaccessible to screen readers. Adding `aria-label` provides necessary context without changing the visual design.
**Action:** When designing compact forms without visible labels, always include `aria-label` attributes describing the input's purpose.
