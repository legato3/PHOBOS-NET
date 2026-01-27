# Visual Consistency Audit: Widgets

## 1. Widget Implementation Patterns (Fragmentation)
There are four distinct widget implementation patterns currently in use, leading to structural and visual inconsistencies:

1.  **Standard Widget Card (`widget_card` macro)**
    *   **Usage:** `network.html` (most widgets), `security.html`, `firewall.html`.
    *   **Structure:** Uses `<h2>` header with flexbox layout for title and actions.
    *   **Style:** `font-family: var(--font-mono)`, `font-size: 13px`, `text-transform: uppercase`.

2.  **Status Card V3 (`status_card` & `panel_card` macros)**
    *   **Usage:** `server.html` ("Host Strip", "Ingestion Pipelines", "Application Internals").
    *   **Structure:** Uses `.status-card` class with `__header`, `__title`, `__meta` BEM-like structure.
    *   **Style:** Distinct from `.card`. Header background `var(--card-header-bg)`, title `font-size: 13px`, `border-left: 3px solid ...`.

3.  **Stat Box (`.card.stat-box`)**
    *   **Usage:** `network.html` (Status Blocks), `hosts.html` (Top Stats), `security.html` (Summary Stats), `firewall.html` (Overview).
    *   **Structure:** `.card` combined with `.stat-box`.
    *   **Style:** Centered text, big numbers (`font-size: var(--fs-xl)`), no header. Distinct `padding: var(--space-4)`.

4.  **Manual Implementation (Inline Styles)**
    *   **Usage:**
        *   `overview.html`: "Legacy Header Metrics" (manual `.card` with inline flex/padding).
        *   `hosts.html`: "What Changed" (manual `.card` with inline background/border).
        *   `tools.html`: All tools widgets (manual `<h2>` construction).
        *   `security.html`: "MITRE Heatmap" (manual cards for cells).

## 2. Border Styles & Radii
*   **Standard:** `.card` uses `border: 1px solid var(--card-border)` and `border-radius: var(--card-radius)`.
*   **Deviations:**
    *   `hosts.html` ("What Changed"): `border: 1px solid var(--border-soft)` (Inline).
    *   `overview.html` (Legacy Metrics): `border: 1px solid var(--card-border)` (Inline, but redundant).
    *   `server.html`: Uses `border-radius: var(--sc-radius)` which maps to `var(--card-radius)` but introduces an alias layer.
    *   `style.css`: `.world-map-card` forces `padding: 0 !important` and `border-radius: var(--radius-lg)` (which might differ from `var(--card-radius)` if they are not synced).

## 3. Header Hierarchy & Typography
*   **Standard (`widget_card`):** `<h2>` tags.
    *   Font: `13px` / `var(--font-mono)`.
    *   Case: `uppercase`.
    *   Spacing: `letter-spacing: 0.1em`.
*   **Deviations:**
    *   `server.html` (`status_card`): `.status-card__title` uses `13px` mono, uppercase, but `border-left` accent.
    *   `tools.html`: Manual `<h2>` mimics `widget_card` but risks drift.
    *   `overview.html`: No headers on legacy metric cards.
    *   **Section Headers:** `.section-header h3` uses `15px` / `var(--font-sans)` / Normal case. This creates a hierarchy conflict where section titles look larger/different than widget titles.

## 4. Color Semantics
*   **Standard:** Uses `var(--signal-primary)`, `var(--text-0)`, `var(--bg-1)`.
*   **Deviations (Hardcoded/Inline):**
    *   `overview.html`: `background:rgba(20,20,25,0.6)` on legacy cards.
    *   `hosts.html`: `background: rgba(255,255,255,0.01)` on "What Changed" cards.
    *   `frontend/src/css/style.css`:
        *   `.stat-box.grade-b`: `border-left-color: #7fff00` (Hardcoded).
        *   `.stat-box.grade-d`: `border-left-color: #ff9500` (Hardcoded).
        *   `.feed-status-dot.ok`: `background: #00ff88 !important` (Hardcoded).
        *   `.feed-status-dot.error`: `background: #ff1744 !important` (Hardcoded).

## 5. Padding & Spacing
*   **Standard:** `.card` uses `padding: var(--panel-padding)` (usually `var(--space-4)`).
*   **Deviations:**
    *   `network.html` ("Network Intelligence"): `.widget-body-inner` has inline `style="padding: var(--space-4);"`.
    *   `overview.html`: Legacy cards use `padding: 15px` (Hardcoded pixel value).
    *   `hosts.html`: Discovery controls use `p-4` (Tailwind-style utility, likely `1rem`/`16px`) vs `var(--space-4)`.
    *   `style.css`: `.world-map-card` uses `padding: 0 !important`.

## 6. Specific File Locations
*   `frontend/templates/tabs/overview.html`: Legacy metrics (Lines ~5-45), World Map manual styling.
*   `frontend/templates/tabs/network.html`: Stat boxes mixed with widget cards. Inline styles in "Network Intelligence".
*   `frontend/templates/tabs/hosts.html`: Inline styles in "What Changed" (Lines ~35-70). Tailwind-like classes (`bg-gray-900`).
*   `frontend/templates/tabs/server.html`: Completely different card macro (`status_card`, `panel_card`).
*   `frontend/templates/tabs/tools.html`: Manual `<h2>` construction (Lines ~4-150).
*   `frontend/src/css/style.css`: Hardcoded colors in `.stat-box.grade-*`, `.feed-status-dot`, `.ev-state--*`.
