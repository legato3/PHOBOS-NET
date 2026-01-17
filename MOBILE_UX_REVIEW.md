# PHOBOS-NET Mobile UX Review

## Executive Summary
PHOBOS-NET's mobile layout provides a solid foundation with responsive grids and touch-friendly targets (`min-height: 44px`). However, critical navigation issues and information density problems hinder situational awareness. The current implementation suffers from navigation inconsistencies, redundant data display, and scrolling traps in data tables.

## Prioritized Issues & Improvements

### 1. Critical Navigation Discrepancy (High Impact)
**Issue:** The mobile bottom navigation bar (`.mobile-nav`) is incomplete and misleading compared to the desktop sidebar.
- **Missing Tabs:** 'Hosts', 'Firewall' (actual logs), and 'Interfaces' are completely inaccessible from the bottom nav.
- **Mislabeling:** The bottom nav item labeled "Firewall" actually links to the 'Forensics' tab (`loadTab('forensics')`).
- **Renaming:** "Assistant" is labeled "AI", "Server" is labeled "Servers", creating minor cognitive load.

**User Experience:**
A mobile user looking for firewall logs or host details is effectively locked out unless they discover the sidebar hamburger menu. Tapping "Firewall" takes them to Forensics (Flow Search), which is not what they expect.

**Improvement Suggestion:**
- **Consolidate Navigation:** Add a "More" (...) button as the last item in the bottom navigation.
- **Action:** This "More" button should open a bottom-sheet modal (using the existing modal pattern) listing the missing tabs: Hosts, Firewall (Logs), Interfaces.
- **Correction:** Rename the bottom nav "Firewall" item to "Forensics" to match the desktop UI and link behavior.

### 2. Redundant Status Areas (High Impact)
**Issue:** The layout displays two separate status areas above the fold:
1. `.mobile-stats-bar`: A horizontal scroll/flex row showing CPU, MEM, Threats, Flows.
2. `.summary-stats-grid`: A grid immediately below showing Health, Alerts, Flows (again), etc.

**User Experience:**
Valuable vertical screen real estate is wasted on duplicate information. The user has to scan two different areas to get a "system health" picture.

**Improvement Suggestion:**
- **Merge & Simplify:** Remove the `.mobile-stats-bar`.
- **Restructure:** Integrate CPU and MEM metrics into the "Overall Health" card within the main grid.
- **Layout:** Make the "Overall Health" card full-width (`col-span-2`) on mobile to accommodate these extra metrics without cramping.

### 3. Stat Box Grid Density (Medium Impact)
**Issue:** The summary stats are presented in a 2-column grid with 5 items (Health, Alerts, Flows, Ext Conn, Blocked Events).
- **Result:** This creates an uneven grid (2 rows of 2, plus 1 orphan row), or visual gaps.

**User Experience:**
The layout feels cluttered. The "Overall Health" card is arguably the most important but shares equal weight with secondary metrics.

**Improvement Suggestion:**
- **Hierarchy:** Change the grid to make the top two cards ("Overall Health" and "Active Alerts") full-width rows.
- **Grouping:** Keep the remaining metrics (Flows, Ext Conn, Blocked Events, Anomalies) in the 2-column grid below. This establishes a clear visual hierarchy: Status -> Alerts -> Metrics.

### 4. Data Table Scrolling Traps (Medium Impact)
**Issue:** Widgets like "Top Sources" and "Top Destinations" use `overflow-x: auto` for tables.
- **Result:** Tables often take up significant width.

**User Experience:**
When swiping vertically to scroll the dashboard, a user's thumb may catch a table, triggering unwanted horizontal scrolling instead of page scrolling.

**Improvement Suggestion:**
- **Limit Rows:** Default to showing only the top 3-5 rows on mobile.
- **Defer:** Rely on the existing "View All" button to open the full table in a modal (which is already implemented but can be emphasized).
- **Styling:** Ensure the table container has a slight margin or padding so edge-swiping still works for the page.

### 5. Hover-Dependent Information (Medium Impact)
**Issue:** Sparklines (`canvas.spark`) and Trend indicators (e.g., `title="Since last hour..."`) rely on mouse hover to reveal specific values or context.

**User Experience:**
Mobile users see a line but cannot easily see the specific trend percentage or the "why" behind it without awkward long-pressing.

**Improvement Suggestion:**
- **Explicit Text:** Render the trend percentage (e.g., "+5%") directly as text next to the value or sparkline on mobile.
- **Touch Interaction:** Make the entire card tappable to open a simple modal or expand the card to show the "tooltip" content (Trend details, exact values).

### 6. Chart Vertical Dominance (Low Impact)
**Issue:** The Bandwidth chart and other chart widgets have fixed or substantial heights.

**User Experience:**
A single chart can dominate the entire mobile viewport, pushing other context off-screen.

**Improvement Suggestion:**
- **Collapse by Default:** Treat charts like the World Map: collapsed by default on mobile with a "Show Chart" toggle.
- **Sparkline Alternative:** Show a smaller, static sparkline by default, and expand to the full interactive Chart.js canvas on tap.

### 7. Accessibility & Touch Targets (Low Impact)
**Issue:** While `min-height: 44px` is good, some secondary actions (like tiny "filter" icons in tables) might be too close to other elements.

**Improvement Suggestion:**
- **Spacing:** Increase padding in table rows (`.network-endpoint-row`) to ensure the "Filter" button doesn't conflict with the "IP Address" click target (which opens a modal).
