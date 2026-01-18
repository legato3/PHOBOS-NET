# PHOBOS-NET Time Range Correctness Audit Report

**Date:** 2026-01-18  
**Auditor:** Gemini (Automated)  
**Scope:** Frontend time range usage, Backend API time window handling, UI labeling consistency

---

## Executive Summary

This audit identified **8 time-related inconsistencies** where data was queried, presented, or labeled across incompatible time scopes. Corrective actions have been applied to ensure:

1. Backend endpoints document their time scope via `time_scope` metadata
2. Frontend widgets explicitly label fixed-scope windows (e.g., "(24h)")
3. Time-aware widgets properly pass the user's selected `timeRange`
4. Code comments mark fixed-scope fetches for maintainability

---

## Time Model Reference

| Scope Type | Description | Example |
|------------|-------------|---------|
| **LIVE** | Real-time / near-real-time | Active Flows (1h refresh) |
| **SELECTED RANGE** | User-selected window | Top Sources (respects time selector) |
| **FIXED WINDOW** | Hard-coded range | Alert History (always 24h) |
| **CUMULATIVE** | Since start/boot | Feed health totals |

---

## Issues Found & Corrective Actions

### 1. `/api/stats/hourly` — Backend Ignores Range Parameter

| Field | Value |
|-------|-------|
| **Widget** | Traffic by Hour (Network tab) |
| **Endpoint** | `/api/stats/hourly` |
| **Issue** | Frontend passed `range=${this.timeRange}` but backend hardcoded `get_time_range("24h")` |
| **Why Misleading** | Endpoint accepted but ignored the range parameter silently |
| **Corrective Action** | ✅ Removed unused `range` parameter from frontend call. Added `// FIXED-SCOPE: Always 24h` comment. UI already correctly labeled "(24h)" |
| **File Changed** | `frontend/src/js/store/index.js` line 3708 |

---

### 2. `fetchAttackTimeline()` — Did Not Pass Time Range

| Field | Value |
|-------|-------|
| **Widget** | Attack Timeline (Security tab) |
| **Endpoint** | `/api/security/attack-timeline` |
| **Issue** | `fetchAttackTimeline()` called endpoint without `range` parameter, defaulting to 24h |
| **Why Misleading** | Widget appeared on same page as time-aware widgets but didn't respond to time selector |
| **Corrective Action** | ✅ Modified `fetchAttackTimeline()` to pass `this.timeRange`. Added `// TIME-AWARE` comment. |
| **File Changed** | `frontend/src/js/store/index.js` line 2619 |

---

### 3. `/api/security/mitre-heatmap` — Fixed 24h, No Label

| Field | Value |
|-------|-------|
| **Widget** | Detected Techniques (Security tab) |
| **Endpoint** | `/api/security/mitre-heatmap` |
| **Issue** | Backend used fixed 24h cutoff but widget title didn't indicate this |
| **Why Misleading** | Users expected widget to respond to time selector |
| **Corrective Action** | ✅ Added `(24h)` to widget title. Added `time_scope: '24h'` to API response. Added `FIXED-SCOPE` comment. |
| **Files Changed** | `frontend/templates/tabs/security.html` line 528, `app/api/routes/security.py` line 2778 |

---

### 4. `/api/security/alerts/history` — Fixed 24h (Correctly Labeled)

| Field | Value |
|-------|-------|
| **Widget** | Alert History (24h) (Security tab) |
| **Endpoint** | `/api/security/alerts/history` |
| **Status** | ✅ **CORRECT** — UI already labeled "(24h)" |
| **Enhancement** | Added `time_scope: '24h'` to API response for auditability |
| **File Changed** | `app/api/routes/security.py` line 2522 |

---

### 5. `/api/hosts/{ip}/timeline` — Fixed 24h (Correctly Labeled)

| Field | Value |
|-------|-------|
| **Widget** | Host Detail Modal timeline chart |
| **Endpoint** | `/api/hosts/{ip}/timeline` |
| **Status** | ✅ **CORRECT** — Frontend hardcodes `?range=24h`, UI shows "Timeline (24h)" |
| **Notes** | No changes needed |

---

### 6. `/api/network/stats/overview` — Mixed Time Scopes

| Field | Value |
|-------|-------|
| **Widget** | Network Stats Overview (Network tab stat boxes) |
| **Endpoint** | `/api/network/stats/overview` |
| **Issue** | Response mixed `active_flows` (1h) with `anomalies_24h` (24h) without metadata |
| **Current UI Labels** | "Active Flows" shows "Live" sublabel, "Network Anomalies (24h)" correctly labeled |
| **Corrective Action** | ✅ Added `time_scope` metadata to API response documenting each field's window |
| **File Changed** | `app/api/routes/traffic.py` line 1912 |

---

### 7. `/api/security/threats/by_country` — Fixed 24h, No Label

| Field | Value |
|-------|-------|
| **Widget** | Threats by Country (Security tab) |
| **Endpoint** | `/api/security/threats/by_country` |
| **Issue** | Backend used fixed 24h cutoff but widget title didn't indicate this |
| **Why Misleading** | Users expected widget to respond to time selector |
| **Corrective Action** | ✅ Added `(24h)` to widget title. Added `time_scope: '24h'` to API response. |
| **Files Changed** | `frontend/templates/tabs/security.html` line 244, `app/api/routes/security.py` line 2936 |

---

### 8. `/api/firewall/stats/overview` — Fixed 24h (Correctly Labeled)

| Field | Value |
|-------|-------|
| **Widget** | Firewall Stats Overview (Firewall tab, Overview tab) |
| **Endpoint** | `/api/firewall/stats/overview` |
| **Status** | ✅ **CORRECT** — UI labels show "(24h)" for all metrics |
| **Notes** | No changes needed |

---

## Widgets That Intentionally Ignore Global Time Range

The following widgets use **fixed time windows by design** and are now explicitly labeled:

| Widget | Fixed Window | Reason |
|--------|--------------|--------|
| Alert History | 24h | Security alerts need consistent historical context |
| Blocked Events | 24h | Firewall metrics for daily trend analysis |
| Network Anomalies | 24h | Anomaly detection requires 24h baseline |
| Threat Velocity | 1h current, 24h total | Velocity calculations use fixed windows |
| Traffic by Hour | 24h | Hourly distribution requires full 24h data |
| Detected Techniques (MITRE) | 24h | Technique mapping from alerts (24h) |
| Threats by Country | 24h | Geo-location of threats (24h) |
| Host Detail Timeline | 24h | Modal shows fixed 24h activity |
| Top Threat IPs | 24h | Threat IP ranking (24h) |
| Total Hosts / New Hosts | 24h | Host discovery metrics (24h) |

---

## Widgets That Respect Global Time Range

These widgets correctly use `this.timeRange` or `this.global_time_range`:

| Widget | Controlled By |
|--------|---------------|
| Top Sources | `global_time_range` |
| Top Destinations | `global_time_range` |
| Top Ports | `global_time_range` |
| Protocols | `global_time_range` |
| Top Countries | `global_time_range` |
| Top ASNs | `global_time_range` |
| Flow Statistics | `global_time_range` |
| Protocol Hierarchy | `global_time_range` |
| Active Flows (Firewall) | `global_time_range` |
| Bandwidth Chart | `global_time_range` |
| Attack Timeline | `global_time_range` **(FIXED in this audit)** |
| Summary Stats | `global_time_range` |
| Blocklist Match Rate | `global_time_range` |
| Protocol Anomalies | `global_time_range` |

---

## API Response Metadata Added

The following endpoints now include `time_scope` metadata for auditability:

```json
// /api/network/stats/overview
{
  "time_scope": {
    "active_flows": "1h",
    "external_connections": "1h",
    "anomalies_24h": "24h"
  }
}

// /api/security/alerts/history
{
  "time_scope": "24h"
}

// /api/security/mitre-heatmap
{
  "time_scope": "24h"
}

// /api/security/threats/by_country
{
  "time_scope": "24h"
}
```

---

## Files Modified

| File | Changes |
|------|---------|
| `frontend/src/js/store/index.js` | Fixed `fetchAttackTimeline()` to use `timeRange`, removed unused range param from `fetchHourlyTraffic()`, added scope comments |
| `frontend/templates/tabs/security.html` | Added "(24h)" labels to MITRE Heatmap and Threats by Country widgets |
| `app/api/routes/security.py` | Added `time_scope` metadata to alerts/history, mitre-heatmap, and threats/by_country endpoints |
| `app/api/routes/traffic.py` | Added `time_scope` metadata to network/stats/overview endpoint |

---

## Recommendations for Future Development

1. **New Endpoints**: Always include `time_scope` in API responses
2. **New Widgets**: Label fixed-scope widgets with their window (e.g., "(1h)", "(24h)")
3. **Code Comments**: Mark fixed-scope fetches with `// FIXED-SCOPE:` comments
4. **Code Comments**: Mark time-aware fetches with `// TIME-AWARE:` comments
5. **Testing**: When adding time-dependent widgets, verify they respond to time selector changes

---

## Verification Checklist

- [x] All fixed-scope widgets are labeled in UI
- [x] All time-aware widgets pass `timeRange` to backend
- [x] Key API responses include `time_scope` metadata
- [x] Code comments document scope intent
- [x] No silent mixing of different time windows without disclosure

---

*End of Audit Report*
