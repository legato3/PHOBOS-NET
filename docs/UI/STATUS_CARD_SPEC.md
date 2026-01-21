# PHOBOS-NET UI Component Specification
## Status Card v3 — Canonical Server Monitor Widget

**Component:** `status-card`  
**Version:** v3 (canonical)  
**Scope:** Server monitoring widgets (NetFlow, Filterlog, Firewall, future service monitors)

### Purpose
Status Card v3 is the canonical UI component for displaying real-time and near-real-time system metrics.
It prioritizes **visual stability**, **clear hierarchy**, and a **clean cyberpunk** aesthetic.

---

## 1) Non‑negotiable principles

1. **Hero First**
   - The central metric is the primary signal.
   - It must always visually dominate the card.

2. **No Layout Jumps**
   - The card must not shift when data changes or is missing.

3. **Single Visual Language**
   - Same structure, spacing, typography rhythm across cards.

4. **Dark, Calm, High‑Tech**
   - No scanlines.
   - Glow is subtle, semantic, and controlled.

---

## 2) Canonical DOM contract (required)

Every status card **must** use this structure exactly:

```
.status-card
├── .status-card__header
│   ├── .status-card__title
│   └── .status-card__meta
│       └── .status-card__meta-item (repeatable)
├── .status-card__hero
│   └── .status-card__hero-content
│       ├── .status-card__hero-value
│       └── .status-card__hero-unit
└── .status-card__statstrip
    ├── .status-card__stat (x4)
        ├── .status-card__stat-label
        ├── .status-card__stat-value
        └── .status-card__stat-subvalue
```

### Contract rules
- No block may be conditionally omitted.
- If data is unavailable: render `—` (never fabricate, never “NaN”).
- `.status-card__stat-subvalue` must **always** exist (reserved height), even if empty.

---

## 3) Header specification

### `.status-card__header`
**Purpose:** identification + current state

- Left: `.status-card__title`
- Right: `.status-card__meta` containing:
  - informational meta items (e.g., `UDP 2055`, `UDP 514`, `SOURCE …` if needed)
  - optional state badge (ACTIVE / STALE / OFFLINE)

#### Title rules
- Uppercase
- Mono
- Stronger contrast than meta
- Optional left accent bar is allowed (thin, semantic color)

#### Meta rules
- No “UPDATED …” / “X ago” strings (timestamps are shown elsewhere if required)
- Small, readable, stable height

#### State badge rules
Allowed states:
- `ACTIVE` (ok)
- `STALE` (warn, optional)
- `OFFLINE` (crit)

State affects **color only**, never layout.

---

## 4) Hero specification

### `.status-card__hero`
**Purpose:** primary signal

Requirements:
- Centered horizontally and vertically
- Minimum height enforced (hero dominates)
- Optical centering is allowed (tiny translateY)

Value:
- Large mono
- Light weight
- Subtle cyan glow

Unit:
- Smaller, muted
- Baseline aligned relative to the value

---

## 5) Stat strip specification

### `.status-card__statstrip`
**Purpose:** secondary metrics (supporting context)

- Grid: 4 columns
- Stable height
- Each cell has: label, value, subvalue (reserved)

Examples:
- NetFlow: FILES / FLOWS / ERRORS / LAST
- Filterlog: RCVD / PARSED / ERRORS / LAST
- Firewall: RCVD / PARSED / ERRORS / LAST

---

## 6) Stability constraints (v3 canonical)

These invariants keep the UI from drifting:

- Card: stable padding and border
- Hero: minimum height enforced
- Stat strip: min/max height enforced
- Subvalue slot: fixed min-height

If a change requires breaking these invariants:
> Create v4. Do not mutate v3.

---

## 7) Forbidden patterns

- Scanlines
- Animated backgrounds
- Expand/collapse “details”
- Duplicate metrics
- Conditional removal of DOM blocks
- Inline timestamps like “UPDATED 8940D AGO”
- Per-card layout overrides

---

## 8) Extension policy

Adding a new server metric card:
1. Copy the canonical template (see `frontend/templates/components/status_card.html`)
2. Change only labels + bindings
3. Keep the DOM contract intact
