# 🔒 PHOBOS-NET — Locked Architecture Contract

This document defines the **non-negotiable semantic and architectural rules** of PHOBOS-NET.

All AI agents (Cursor, Claude, Jules, Gemini, etc.) **MUST follow this document strictly**.

Violating these rules is considered a **breaking change**, even if the code appears to function.

---

## 1. Core Semantic Separation (LOCKED)

PHOBOS-NET operates on **four strictly separated semantic layers**.

These layers **MUST NEVER be merged, inferred, auto-derived, or implicitly coupled**.

---

### 1.1 Events (Timeline)

Events are **raw, factual observations** sourced from:

- NetFlow
- Filterlog (packet decisions)
- Firewall control logs
- Syslog
- SNMP state changes
- PHOBOS-NET internal system events

Rules:
- Events are **high-volume and noisy by nature**
- Events are **chronological and immutable**
- Events are **informational only**
- Events **MUST NEVER escalate automatically**

Events answer:

> “What happened?”

---

### 1.2 Signals / Indicators

Signals are **derived observations** such as anomalies or deviations.

Rules:
- Signals are **informational**
- Signals provide **context, not urgency**
- Signals **MUST NEVER create alerts**
- Signals **MUST NEVER affect system health directly**

Examples:
- SYN-only traffic spikes
- TCP reset bursts
- ICMP floods
- Baseline deviations
- Elevated block/pass ratios

Signals answer:

> “This is notable.”

---

### 1.3 Alerts (STRICT)

Alerts are **rare, actionable, stateful objects**.

An Alert MUST:
- Represent a **persistent condition**
- Require **human action**
- Be **explicitly created** by alert logic
- Be **deduplicated** by condition
- Have a **clear lifecycle**

Every alert MUST include:
- `first_seen`
- `last_seen`
- `active` (boolean)
- `resolved_at` (nullable)

Rules:
- Multiple events update **ONE alert**
- Alerts **MUST auto-resolve** when conditions clear
- Alerts **MUST NEVER be created from**:
  - events
  - signals
  - anomalies
  - raw counters
  - traffic volume
  - firewall decision counts

Alerts answer:

> “Something requires action.”

---

### 1.4 System Health (LOCKED DEFINITION)

**System Health reflects observability integrity — NOT threat level.**

Health MAY depend on:
- NetFlow engine availability
- Syslog ingestion status
- SNMP reachability
- Database connectivity
- Sustained ingestion stalls
- Parser failure rates

Health MUST NOT depend on:
- Alert count
- Signal or anomaly count
- Traffic volume
- Firewall pass/block volume
- External attack activity
- Timeline size

Allowed states ONLY:
- `Healthy`
- `Degraded` (partial visibility)
- `Unavailable`

Health answers:

> “Can I trust what I’m seeing?”

---

## 2. Timeline Authority Rule (ABSOLUTE)

The Event Timeline is **non-authoritative**.

Rules:
- Timeline events MUST NEVER:
  - create alerts
  - increment alert counters
  - affect system health
  - imply urgency
- Timeline exists for:
  - context
  - explanation
  - investigation
- Absence of timeline events is **valid and calm**

---

## 3. Alert Count Discipline (LOCKED)

- Alert count MUST remain **low under normal operation**
- A noisy but healthy network SHOULD show:
  - 0–few active alerts
  - Healthy or Degraded system state
- High alert counts indicate a **logic error**, not a feature

If alert count grows unbounded → **architectural violation**

---

## 4. Security / Pressure Scores vs System Health (DO NOT MERGE)

These concepts are intentionally separate:

### System Health
- Infrastructure reliability
- Observability confidence
- Data pipeline integrity

### Security / Pressure / Activity Scores
- Threat volume
- Attack surface activity
- Environmental pressure

Rules:
- Security pressure MUST NOT degrade system health
- These values MUST NOT influence each other
- They MUST NOT be combined in UI or logic
- They MAY coexist, but remain independent

---

## 5. UI Truthfulness Contract

The UI MUST:
- Prefer “—” over guessing
- Distinguish clearly between:
  - unavailable vs zero
  - noisy vs dangerous
- Avoid alarmist language unless action is required

Forbidden UI patterns:
- “Unhealthy” due to traffic volume
- Large red numbers without action
- Alert inflation visuals
- Severity implied by color alone

Calm, truthful UX is a **core requirement**, not polish.

---

## 6. Change Discipline (ENFORCED)

Before implementing any change, AI agents MUST ask:

> “Which layer am I modifying: Events, Signals, Alerts, or Health?”

If unclear → **STOP and ask for clarification**.

After completing a requested phase:
- STOP immediately
- Summarize exactly what changed
- Do NOT continue refactoring or adding features

---

## 7. Guiding Principle (FINAL)

> **Observability systems must be calm, honest, and boring when things are fine.**  
> Noise is data. Alerts are decisions.

If a change violates this principle, it must not be implemented.

---

## 8. Architecture Version

This document locks:

**PHOBOS-NET Architecture v1.0**

Any change to this file requires **explicit human approval**.