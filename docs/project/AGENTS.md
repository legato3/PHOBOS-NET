
# AGENTS.md — AI Agent Operating Guide for PHOBOS-NET

This document defines how AI coding agents must work inside the PHOBOS-NET codebase.
It exists to prevent regressions, scope creep, and broken observability logic.

PHOBOS-NET is a single-node, Docker-based network observability dashboard.
It prioritizes clarity, determinism, and explainability over automation magic.

---

## 1. Project Philosophy (READ FIRST)

PHOBOS-NET follows these rules:

- Observability first, automation second
- Anomalies ≠ Alerts
- Data must persist before UI consumes it
- Health is derived, never guessed
- Docker paths are not runtime settings

AI agents must NOT change behavior unless explicitly instructed.

If unsure: ask, don’t assume.

---

## 2. Core Architecture

Backend:
- Python 3 + Flask
- Modular services under app/services
- SQLite used for persistence (alerts, firewall logs, trends)
- Heavy operations cached with TTL + locks

Frontend:
- Alpine.js (no build step)
- Single-page dashboard
- UI is reactive but dumb: backend owns logic

Data Sources:
- NetFlow via nfdump (CLI)
- SNMP polling (firewall health)
- Syslog (firewall blocks)
- Threat intelligence feeds

Deployment:
- Docker container
- Paths and binaries are environment concerns
- UI must not expose filesystem internals

---

## 3. Data Lifecycle Rules

### Flows
Flows are raw NetFlow records.
They must never be directly treated as alerts.

### Anomalies
Anomalies are soft signals:
- statistical deviations
- suspicious patterns
- heuristic matches

They:
- affect health score
- increment counters
- do NOT automatically appear in Alert History

### Alerts
Alerts are escalated anomalies.

Rules:
- Alerts must be persisted
- Alerts must be deduplicated
- Alerts must have timestamps
- Alerts must appear in Alert History (24h)

Never create UI-only alerts.

---

## 4. Alert Escalation Rules

An anomaly becomes an alert if ANY is true:
- Severity is HIGH
- Same anomaly repeats ≥ 3 times within 10 minutes
- Anomaly persists across polling intervals
- Watchlist IP involved

Deduplication fingerprint:
(type, source_ip, destination_ip, port)

Deduplication window:
- 30 minutes

Existing alerts should update count and last_seen, not create new rows.

---

## 5. Time Range Semantics (CRITICAL)

Time selectors (Live / 1h / 6h / 24h):
- Must affect backend queries
- Must not be cosmetic
- Must propagate to:
  - charts
  - counters
  - insights
  - alert history

If a widget ignores time range, it is a bug.

---

## 6. SNMP Rules

SNMP data:
- Is authoritative for firewall health
- Must be cached
- Must fail gracefully
- Must never block UI

Interface metrics must come from expanded OIDs.
Never fake interface data.

---

## 7. Configuration UI Rules

Settings UI:
- Exposes runtime-safe values only

Allowed:
- DNS server
- Internal networks
- SNMP host/community/poll interval
- Detection sensitivity
- Default time range

Forbidden:
- Filesystem paths
- Docker volume locations
- Binary paths

Paths belong in env or docker-compose.

---

## 8. Frontend Rules

- Alpine.js state must remain reactive
- No hardcoded magic numbers
- Mobile layout must be first-class
- Empty states must be informative, not blank

Never hide missing data silently.

---

## 9. Performance & Safety

- nfdump calls are expensive → cache aggressively
- SQLite writes must be controlled
- Never introduce infinite loops (sparklines, timers)
- Avoid N+1 backend calls

---

## 10. What AI Agents MUST NOT Do

- Do not refactor large areas without instruction
- Do not change detection thresholds silently
- Do not invent new alert types
- Do not “optimize” UI by hiding data
- Do not remove persistence layers

---

## 11. When in Doubt

If behavior seems unclear:
- Inspect data flow
- Check persistence
- Ask the human

PHOBOS-NET values correctness over cleverness.

---

Last updated: v1.2
Project: PHOBOS-NET  
Maintained by: Human + AI collaboration
