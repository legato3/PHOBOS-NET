# AGENTS.md — PHOBOS-NET

This file defines **non-negotiable rules** and **operational context** for any AI agent (Cursor, Codex, Claude, Gemini, etc.) working on PHOBOS-NET.

PHOBOS-NET is a **read-only network observability system**.
Truth, calmness, and correctness always outweigh features or visual flair.

---

## 1. Core Principles (LOCKED)

### 1.1 Truth over completeness
- Never invent, infer, or approximate data.
- If data is unavailable, explicitly show `UNKNOWN`, `—`, or `STALE`.
- Silent failure or “best guess” behavior is forbidden.

### 1.2 Observational, not reactive
- No automatic blocking, enforcement, mitigation, or remediation.
- No hidden background actions.
- Everything must be explicit and explainable.

### 1.3 No silent behavior changes
- Do **not** change thresholds, alert semantics, health scoring, or aggregation windows unless explicitly instructed.
- UI refactors must preserve meaning.

---

## 2. Architecture Boundaries

### Backend
- Flask-based API.
- Services are **data producers**, not decision-makers.
- Health ≠ Alerts ≠ Signals.

### Frontend
- Jinja templates + lightweight JS.
- UI reflects backend truth only.
- UI never “fixes” backend ambiguity.

---

## 3. Health, Alerts, and Signals (CRITICAL)

### Health
- Measures **system operability**, not threat level.
- Depends only on ingestion and system availability.
- Must never degrade due to attacks or traffic volume.

### Alerts
- Rare, actionable, persistent.
- Require repetition and time persistence.
- Auto-resolution must be explicit.

### Signals / Indicators
- Informational only.
- Never escalate health.
- May be noisy by design.

---

## 4. Data Source Rules

### NetFlow
- Observational only.
- Flow count ≠ host count.
- External churn is expected.
- `nfdump` is the source of truth.
- Default window: **48h**.

### Syslog (OPNsense)
- Filterlog and Firewall logs are **separate streams**.
- Strict parsing, schema-driven.
- No silent merging.

### SNMP
- Authoritative source.
- Use counters + deltas.
- Never infer state from traffic volume.

---

## 5. UI & UX Rules

### Status Card v3 (Canonical)
- Rectangular, angular cards.
- Consistent border, header, typography, spacing.
- Hero value primary; stat strip secondary.

### Visual hierarchy
- Health informs.
- Alerts demand attention.
- Zero states must feel calm.

---

## 6. Performance & Safety
- Prefer caching over recomputation.
- No increased polling without approval.
- No blocking UI.
- Background threads only when required.

---

## 7. Change Discipline
- Identify change type before implementing.
- Ask when ambiguous.
- Stop when requested scope is complete.

---

## 8. Release Discipline
- Versions must align (UI, backend, Docker, tags).
- Multi-arch Docker images mandatory.
- v2.0.0 is a stable major release.

---

## 9. Forbidden Actions
- Invent metrics.
- Promote signals to alerts.
- Change health logic silently.
- Trade correctness for visuals.

---

## 10. Guiding Question

> Does this make the system more truthful, calmer, and easier to reason about?

If not, do not proceed.
