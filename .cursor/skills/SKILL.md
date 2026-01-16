# PHOBOS-NET — Cursor Skill Guide

This repository powers **PHOBOS-NET**, a security-focused network observability platform.
Cursor must follow the rules below strictly.

---

## 1. Core Principles (NON-NEGOTIABLE)

### 1.1 Truth over completeness
- Never infer, guess, or fabricate data
- If data is unavailable, show UNKNOWN / —
- Calm accuracy is preferred over noisy insight

### 1.2 Observational first
- Default behavior is read-only and passive
- No automatic enforcement, blocking, or remediation
- No background actions without explicit instruction

### 1.3 No silent behavior changes
- Do not change logic, thresholds, or semantics unless explicitly requested
- UI refactors must not alter meaning
- Refactors must preserve external behavior

---

## 2. Data & Semantics Rules

### 2.1 Baselines
- Baselines require warm-up (WARMING → PARTIAL → STABLE)
- Baselines must never affect health or alerts until STABLE
- After restart, baselines reset safely

### 2.2 Health scoring
- Overall Health is a *summary*, not a detector
- SNMP metrics are supporting signals only
- Health must never flip state due to a single signal

### 2.3 Alerts & anomalies
- Alerts must be explicit and explainable
- Anomalies ≠ alerts
- Zero-state alerts must feel reassuring, not alarming

---

## 3. SNMP Rules

### 3.1 SNMP is authoritative, not inferred
- Interface RX/TX must come from counters + deltas
- Never derive interface data from aggregate throughput
- Never fake interface status

### 3.2 Interface handling
- Use ifTable / ifXTable
- Prefer HC counters when available
- Map interfaces via descr / alias, not fixed indexes

---

## 4. NetFlow Rules

- NetFlow data is observational
- Flow counts ≠ host counts
- External churn is expected and valid
- Never collapse or deduplicate flows unless explicitly instructed

---

## 5. Hosts Page Rules

### 5.1 Host definition
- A host is an observed endpoint, not a device
- Hosts may be internal or external
- Discovery source must be explicit (Observed vs Discovered)

### 5.2 Active discovery
- Must be opt-in
- Must never run automatically
- Must be clearly separated from observed hosts

---

## 6. UI & UX Rules

### 6.1 Mobile
- Mobile is situational awareness, not full analytics
- Reduce density aggressively
- No “desktop shrunk to phone” layouts

### 6.2 Visual hierarchy
- No element should compete unnecessarily
- Health informs, alerts demand attention
- Zero states must feel calm

### 6.3 Tables
- Prefer cards or modals on mobile
- Never hide critical information behind hover
- Touch targets ≥ 44px

---

## 7. Performance & Safety

- Prefer caching over recomputation
- Never increase polling frequency without instruction
- Avoid background threads unless required
- Never block UI on long operations

---

## 8. Change Discipline

Before implementing:
- Identify whether change is UI, logic, or semantics
- Ask for clarification if scope is ambiguous

After implementing:
- Stop immediately when requested phase is complete
- Do not continue refactoring without approval

---

## 9. What Cursor Must NOT Do

- ❌ Invent metrics
- ❌ Infer host identity or importance
- ❌ Promote hints into alerts automatically
- ❌ Change health logic silently
- ❌ Mix active discovery with passive observation
- ❌ Optimize away correctness

---

## 10. Guiding Question

Before any change, ask:

> “Does this make the system more truthful, calmer, and easier to reason about?”

If not, do not proceed.