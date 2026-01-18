# PHOBOS-NET

PHOBOS-NET is a self-hosted **network observability and security dashboard** built as a hobby project.  
It combines **NetFlow**, **SNMP**, and lightweight analytics into a calm, explainable UI focused on *understanding* network behavior rather than reacting to it.

This project intentionally prioritizes **clarity, trust, and signal** over alerts, automation, or configuration complexity.

---

## ✨ Key Characteristics

- Read-only, observational by design
- No alert storms, no automation, no enforcement
- Baseline-aware insights that explain *what stands out*
- Explicit normal states (never silent or empty)
- Desktop and mobile-friendly layouts
- Designed to stay understandable as complexity grows

---

## ❌ What PHOBOS-NET Is Not

PHOBOS-NET does **not** aim to be:

- An IDS/IPS
- A firewall management interface
- A configuration or tuning tool
- An AI/ML-driven anomaly engine
- A production NOC platform
- No alerting workflows

---
Raw measurements such as:
- Traffic volume
- Flow counts
- CPU, memory, disk usage
- Database size and growth

Stats answer:
> “What is happening?”

---

### Insights
Derived summaries that highlight patterns:
- Top talkers
- Dominant protocols
- Sustained deviations
- Explicit confirmations of stability

Insights answer:
> “What stands out right now?”

Insights are:
- Stable (no flapping)
- Baseline-aware
- Never empty
- Clear about time context

---

### Health
High-level status indicators for:
- Network
- System
- Database

Health answers:
> “Should I be concerned?”

Health states always include a short explanation, even when healthy.

---

## 📊 Features

### Network & Traffic
- NetFlow ingestion and aggregation
- Active flows and top talkers
- Protocol and port distribution
- Traffic world map
- Network health indicators

### Hosts
- Observed hosts based on traffic
- First-seen / last-seen tracking
- Per-host traffic and flow counts
- Internal vs external classification

### Firewall
- Blocked event summaries
- Threat feed integration
- Lightweight correlation
- Firewall activity insights

### Server & System
- CPU, memory, disk metrics
- NetFlow engine status
- SNMP interface statistics
- Syslog activity overview
- SQLite database statistics

### Insights Engine
- Reusable insight panels
- Baseline vs notable insights
- Expandable breakdowns
- Consistent behavior across pages

### Mobile Support
- Mobile-first layouts
- Predictable expand/collapse behavior
- Reduced density without loss of meaning

---

## 🛠 Architecture (High-Level)

- **Backend**
  - Python
  - NetFlow parsing (nfdump)
  - SNMP polling
  - SQLite for local storage

- **Frontend**
  - Custom UI components
  - Stat boxes, insight panels, tables
  - Focused on visual hierarchy and scanability

- **Data Philosophy**
  - Read-only
  - Cached where appropriate
  - No writes triggered by UI reads

---

## 🚦 Project Status

- **Current version:** v1.1
- **Stability:** Suitable for hobby and personal use
- **Focus:** UX consistency, insight quality, polish
- **Development style:** Iterative, exploratory, no fixed roadmap

---

## 🧭 Design Principles

- Every page answers one primary question
- Insight panels are never empty
- Normal behavior is explicitly stated
- Data is reorganized, not hidden
- Consistency is preferred over cleverness
- Calm UX is preferred over urgency

---

## 📄 License

Provided as-is for personal and educational use.  
No warranty, no guarantees.

---

## 💡 Why This Exists

Many monitoring tools are powerful but noisy, complex, or opaque.

PHOBOS-NET is an experiment in building a system that:
- Explains itself
- Encourages understanding
- Stays calm under normal conditions
