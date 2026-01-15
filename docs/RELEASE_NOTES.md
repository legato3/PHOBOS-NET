PROX_NFDUMP — v1.0 Release Notes

Release: v1.0 — Stable Investigation Platform

Status: Production-ready (operator-grade)
Focus: Trust, clarity, explainability, performance

⸻

🎯 Purpose of v1

v1 establishes PROX_NFDUMP as a reliable network & security investigation platform, not a demo dashboard.

The core goals of this release were:
	•	truthful metrics (no UI-derived data)
	•	explainable health and detections
	•	calm, low-noise UX
	•	clear investigation paths
	•	predictable performance under load

⸻

🧱 Architecture & Refactor
	•	Fully refactored monolithic codebase into clean modules:
	•	services/ (netflow, threats, firewall, stats)
	•	utils/ (DNS, GeoIP, helpers)
	•	db/ abstraction
	•	api/ routes
	•	Clear separation between:
	•	heuristics (UI hints)
	•	detections (authoritative backend logic)
	•	No circular imports, no hidden side effects

Result: Maintainable, extensible foundation.

⸻

⚡ Performance & Observability
	•	Added safe, bounded, TTL-based caching
	•	Instrumented:
	•	nfdump subprocess usage
	•	service execution time
	•	API request latency
	•	Exposed metrics via /api/performance/metrics
	•	No blocking DNS or GeoIP calls in hot paths

Result: Predictable performance and early regression visibility.

⸻

🔁 Active Flows (Major Upgrade)
	•	Corrected AGE calculation
	•	Separated display limits from ground-truth counts
	•	Fixed critical bug where capped lists affected stats
	•	Added:
	•	direction indicators
	•	cached DNS resolution
	•	clear IP → port → protocol hierarchy
	•	Added subtle “interesting flow” hints (non-alarming)

Result: Active Flows can be trusted during live investigation.

⸻

🧠 Heuristics & Detections
	•	Introduced explainable heuristics as visual hints only
	•	Promoted exactly one high-confidence heuristic to detection:
	•	long-lived, low-volume external flows
	•	All detections are:
	•	deterministic
	•	explainable
	•	linkable back to flows

Result: No alert fatigue, no “magic scoring”.

⸻

🔍 Investigation UX (Modals & Correlation)
	•	Unified investigation modal pattern for:
	•	flows
	•	firewall logs
	•	threat events
	•	Added contextual correlation:
	•	flows ↔ threats
	•	threats ↔ related flows
	•	Clear, reversible investigation paths:
Overview → Threat → Flow → Context

Result: Analysts never lose context.

⸻

🧱 Firewall Page Improvements

Added four high-signal metrics:
	1.	Blocked events (24h)
	2.	Unique blocked sources
	3.	New blocked IPs
	4.	Top block reason / rule

Result: Control & explanation instead of raw volume.

⸻

🌐 Network Page Improvements

Added behavior-focused metrics:
	1.	Network Health
	2.	Active Flows
	3.	External Connections
	4.	Network Anomalies (24h)

Result: Answers “Is the network behaving normally?”

⸻

🧭 Overview Page (Triage)

Redesigned to answer:

“Is everything okay — and where should I look?”

Final metrics:
	1.	Overall Health (state, not score)
	2.	Active Alerts
	3.	Active Flows
	4.	External Connections
	5.	Blocked Events (24h)
	6.	Anomalies (24h)

Each stat box has a clear click-through destination.

⸻

❤️ Overall Health (Trust-First Design)
	•	Removed meaningless numeric health scores
	•	Health states:
	•	Healthy
	•	Degraded
	•	Unhealthy
	•	Health is based on multiple corroborating signals
	•	UI explains why health is degraded or unhealthy
	•	Integrated adaptive baselines

Result: Red states are rare and meaningful.

⸻

📊 Baselines, Trends & NOC Mode
	•	Automatic, environment-specific baselines for key metrics
	•	Subtle “since last hour” trend hints
	•	Read-only NOC / wallboard mode for continuous monitoring

Result: Calm monitoring without panic.