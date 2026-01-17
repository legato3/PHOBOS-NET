# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PHOBOS-NET is a self-hosted network observability dashboard combining NetFlow, SNMP, and syslog. It prioritizes **clarity, truth, and calm UX** over alerts and automation. Read-only by design.

## Commands

### Development
```bash
# Local development (Flask dev server)
source .venv/bin/activate
python app/main.py

# Production (Docker)
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml logs -f netflow-dashboard

# Fast code update (avoids full rebuild)
docker cp app/ phobos-net:/app/
docker exec phobos-net pkill -f gunicorn

# Health check
curl http://localhost:8080/health
```

### Dependencies
```bash
pip install -r docker-data/requirements.txt gunicorn>=21.2.0
```

No test suite or linting configured.

## Architecture

### Data Flow
```
nfcapd (NetFlow files) → nfdump CLI (CSV) → parse_csv() → cache → API → Frontend
SNMP polling → snmp.py → cache → API → Frontend
Syslog UDP → syslog.py → firewall.db → API → Frontend
Threat feeds HTTP → threats.py → memory → API → Frontend
```

### Backend (Python/Flask)
- **Entry points**: `app/main.py` (local), `scripts/gunicorn_config.py` (production)
- **Routes**: `app/api/routes/` — traffic.py (24 routes), security.py (17 routes), system.py (7 routes)
- **Services**: `app/services/` — netflow/, security/, shared/ (snmp, syslog, geoip, dns, baselines)
- **State**: `app/core/app_state.py` — global caches, locks, baselines, metrics
- **Config**: `app/config.py` — all constants, thresholds, paths, OIDs

### Frontend (Alpine.js + Jinja2)
- **Templates**: `frontend/templates/` — index.html, tabs/*.html, macros/widgets.html
- **JS modules**: `frontend/src/js/modules/` — api.js, charts.js, utils.js
- **Store**: `frontend/src/js/store/index.js` — Alpine reactive state
- No build step; vanilla JS modules

### Background Threads
Started in main.py or gunicorn post_worker_init:
- ThreatFeedThread (15min)
- TrendsThread (30s)
- AggregationThread (60s)
- SNMPThread (2s)
- SyslogThread (UDP listener)
- DbSizeSamplerThread (60s)

### Databases
- `netflow-trends.sqlite` — traffic rollups, host memory
- `firewall.db` — syslog block logs

## Non-Negotiable Rules

From `.cursor/skills/SKILL.md`:

1. **Truth over completeness** — Never invent/guess data. Show UNKNOWN if unavailable.
2. **Observational first** — Read-only by default. No automated enforcement.
3. **No silent behavior changes** — Refactors must preserve external behavior exactly.
4. **Baselines require warm-up** — WARMING → PARTIAL → STABLE state machine.
5. **Health is summary, not detector** — Never flip state on single signal.
6. **SNMP is authoritative** — Interface RX/TX from counters, never derived.
7. **NetFlow is observational** — Flow counts ≠ host counts.

**Before any change ask**: "Does this make the system more truthful, calmer, and easier to reason about?"

## Key Files

| File | Purpose |
|------|---------|
| `app/config.py` | Central config: TTLs, thresholds, paths, SNMP OIDs, port mappings |
| `app/core/app_state.py` | Global caches, locks, baselines, metrics |
| `app/services/netflow/netflow.py` | nfdump wrapper, CSV parsing, traffic direction |
| `app/services/security/threats.py` | Threat feeds, anomaly detection, MITRE mappings |
| `app/services/shared/snmp.py` | SNMP polling (CPU, memory, interfaces) |
| `docker/docker-compose.yml` | Container config, port mapping (3434:8080), volumes |

## Environment Variables

Key vars (see `app/config.py` for full list):
- `SNMP_HOST`, `SNMP_COMMUNITY` — Firewall SNMP target
- `DNS_SERVER` — DNS resolver
- `FIREWALL_IP`, `SYSLOG_PORT` — Syslog source
- `MMDB_CITY`, `MMDB_ASN` — MaxMind GeoIP database paths
- `TRENDS_DB_PATH`, `FIREWALL_DB_PATH` — SQLite paths
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` — Optional threat intel

## Ports

- 3434 → 8080: Web dashboard
- 2055/udp: NetFlow (nfcapd)
- 514/udp: Syslog receiver
