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

## Deployment

```bash
# Deploy to production server (from docker/ folder)
./DEPLOY_TO_SERVER.sh          # Fast mode: docker cp + restart
./DEPLOY_TO_SERVER.sh --rebuild # Full rebuild (for Dockerfile changes)
```

Server: 192.168.0.73, SSH key: `~/.ssh/id_ed25519_192.168.0.73`

## Threading & Concurrency Patterns

### Global State Locks
All shared state in `app_state.py` uses dedicated locks:
- `_snmp_cache_lock` — SNMP data
- `_alert_history_lock` — Alert deque (threats.py)
- `_anomaly_tracker_lock` — Anomaly tracking (threats.py)
- `_feed_data_lock` — Threat feed data (threats.py)
- `_common_data_lock` — Cached nfdump results (netflow.py)

### Cache TTL Patterns
- **Time-window caching**: `cache_key = f"{type}:{range}:{int(now // 60)}"` expires every minute
- **Explicit TTL**: `if (now - cached["ts"]) < cache_ttl: return cached["data"]`
- **Bounded caches**: Most caches have max size limits (e.g., `COMMON_DATA_CACHE_MAX`)

### Common Bug Patterns to Avoid

1. **Async updates before reads**: Don't spawn background thread for DB update then immediately read
   ```python
   # BAD: Race condition
   threading.Thread(target=update_db, args=(data,)).start()
   result = read_from_db()  # May get stale data

   # GOOD: Synchronous update
   update_db(data)
   result = read_from_db()
   ```

2. **Global dict replacement under lock**: Replace dict contents in-place, don't reassign
   ```python
   # BAD: Other threads may cache old reference
   with lock:
       _global_dict = new_dict

   # GOOD: Update in-place
   with lock:
       _global_dict.clear()
       _global_dict.update(new_dict)
   ```

3. **Deque iteration**: Convert to list before iterating to avoid concurrent modification
   ```python
   # BAD: Can fail if deque modified
   for item in _deque:
       process(item)

   # GOOD: Snapshot first
   with lock:
       snapshot = list(_deque)
   for item in snapshot:
       process(item)
   ```

4. **Bare except clauses**: Always specify exception types
   ```python
   # BAD: Catches KeyboardInterrupt, SystemExit
   except:
       pass

   # GOOD: Specific exceptions
   except (ValueError, IndexError, KeyError):
       pass
   ```

## Host Memory & Baseline System

The "NEW hosts" feature relies on persisted first-seen timestamps:

1. **Storage**: `host_memory` table in `netflow-trends.sqlite`
2. **Updates**: `update_host_memory()` in `sqlite.py` — preserves earliest timestamp
3. **Baseline logic**: If oldest `first_seen` < 23h ago → "Baseline warming"
4. **Cache dependency**: `get_merged_host_stats()` must update DB synchronously before reading

## nfdump Integration

- **Wrapper**: `run_nfdump()` in `netflow.py` — handles subprocess, timeouts, metrics
- **CSV parsing**: `parse_csv()` — expects header row, returns list of dicts
- **Common queries**: `get_common_nfdump_data()` — cached sources/ports/dests/protos
- **Time ranges**: `get_time_range()` in helpers.py — returns `-t` flag value

## Known Technical Debt

1. **~50 bare except clauses** in routes/traffic.py and routes/security.py — should specify exception types
2. **Large route files** — security.py (3500+ lines), traffic.py (2500+ lines) could be split
3. **No test suite** — manual testing only
4. **Hardcoded fallback indices** — CSV parsing falls back to magic column numbers if header parsing fails
