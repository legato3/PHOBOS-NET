# 🛡️ PHOBOS-NET

PHOBOS-NET is a self-hosted, read-only **network observability platform** that combines **NetFlow**, **Syslog (OPNsense)**, and **SNMP** into a calm, truthful, and explainable interface.

It is designed for **situational awareness**, not automation.

> No blocking.  
> No enforcement.  
> No alarmist dashboards.  
> Just clear visibility into what your network is doing.

---

## ✨ Key Features

### NetFlow Observation
- Flow-level visibility via `nfdump`
- Time-range aware queries (48h default)
- No flow deduplication or inference
- Traffic is observed, never altered

### Firewall Visibility (OPNsense)
- RFC-compliant `filterlog` parsing
- Normalized firewall decisions (`pass`, `block`, `reject`)
- IPv4 and IPv6 support
- No risk scoring or automated response

### SNMP Monitoring
- CPU, memory, and interface metrics
- Interface throughput and saturation hints
- Uses authoritative counters (ifTable / ifXTable)
- Explicit availability states (never guessed)

### Health, Alerts & Indicators
- **System Health** reflects monitoring operability only
- Attacks do *not* degrade health if monitoring is working
- Alerts require strict escalation and persistence
- Indicators provide context without triggering alarms

### Calm, Truth-First UI
- Clear separation of Health, Alerts, and Indicators
- Explicit unknowns shown as “—”
- Red is reserved for actionable failures only
- Designed for NOC screens and long-running use

---

## 🧠 Design Philosophy

PHOBOS-NET is intentionally conservative by design.

### Observational, Not Reactive
The system never blocks traffic, modifies firewall rules, or takes automated action.  
It exists to *observe*, not to enforce.

### Truth Over Completeness
If data is unavailable, it is shown as **UNKNOWN / —**.  
PHOBOS-NET never infers, guesses, or fabricates metrics.

### Signals ≠ Alerts
- **Signals / Indicators** provide situational context
- **Alerts** are rare, explainable, and require persistence
- Noise reduction is a first-class goal

### Calm UX
- No dramatic state banners
- No glowing red dashboards
- Degraded states are yellow, not alarming
- Calm dashboards help operators think clearly

---

## 🚀 Quick Start (Docker)

### Pull the image
```bash
docker pull legato3/phobos-net:latest
```

### Example docker-compose.yml
```yaml
version: "3.9"

services:
  phobos-net:
    image: legato3/phobos-net:latest
    container_name: phobos-net
    restart: unless-stopped

    ports:
      - "3434:8080"     # Web UI
      - "514:5514/udp"  # Syslog (filterlog)
      - "515:5515/udp"  # Firewall syslog (optional)
      - "2055:2055/udp" # NetFlow

    volumes:
      - ./docker-data:/app/data

    environment:
      WEB_PORT: 8080
      NFCAPD_DIR: /app/data/netflow
      THREAT_FEEDS_PATH: /opt/phobos/config/threat-feeds.txt
```

Start PHOBOS-NET:
```bash
docker compose up -d
```

Access the UI:
```
http://<host>:3434
```

---

## 🔐 Security & Runtime Model

- Runs as **non-root user** (UID 1000)
- No privileged container
- No packet capture
- No automatic scanning unless explicitly enabled
- All persistence via mounted volume (`/app/data`)

---

## 🧩 Data Sources

| Source   | Role                         | Notes                                  |
|--------|------------------------------|----------------------------------------|
| NetFlow | Traffic observation          | Read-only, no inference                |
| Syslog  | Firewall & system events     | Parsed, normalized                     |
| SNMP    | Device & interface metrics   | Supporting signal only                 |

All sources are optional and independent.  
Unavailable sources are reported explicitly.

---

## ⚠️ What PHOBOS-NET Is NOT

PHOBOS-NET is deliberately **not**:

- ❌ An IDS / IPS
- ❌ A SIEM replacement
- ❌ An automation or remediation platform
- ❌ A blocking firewall
- ❌ A compliance reporting tool

These exclusions are intentional and documented.

---

## 🧪 Stability & Versioning

- Architecture semantics are **locked**
- Minor releases add visibility, never change meaning
- Patch releases fix bugs only
- Backward compatibility is prioritized

Current versioning:
- `1.0.0` — exact release
- `1.0` — compatible minor
- `latest` — newest stable

---

## 📄 Documentation

- Docker build & publish guide: `docs/DOCKER.md`
- Architecture & AI rules: `AGENTS.md`
- Skill / agent behavior guide: `SKILL.md`

---

## 🧠 Final Note

PHOBOS-NET is built to be **quiet, honest, and boring in the best way**.

If the dashboard is calm — that’s success.
