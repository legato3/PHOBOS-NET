# 🛡️ PHOBOS-NET

**PHOBOS-NET** is a self-hosted, read-only **network observability dashboard** that combines **NetFlow**, **Syslog (OPNsense)**, and **SNMP** into a calm, truthful, and explainable UI.

It is designed for **situational awareness**, not automation.

> No blocking.  
> No enforcement.  
> No alarmist dashboards.  
> Just clear visibility into what your network is doing.

---

## ✨ Key Features

- 📊 **NetFlow analysis** (via `nfdump`)
  - Active flows, protocols, destinations
  - Time-range aware (48h default)
- 🧱 **Firewall visibility (OPNsense)**
  - Filterlog parsing (pass / block / reject)
  - Normalized, read-only firewall events
- 📡 **SNMP monitoring**
  - CPU, memory, interfaces
  - Interface throughput and saturation hints
- 📜 **Syslog ingestion**
  - Passive ingestion only
  - Explicit availability & error reporting
- 🧠 **Truth-first health model**
  - System health ≠ threat volume
  - Attacks do **not** degrade health if monitoring works
- 🧭 **Calm UI**
  - Clear separation of Health, Alerts, and Indicators

---

## 🧠 Design Philosophy

- Observational, not reactive
- Truth over completeness
- Explicit unknowns (`—` instead of guessing)
- Alerts are rare and explainable
- Signals ≠ alerts

---

## 🚀 Quick Start (Docker)

```bash
docker pull legato3/phobos-net:latest
```

### docker-compose.yml

```yaml
version: "3.9"

services:
  phobos-net:
    image: legato3/phobos-net:latest
    container_name: phobos-net
    restart: unless-stopped

    ports:
      - "3434:8080"
      - "514:5514/udp"
      - "515:5515/udp"
      - "2055:2055/udp"

    volumes:
      - ./docker-data:/app/data

    environment:
      WEB_PORT: 8080
      NFCAPD_DIR: /app/data/netflow
      THREAT_FEEDS_PATH: /opt/phobos/config/threat-feeds.txt

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/server/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

Start with:

```bash
docker compose up -d
```

Access the UI at:

```
http://<host>:3434
```

---

## 🔐 Security Model

- Runs as non-root (UID 1000)
- No privileged container
- No packet capture
- No active scanning unless explicitly enabled

---

## 🧩 Data Sources

| Source   | Purpose |
|--------|---------|
| NetFlow | Traffic observation |
| Syslog  | Firewall & system events |
| SNMP    | Device & interface metrics |

---

## ⚠️ What PHOBOS-NET is NOT

- Not an IDS / IPS
- Not a SIEM replacement
- Not an automation platform
- Not a blocking firewall

---

## 🏷️ Versioning

- `1.0.0` — exact release
- `1.0` — compatible
- `latest` — newest stable

---

PHOBOS-NET is built to be **quiet, honest, and boring in the best way**.
