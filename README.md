# PHOBOS-NET

<p align="center">
  <img src="https://raw.githubusercontent.com/legato3/PHOBOS-NET/main/docs/Dashboard.png" width="100%" />
</p>

<p align="center">
  <a href="https://hub.docker.com/r/legato3/phobos-net">
    <img src="https://img.shields.io/docker/pulls/legato3/phobos-net?style=flat-square" alt="Docker Pulls"/>
  </a>
  <a href="https://hub.docker.com/r/legato3/phobos-net">
    <img src="https://img.shields.io/docker/v/legato3/phobos-net?style=flat-square" alt="Docker Version"/>
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"/>
  </a>
</p>

PHOBOS-NET is a **self-hosted, read-only network observability platform** designed for operators who value **truth, clarity, and calm UX** over automation and alert noise.

It combines **NetFlow**, **OPNsense firewall logs**, and **SNMP** into a single, explainable view of network behavior.

> No blocking.  
> No enforcement.  
> No guessing.  
> Just accurate visibility.

---

## Why PHOBOS-NET

PHOBOS-NET is intentionally conservative by design:

- **Observational, not reactive**
- **Truth over completeness**
- **Signals ≠ alerts**
- **Health reflects operability, not attacks**

If data is unavailable, PHOBOS-NET shows **UNKNOWN / —** instead of inferring values.

---

## Core Capabilities

### NetFlow Observation
- Flow-level visibility via `nfdump`
- Time-range aware queries (48h default)
- No flow deduplication or inference

### Firewall Visibility (OPNsense)
- RFC-compliant `filterlog` parsing
- Normalized `pass / block / reject` events
- IPv4 and IPv6 support
- Separate syslog streams supported (UDP 514 / 515)

### SNMP Monitoring (Required)
- CPU, memory, and interface metrics
- Authoritative counters (`ifTable` / `ifXTable`)
- Explicit availability tracking

### Health, Alerts & Indicators
- **System Health** reflects monitoring operability only
- Alerts require strict escalation and persistence
- Indicators provide context without triggering alarms

---

## Quick Start (Docker Compose)
Dockerhub: https://hub.docker.com/r/legato3/phobos-net

The fastest way to deploy PHOBOS-NET is using Docker Compose.

1. **Create `docker-compose.yml`**:
```yaml
services:
  phobos-net:
    image: legato3/phobos-net:latest
    container_name: phobos-net
    restart: unless-stopped
    cap_add:
      - NET_RAW
    ports:
      - "3434:8080"      # Web UI
      - "514:5514/udp"   # Firewall Logs (OPNsense)
      - "515:5515/udp"   # App/Syslog
      - "2055:2055/udp"  # NetFlow (nfcapd)
    volumes:
      - ./docker-data:/app/data
      - ./docker-data/nfdump:/var/cache/nfdump
    environment:
      - TZ=UTC # Set to your timezone
```

2. **Launch**:
```bash
docker compose up -d
```

### First-Run Validation
PHOBOS-NET is observational; it needs data to show anything. Verify your setup in 3 steps:
1. **Open UI**: Access `http://localhost:3434`. You should see the login-less dashboard.
2. **Confirm Syslog**: Go to the **Firewall** tab. If OPNsense is configured, you should see logs appearing within 60 seconds.
3. **Confirm NetFlow**: Go to the **Network** tab. Data appears in 5-minute increments as `nfdump` rotates files.

---

## OPNsense Configuration
SNMP, Syslog, and NetFlow must be configured on your gateway. 
See: [`docs/OPNSENSE_CONFIG.md`](docs/OPNSENSE_CONFIG.md)

---

## Security Model

- Runs as non-root
- No packet capture
- No active response
- No automation
- Read-only by design

---

## Contributing

PHOBOS-NET welcomes contributors who value correctness and calm UX.

Please read:
- `CONTRIBUTING.md`
- `SECURITY.md`
- `AGENTS.md`

---

## License

MIT License
