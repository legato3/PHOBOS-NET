# 🛡️ PHOBOS-NET

<p align="center">
  <img src="https://raw.githubusercontent.com/legato3/phobos-net-assets/main/images/dashboard-overview.png" width="100%" />
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

## Quick Start (Docker)

```bash
docker pull legato3/phobos-net:latest
```

```yaml
services:
  phobos-net:
    image: legato3/phobos-net:latest
    ports:
      - "3434:8080"
      - "514:5514/udp"
      - "515:5515/udp"
      - "2055:2055/udp"
    volumes:
      - ./docker-data:/app/data
```

Access the UI:
```
http://<host>:3434
```

---

## OPNsense Configuration

SNMP and Syslog are **not optional**.

See:
- [`docs/OPNSENSE_QUICK_START.md`](docs/OPNSENSE_QUICK_START.md)
- [`docs/OPNSENSE.md`](docs/OPNSENSE.md)

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
