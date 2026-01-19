# PHOBOS-NET

Calm, read-only **network observability** for NetFlow, Syslog (OPNsense), and SNMP.

PHOBOS-NET shows what your network is doing — without automation, blocking, or alarmist dashboards.

---

## Features

- NetFlow traffic visibility (nfdump)
- OPNsense firewall filterlog parsing
- SNMP system & interface metrics
- Truth-first health model (signals ≠ alerts)
- Calm, NOC-friendly UI

---

## Quick Start

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
      - "2055:2055/udp"
    volumes:
      - ./docker-data:/app/data
```

Open: `http://localhost:3434`

---

## Philosophy

- Observational, not reactive
- Explicit unknowns (`—`, not guesses)
- Alerts are rare and explainable

PHOBOS-NET is designed to stay quiet when everything is fine.
