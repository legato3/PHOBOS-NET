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
- No inference or deduplication

### Firewall Visibility (OPNsense)
- RFC-compliant `filterlog` parsing
- Normalized firewall decisions
- IPv4 and IPv6 support

### SNMP Monitoring
- CPU, memory, and interface metrics
- Uses authoritative counters
- Explicit availability states

---

## 🚀 Quick Start (Docker)

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

Access:
```
http://<host>:3434
```

---

## 🤝 Contributing

Contributions are welcome, with an emphasis on:
- correctness
- calm UX
- observability over automation

See `CONTRIBUTING.md` for details.

---

## 📄 License

MIT License
