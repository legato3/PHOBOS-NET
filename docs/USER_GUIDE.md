# PHOBOS-NET — Home User Quick Start

These instructions are intended for **home labs and personal networks**.
PHOBOS-NET is read-only and safe by design.

---

## Requirements

- Docker host (NAS, mini-PC, VM, or server)
- OPNsense firewall
- Docker and Docker Compose installed

---

## 1. Start PHOBOS-NET

```bash
mkdir phobos-net
cd phobos-net
mkdir docker-data
```

Create `docker-compose.yml`:

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
```

Start:

```bash
docker compose up -d
```

Open:

```
http://<docker-host-ip>:3434
```

---

## 2. Configure OPNsense (Required)

You must enable **all three data sources**:

### Syslog
- Filterlog → UDP 514
- Firewall/System → UDP 515

### NetFlow
- Export to UDP 2055

### SNMP (Required)
- Enable SNMP
- Allow access from Docker host
- Use read-only community

---

## 3. What to Expect

- Empty dashboard at first (normal)
- Health remains green if ingestion works
- Missing data shown as `—`
- No alerts unless something persistent occurs

---

## 4. Troubleshooting

```bash
curl http://localhost:3434/api/server/health
```

If JSON is returned, PHOBOS-NET is running correctly.
