# PHOBOS-NET — Quick Start Guide

These instructions are intended for **home labs and personal networks**.
PHOBOS-NET is read-only and safe by design.

---

## Requirements

- Docker host (NAS, mini-PC, VM, or server)
- OPNsense firewall
- Docker and Docker Compose installed

---

## 1. Running PHOBOS-NET

Create `docker-compose.yml`:

```yaml
services:
  phobos-net:
    image: legato3/phobos-net:latest
    container_name: phobos-net
    restart: unless-stopped
    ports:
      - "3434:8080"       # Web dashboard - access at http://localhost:3434
      - "514:5514/udp"    # Syslog filterlog (OPNsense block/pass events)
      - "515:5515/udp"    # Syslog application logs
      - "2055:2055/udp"   # NetFlow collection (nfcapd)
    environment:
      # REQUIRED: Set your local timezone
      - TZ=Europe/Amsterdam

      # OPTIONAL: Threat intelligence API keys (leave commented if not needed)
      # - VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
      # - ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

    volumes:
      # Data persistence - these directories will be created automatically
      - ./docker-data:/app/data                    # Databases, watchlists, threat feeds
      - ./docker-data/nfdump:/var/cache/nfdump    # NetFlow data files

    # Log rotation to prevent disk fill-up
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

    # Resource limits (adjust based on your network size)
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1024M  # Use 1536M-2048M for networks with >100 active devices

    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
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
