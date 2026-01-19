# PHOBOS-NET Docker Deployment

## Quick Start for Home Users

### 1. Prerequisites
- Docker and Docker Compose installed
- A firewall/router with NetFlow and SNMP enabled (e.g., OPNsense, pfSense)
- Basic network information (firewall IP, SNMP community string)

### 2. Configuration

**Option A: Use the example template** (recommended for most users)
```bash
# Copy the example template
cp docker-compose.example.yml docker-compose.yml

# Edit the file and update these values:
# - TZ: Your timezone (e.g., America/New_York, Asia/Tokyo)
# - SNMP_HOST: Your firewall IP address
# - DNS_SERVER: Your DNS server IP
# - FIREWALL_IP: Your firewall IP (for syslog filtering)
```

**Option B: Use the development version**
```bash
# The default docker-compose.yml includes build configuration
# Good for developers, but requires the full source code
```

### 3. Required Firewall Configuration

Configure your firewall to send data to the server running PHOBOS-NET:

**NetFlow (OPNsense example):**
- Navigate to: System → Settings → Reporting → NetFlow
- Target: `<server-ip>:2055`
- Version: NetFlow v5 or v9

**Syslog (OPNsense example):**
- Navigate to: System → Settings → Logging / Targets
- Add target: `<server-ip>:514` (UDP) - for firewall logs
- Add target: `<server-ip>:515` (UDP) - for application logs

**SNMP:**
- Navigate to: System → Settings → SNMP
- Enable SNMP, set community string (default: `public`)
- Note your community string for the docker-compose.yml

### 4. Launch

```bash
cd docker
docker compose up -d
```

Access the dashboard at: **http://localhost:3434**

### 5. Verify

```bash
# Check container status
docker compose ps

# View logs
docker compose logs -f

# Check health
curl http://localhost:3434/health
```

---

## File Differences

| File | Purpose | Best For |
|------|---------|----------|
| `docker-compose.yml` | Development version with build config | Developers building from source |
| `docker-compose.example.yml` | Production-ready, pull-only template | Home users, simple deployments |

---

## Troubleshooting

**No data showing:**
1. Verify NetFlow is configured on firewall
2. Check firewall can reach server on port 2055/udp
3. Run: `docker exec phobos-net ls -la /var/cache/nfdump` (should see files)

**SNMP not working:**
1. Verify SNMP is enabled on firewall
2. Test from host: `snmpwalk -v2c -c public <firewall-ip> system`
3. Check SNMP_HOST and SNMP_COMMUNITY in docker-compose.yml

**Wrong timezone:**
- Update `TZ` environment variable
- Restart: `docker compose restart`

---

## Resource Requirements

| Network Size | CPU | Memory | Disk |
|--------------|-----|--------|------|
| Small (<50 devices) | 0.5 CPU | 512MB | 5GB |
| Medium (50-100 devices) | 1.0 CPU | 1GB | 10GB |
| Large (100-500 devices) | 2.0 CPU | 2GB | 20GB |

Adjust `deploy.resources.limits` in docker-compose.yml accordingly.

---

## Updates

To update to the latest version:

```bash
docker compose pull
docker compose up -d
```

Your data persists in `./docker-data/` and will not be lost during updates.
