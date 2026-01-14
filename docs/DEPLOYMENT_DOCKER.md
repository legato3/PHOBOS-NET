# Docker Deployment Instructions

This document describes deploying the NetFlow Dashboard using Docker on PROX-DOCKER-2.

## System Information

- **Server**: PROX-DOCKER-2 (192.168.0.73)
- **SSH User**: root
- **SSH Key**: ~/.ssh/id_ed25519_192.168.0.73
- **Dashboard URL**: http://192.168.0.73:3434
- **Container Name**: phobos-net
- **Docker Compose Version**: v5.0.1+ (use `docker compose` command, not `docker compose`)

## Quick Deployment

### Enable World Map (GeoIP)

The "Traffic World Map" requires MaxMind GeoIP databases. Due to licensing, these cannot be bundled.

1. **Download Databases**:
   - Sign up for a free account at [MaxMind](https://www.maxmind.com).
   - Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.

2. **Place Files on Server**:
   - Put them in the `docker-data/` directory on the host (which is mounted to volume).
   - Ensure they are named exactly `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
   
   ```bash
   # Example copy to server
   scp GeoLite2-*.mmdb root@192.168.0.73:/root/netflow-dashboard/docker-data/
   ```

3. **Restart Container**:
   ```bash
   docker compose -f docker/docker compose.yml restart
   ```

### Initial Deployment

1. **Copy files to server:**
   ```bash
   cd /path/to/PROX_NFDUMP
   
   # Create directory structure on server
   ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 \
     "mkdir -p /root/netflow-dashboard/docker/{templates,static,scripts,sample_data}"
   
   # Copy Docker configuration files
   scp -i ~/.ssh/id_ed25519_192.168.0.73 \
     docker/docker compose.yml \
     docker/Dockerfile \
     docker/docker-entrypoint.sh \
     root@192.168.0.73:/root/netflow-dashboard/docker/
   
   # Copy application files
   scp -i ~/.ssh/id_ed25519_192.168.0.73 \
     netflow-dashboard.py \
     root@192.168.0.73:/root/netflow-dashboard/

   # Copy sample data requirements and threat feeds to root for build context
   scp -i ~/.ssh/id_ed25519_192.168.0.73 \
     sample_data/threat-feeds.txt \
     sample_data/requirements.txt \
     root@192.168.0.73:/root/netflow-dashboard/sample_data/
   
   # Copy templates, static files, scripts, and sample data
   scp -i ~/.ssh/id_ed25519_192.168.0.73 -r \
     templates/* \
     root@192.168.0.73:/root/netflow-dashboard/templates/
   
   scp -i ~/.ssh/id_ed25519_192.168.0.73 -r \
     static/* \
     root@192.168.0.73:/root/netflow-dashboard/static/
   
   scp -i ~/.ssh/id_ed25519_192.168.0.73 \
     scripts/gunicorn_config.py \
     root@192.168.0.73:/root/netflow-dashboard/scripts/
   
   scp -i ~/.ssh/id_ed25519_192.168.0.73 -r \
     sample_data \
     root@192.168.0.73:/root/netflow-dashboard/ 2>/dev/null || true
   ```

2. **Build and start container:**
   ```bash
   ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73
   cd /root/netflow-dashboard
   
   # Stop any existing container
   docker compose -f docker/docker compose.yml down 2>/dev/null || true
   
   # Build image
   docker compose -f docker/docker compose.yml build --no-cache
   
   # Start container
   docker compose -f docker/docker compose.yml up -d
   ```

3. **Verify deployment:**
   ```bash
   # Check container status
   docker ps | grep netflow-dashboard
   
   # View logs
   docker logs netflow-dashboard-test -f
   
   # Test health endpoint
   curl http://localhost:3434/api/server/health | python3 -m json.tool
   ```

## Updating Deployment

### Quick Update (Code Changes Only)

For updates to `netflow-dashboard.py` or other application files (no Dockerfile changes):

```bash
# From local machine
cd /path/to/PROX_NFDUMP

# Commit and push changes (if not already done)
git add -A
git commit -m "Your commit message"
git push origin main

# Copy updated application file
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/

# Restart container (picks up new code)
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "cd /root/netflow-dashboard && docker compose -f docker/docker compose.yml restart"
```

**Note**: A restart is sufficient for code-only changes. The container will reload the updated Python file.

### Full Rebuild (Dockerfile or Dependencies Changed)

For changes to Dockerfile, requirements.txt, or other build-time dependencies:

```bash
# From local machine
cd /path/to/PROX_NFDUMP

# Copy updated files (repeat relevant scp commands from initial deployment)
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/
scp -i ~/.ssh/id_ed25519_192.168.0.73 requirements.txt root@192.168.0.73:/root/netflow-dashboard/
# ... copy other updated files as needed

# SSH to server and rebuild
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73
cd /root/netflow-dashboard
docker compose -f docker/docker compose.yml down
docker compose -f docker/docker compose.yml build --no-cache
docker compose -f docker/docker compose.yml up -d
```

### What Requires Rebuild vs Restart?

**Restart Only (Fast)**:
- Changes to `netflow-dashboard.py`
- Changes to templates, static files (if mounted)
- Environment variable changes in docker compose.yml

**Full Rebuild Required**:
- Changes to `Dockerfile`
- Changes to `requirements.txt`
- Changes to `docker-entrypoint.sh`
- Changes to system dependencies

## Port Configuration

- **Dashboard**: Port 3434 (HTTP) - mapped to container port 8080
- **Syslog**: Port 514 (UDP) - receives firewall logs
- **NetFlow**: Port 2055 (UDP) - receives NetFlow data

The container runs the application on port 8080 internally. Port 3434 is used on the host to avoid conflicts with other services.

## Firewall Configuration

After deployment, configure your OPNsense firewall:

1. Go to **System → Settings → Logging / Targets**
2. Edit the syslog target (or create new one)
3. Set **Hostname**: `192.168.0.73`
4. Set **Port**: `514`
5. Set **Transport**: `UDP`
6. Click **Save** and **Apply**

## Service Management

### View Logs
```bash
# Follow logs
docker logs phobos-net -f

# Last 100 lines
docker logs phobos-net --tail 100
```

### Restart Container
```bash
docker compose -f /root/netflow-dashboard/docker/docker compose.yml restart
```

### Stop Container
```bash
docker compose -f /root/netflow-dashboard/docker/docker compose.yml down
```

### Start Container
```bash
docker compose -f /root/netflow-dashboard/docker/docker compose.yml up -d
```

### Check Status
```bash
docker compose -f /root/netflow-dashboard/docker/docker compose.yml ps
```

## Health Checks

### Check Container Health
```bash
docker ps | grep phobos-net
# Look for "healthy" or "starting" status
```

### Check API Health
```bash
curl http://192.168.0.73:3434/api/server/health | python3 -m json.tool
```

### Check Syslog Status
```bash
curl http://192.168.0.73:3434/api/server/health | python3 -m json.tool | grep -A 8 syslog
```

Expected output should show:
- `"received"`: Number of syslog messages received
- `"parsed"`: Number of messages successfully parsed
- `"active"`: true (receiver is running)

## Troubleshooting

### Container Won't Start

```bash
# Check logs for errors
docker logs phobos-net

# Check if port is in use
ss -tlnp | grep 3434
netstat -tlnp | grep 3434

# Check Docker Compose configuration
docker compose -f /root/netflow-dashboard/docker/docker compose.yml config
```

### Port Already in Use

If port 3434 is already in use:

```bash
# Find what's using the port
ss -tlnp | grep 3434

# Stop conflicting container/service
docker stop <container-name>
# or
systemctl stop <service-name>
```

### Syslog Not Receiving Data

1. **Verify container is running:**
   ```bash
   docker ps | grep netflow-dashboard
   ```

2. **Check syslog receiver status:**
   ```bash
   curl http://localhost:3434/api/server/health | python3 -m json.tool | grep -A 8 syslog
   ```

3. **Verify firewall configuration:**
   - Firewall should send to `192.168.0.73:514`
   - Protocol: UDP
   - Transport: UDP

4. **Test UDP connectivity:**
   ```bash
   # From firewall or another machine
   echo "test message" | nc -u 192.168.0.73 514
   ```

5. **Check container logs:**
   ```bash
   docker logs phobos-net | grep -i syslog
   ```

### Rebuild After Changes

```bash
cd /root/netflow-dashboard
docker compose -f docker/docker compose.yml down
docker compose -f docker/docker compose.yml build --no-cache
docker compose -f docker/docker compose.yml up -d
```

## Services Running in Container

The Docker container runs multiple services:

1. **nfcapd** - NetFlow collector (UDP port 2055)
   - Collects NetFlow data from network devices
   - Stores data in `/var/cache/nfdump` with LZ4 compression
   - 5-minute file rotation, auto-expire enabled

2. **Gunicorn** - Production WSGI server (container port 8080)
   - Serves the Flask dashboard application
   - 1 worker, 8 threads (gthread worker class)
   - Matches production configuration

3. **Syslog Receiver** - UDP port 514
   - Receives firewall syslog messages
   - Started automatically by the Flask application
   - Stores data in SQLite database

4. **SNMP Support** - python3-pysnmp4 installed
   - Available for SNMP polling (configured via environment variables)

## Data Persistence

Database files and NetFlow data are stored in mounted volumes:
- Location: `/root/netflow-dashboard/docker-data` (on host)
- Database files: `firewall.db`, `netflow-trends.sqlite`
- NetFlow data: `nfdump/` directory (contains nfcapd flow files)

Both databases and NetFlow data files persist across container restarts and updates.

To reset data:
```bash
# Stop container
docker compose -f /root/netflow-dashboard/docker/docker-compose.yml down

# Remove data directory (WARNING: This deletes all data)
rm -rf /root/netflow-dashboard/docker-data

# Restart container (will create new databases)
docker compose -f /root/netflow-dashboard/docker/docker-compose.yml up -d
```

## Environment Variables

Key environment variables (configured in `docker-compose.yml`):

- `FIREWALL_IP=0.0.0.0` - Accept syslog from any source (set to specific IP for production)
- `SYSLOG_BIND=0.0.0.0` - Bind syslog receiver to all interfaces
- `SYSLOG_PORT=514` - Syslog UDP port
- `FIREWALL_DB_PATH=/app/data/firewall.db` - Firewall database path
- `TRENDS_DB_PATH=/app/data/netflow-trends.sqlite` - Trends database path

See `docker/DOCKER.md` for complete list of environment variables.

## Additional Resources

- Detailed Docker usage: `docker/DOCKER.md`
- Docker quick reference: `docker/README.md`
- LXC/Systemd deployment: `docs/DEPLOYMENT.md`
