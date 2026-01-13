# Deploy to PROX-DOCKER-2 (192.168.0.73)

## Quick Deploy

1. **Copy files to server:**
   ```bash
   cd /Users/chris/Documents/GitHub/PROX_NFDUMP
   
   # Create directory on server
   ssh root@192.168.0.73 "mkdir -p /root/netflow-dashboard/docker"
   
   # Copy docker files
   scp docker/docker-compose.yml docker/Dockerfile docker/docker-entrypoint.sh root@192.168.0.73:/root/netflow-dashboard/docker/
   
   # Copy application files
   scp netflow-dashboard.py threat-feeds.txt requirements.txt root@192.168.0.73:/root/netflow-dashboard/
   ssh root@192.168.0.73 "mkdir -p /root/netflow-dashboard/{templates,static,scripts,sample_data}"
   scp -r templates/* root@192.168.0.73:/root/netflow-dashboard/templates/
   scp -r static/* root@192.168.0.73:/root/netflow-dashboard/static/
   scp scripts/gunicorn_config.py root@192.168.0.73:/root/netflow-dashboard/scripts/
   scp -r sample_data/* root@192.168.0.73:/root/netflow-dashboard/sample_data/ 2>/dev/null || true
   ```

2. **SSH to server and deploy:**
   ```bash
   ssh root@192.168.0.73
   cd /root/netflow-dashboard
   docker-compose -f docker/docker-compose.yml down 2>/dev/null || true
   docker-compose -f docker/docker-compose.yml build --no-cache
   docker-compose -f docker/docker-compose.yml up -d
   ```

3. **Verify:**
   ```bash
   docker ps | grep netflow-dashboard
   docker logs netflow-dashboard-test -f
   curl http://localhost:8080/api/server/health | grep -A 6 syslog
   ```

## Access

- **Dashboard**: http://192.168.0.73:8080
- **Syslog**: UDP port 514 (configure firewall to send to 192.168.0.73:514)
- **NetFlow**: UDP port 2055 (configure firewall to send NetFlow to 192.168.0.73:2055)

## Update Firewall Configuration

After deployment, update your OPNsense firewall syslog target:

1. Go to **System → Settings → Logging / Targets**
2. Edit the existing syslog target (or create new one)
3. Change **Hostname** from `192.168.0.148` to `192.168.0.73`
4. **Port**: `514`
5. **Transport**: `UDP`
6. Click **Save** and **Apply**

## Useful Commands

```bash
# View logs
docker logs netflow-dashboard-test -f

# Restart container
docker-compose -f /root/netflow-dashboard/docker/docker-compose.yml restart

# Check status
docker-compose -f /root/netflow-dashboard/docker/docker-compose.yml ps

# Check syslog stats
curl http://localhost:8080/api/server/health | python3 -m json.tool | grep -A 6 syslog

# Check firewall stats
curl http://localhost:8080/api/stats/firewall | python3 -m json.tool
```
