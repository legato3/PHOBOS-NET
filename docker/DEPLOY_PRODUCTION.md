# Deploy to PROX-DOCKER-2 (192.168.0.73)

## Quick Deploy

1. **Copy files to server:**
   ```bash
   cd /Users/chris/Documents/GitHub/PROX_NFDUMP
   
   # Create directory on server
   ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "mkdir -p /root/netflow-dashboard/docker/{templates,static,scripts,sample_data}"
   
   # Copy docker files
   scp -i ~/.ssh/id_ed25519_192.168.0.73 docker/docker-compose.yml docker/Dockerfile docker/docker-entrypoint.sh root@192.168.0.73:/root/netflow-dashboard/docker/
   
   # Copy application files
   scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py threat-feeds.txt requirements.txt root@192.168.0.73:/root/netflow-dashboard/
   scp -i ~/.ssh/id_ed25519_192.168.0.73 -r templates/* root@192.168.0.73:/root/netflow-dashboard/templates/
   scp -i ~/.ssh/id_ed25519_192.168.0.73 -r static/* root@192.168.0.73:/root/netflow-dashboard/static/
   scp -i ~/.ssh/id_ed25519_192.168.0.73 scripts/gunicorn_config.py root@192.168.0.73:/root/netflow-dashboard/scripts/
   scp -i ~/.ssh/id_ed25519_192.168.0.73 -r sample_data root@192.168.0.73:/root/netflow-dashboard/ 2>/dev/null || true
   ```

2. **SSH to server and deploy:**
   ```bash
   ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73
   cd /root/netflow-dashboard
   docker compose -f docker/docker-compose.yml down 2>/dev/null || true
   docker compose -f docker/docker-compose.yml build --no-cache
   docker compose -f docker/docker-compose.yml up -d
   ```

3. **Verify:**
   ```bash
   docker ps | grep netflow-dashboard
   docker logs netflow-dashboard-test -f
   curl http://localhost:3434/api/server/health | python3 -m json.tool | grep -A 6 syslog
   ```

## Access

- **Dashboard**: http://192.168.0.73:3434
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
curl http://localhost:3434/api/server/health | python3 -m json.tool | grep -A 6 syslog

# Check firewall stats
curl http://localhost:3434/api/stats/firewall | python3 -m json.tool
```
