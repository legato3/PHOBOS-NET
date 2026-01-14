# Deploy to PROX-DOCKER-2 (192.168.0.73)

> **Note**: The legacy `netflow-dashboard.py` entrypoint has been removed. Prefer `docker/DEPLOY_TO_SERVER.sh` to deploy the modular `app/` and `frontend/` structure.

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
   docker ps | grep phobos-net
   docker logs phobos-net -f
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

## Updating Deployment

When you have code changes to deploy, use the **fast update method**:

### Fast Update (Recommended - No Rebuild)

Use `docker cp` to inject files directly into the running container. This works for all file types and is much faster than rebuilding:

```bash
# From your local machine
cd /path/to/PROX_NFDUMP

# Commit and push changes (if not already done)
git add -A
git commit -m "Your commit message"
git push origin main

# Copy files to server temp directory
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/tmp/
# For templates/static files:
# scp -i ~/.ssh/id_ed25519_192.168.0.73 templates/index.html root@192.168.0.73:/tmp/
# scp -i ~/.ssh/id_ed25519_192.168.0.73 static/js/store.js root@192.168.0.73:/tmp/

# Inject into container and restart (takes ~5 seconds)
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "
  docker cp /tmp/netflow-dashboard.py phobos-net:/app/netflow-dashboard.py && \
  docker exec phobos-net chown root:root /app/netflow-dashboard.py && \
  cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart
"
```

**Time**: ~5 seconds (vs 15-20 seconds for rebuild)

**Note**: Only rebuild if you changed the Dockerfile, requirements.txt, or other build-time dependencies.

See **[UPDATING.md](UPDATING.md)** for detailed update procedures and all available methods.

## Useful Commands

```bash
# View logs
docker logs phobos-net -f

# Restart container
docker compose -f /root/netflow-dashboard/docker/docker-compose.yml restart

# Check status
docker compose -f /root/netflow-dashboard/docker/docker-compose.yml ps

# Check syslog stats
curl http://localhost:3434/api/server/health | python3 -m json.tool | grep -A 6 syslog

# Check firewall stats
curl http://localhost:3434/api/stats/firewall | python3 -m json.tool
```
<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>
run_terminal_cmd
