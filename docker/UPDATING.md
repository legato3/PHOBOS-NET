# Updating PHOBOS-NET Docker Container

This guide explains how to update the Docker container when you have code changes.

## Quick Reference

### For Code Changes Only (Most Common)

```bash
# 1. Commit and push changes
cd /path/to/PROX_NFDUMP
git add -A
git commit -m "Your commit message"
git push origin main

# 2. Copy updated file to server
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/

# 3. Restart container
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

That's it! The container will reload the updated Python file.

## Detailed Steps

### Step 1: Commit Your Changes

First, commit and push your changes to Git:

```bash
cd /path/to/PROX_NFDUMP
git add -A
git commit -m "Description of your changes"
git push origin main
```

### Step 2: Copy Updated Files to Server

For code-only changes, you typically only need to update `netflow-dashboard.py`:

```bash
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/
```

If you also changed templates or static files:

```bash
scp -i ~/.ssh/id_ed25519_192.168.0.73 -r templates/* root@192.168.0.73:/root/netflow-dashboard/templates/
scp -i ~/.ssh/id_ed25519_192.168.0.73 -r static/* root@192.168.0.73:/root/netflow-dashboard/static/
```

### Step 3: Restart the Container

For code-only changes, a simple restart is sufficient:

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

The container will reload the Python application without rebuilding the image.

### Step 4: Verify Deployment

Check that the container is running:

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "docker ps | grep phobos-net"
```

Check the logs:

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "docker logs phobos-net --tail 20"
```

Test the health endpoint:

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "curl -s http://localhost:3434/api/server/health | python3 -m json.tool | head -10"
```

## When to Rebuild vs Restart

### Restart Only (Recommended for Most Updates)

Use restart when you change:
- ✅ `netflow-dashboard.py` (application code)
- ✅ Templates (`templates/index.html`)
- ✅ Static files (`static/*.js`, `static/*.css`)
- ✅ Environment variables in `docker-compose.yml`
- ✅ Configuration files

**Why**: These files are either mounted as volumes or loaded at runtime. A restart reloads them.

### Full Rebuild Required

Use rebuild when you change:
- ❌ `Dockerfile` (image definition)
- ❌ `requirements.txt` (Python dependencies)
- ❌ `docker-entrypoint.sh` (startup script)
- ❌ System packages in Dockerfile
- ❌ `docker-compose.yml` volume or build configuration

**Why**: These require rebuilding the Docker image.

### Full Rebuild Process

```bash
# Copy updated files
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/
scp -i ~/.ssh/id_ed25519_192.168.0.73 requirements.txt root@192.168.0.73:/root/netflow-dashboard/
scp -i ~/.ssh/id_ed25519_192.168.0.73 docker/Dockerfile root@192.168.0.73:/root/netflow-dashboard/docker/
# ... copy other changed files

# SSH and rebuild
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73
cd /root/netflow-dashboard
docker compose -f docker/docker-compose.yml down
docker compose -f docker/docker-compose.yml build --no-cache
docker compose -f docker/docker-compose.yml up -d
```

## Data Persistence

**Important**: Your data is persistent! When you restart or rebuild:

- ✅ Databases (`firewall.db`, `netflow-trends.sqlite`) persist
- ✅ NetFlow data (`nfdump/` directory) persists
- ✅ All data in `docker-data/` persists

Data is stored on the host at `/root/netflow-dashboard/docker-data/` and mounted into the container.

## Troubleshooting

### Container Won't Start After Update

Check logs for errors:

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "docker logs phobos-net --tail 50"
```

Common issues:
- **Syntax errors in Python**: Check the logs for Python tracebacks
- **Missing dependencies**: If you added imports, you may need to rebuild
- **Permission issues**: Check file permissions on the server

### Changes Not Reflecting

1. **Verify file was copied**:
   ```bash
   ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "ls -lh /root/netflow-dashboard/netflow-dashboard.py"
   ```

2. **Check file modification time** matches your local file

3. **Verify container restarted**:
   ```bash
   ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "docker ps | grep phobos-net"
   ```
   Check the "Up" time to confirm it restarted recently

4. **Clear browser cache** if changes are in frontend (CSS/JS)

### Rollback to Previous Version

If you need to rollback:

```bash
# SSH to server
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73

# Restore from Git (if you have git on server)
cd /root/netflow-dashboard
git checkout <previous-commit-hash> netflow-dashboard.py

# Or copy previous version from backup
# cp /root/netflow-dashboard/netflow-dashboard.py.backup /root/netflow-dashboard/netflow-dashboard.py

# Restart container
docker compose -f docker/docker-compose.yml restart
```

## One-Liner Quick Update

For the fastest update (code changes only):

```bash
cd /path/to/PROX_NFDUMP && \
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/ && \
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

## Summary

- **Most updates**: Copy file → Restart container (30 seconds)
- **Docker changes**: Copy files → Rebuild container (2-5 minutes)
- **Data always persists**: No data loss on updates
- **Always verify**: Check logs and health endpoint after update
