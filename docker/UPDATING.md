# Updating PHOBOS-NET Docker Container

This guide explains how to update the Docker container when you have code changes.

## Quick Reference

### Fast Update Method (Recommended - No Rebuild Needed)

For code, templates, or static file changes, use `docker cp` to inject files directly into the running container. This is **much faster** than rebuilding (2-3 seconds vs 15-20 seconds).

```bash
# 1. Commit and push changes
cd /path/to/PROX_NFDUMP
git add -A
git commit -m "Your commit message"
git push origin main

# 2. Copy files to server temp directory
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/tmp/
# For templates/static files:
# scp -i ~/.ssh/id_ed25519_192.168.0.73 templates/index.html root@192.168.0.73:/tmp/
# scp -i ~/.ssh/id_ed25519_192.168.0.73 static/js/store.js root@192.168.0.73:/tmp/

# 3. Inject files directly into container and restart
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "docker cp /tmp/netflow-dashboard.py phobos-net:/app/netflow-dashboard.py && docker exec phobos-net chown root:root /app/netflow-dashboard.py && cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

**Time**: ~5 seconds total (vs 15-20 seconds for rebuild)

### Alternative: Copy to Host Then Restart

If you prefer copying to the host filesystem first:

```bash
# 1. Copy updated file to server
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/

# 2. Restart container
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

**Note**: This method works for `netflow-dashboard.py` because it's loaded at runtime. For templates/static files that are copied into the image during build, use the `docker cp` method above.

## Detailed Steps

### Step 1: Commit Your Changes

First, commit and push your changes to Git:

```bash
cd /path/to/PROX_NFDUMP
git add -A
git commit -m "Description of your changes"
git push origin main
```

### Step 2: Deploy Updated Files

You have two options:

#### Option A: Fast Method - Direct Container Injection (Recommended)

Use `docker cp` to inject files directly into the running container. This is fastest and works for all file types:

```bash
# Copy files to server temp directory
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/tmp/

# For templates/static files:
scp -i ~/.ssh/id_ed25519_192.168.0.73 templates/index.html root@192.168.0.73:/tmp/
scp -i ~/.ssh/id_ed25519_192.168.0.73 static/js/store.js root@192.168.0.73:/tmp/
scp -i ~/.ssh/id_ed25519_192.168.0.73 static/style.css root@192.168.0.73:/tmp/

# Inject into container, set permissions, and restart
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "
  docker cp /tmp/netflow-dashboard.py phobos-net:/app/netflow-dashboard.py && \
  docker cp /tmp/index.html phobos-net:/app/templates/index.html && \
  docker cp /tmp/store.js phobos-net:/app/static/js/store.js && \
  docker cp /tmp/style.css phobos-net:/app/static/style.css && \
  docker exec phobos-net chown root:root /app/netflow-dashboard.py /app/templates/index.html /app/static/js/store.js /app/static/style.css && \
  cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart
"
```

**Advantages**: 
- ✅ Works for all file types (Python, templates, static files)
- ✅ No rebuild needed
- ✅ Very fast (~5 seconds)
- ✅ Files are immediately available in container

#### Option B: Copy to Host Filesystem

For `netflow-dashboard.py` only (since it's loaded at runtime):

```bash
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/
```

**Note**: Templates and static files copied into the image during build won't be updated this way. Use Option A for those.

### Step 3: Restart the Container

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

The container will reload the updated files without rebuilding the image.

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

### Fastest Method (Direct Container Injection)

For code, templates, or static files - injects directly into container:

```bash
cd /path/to/PROX_NFDUMP && \
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/tmp/ && \
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "docker cp /tmp/netflow-dashboard.py phobos-net:/app/netflow-dashboard.py && docker exec phobos-net chown root:root /app/netflow-dashboard.py && cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

### Alternative (Host Filesystem Method)

For Python code only:

```bash
cd /path/to/PROX_NFDUMP && \
scp -i ~/.ssh/id_ed25519_192.168.0.73 netflow-dashboard.py root@192.168.0.73:/root/netflow-dashboard/ && \
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "cd /root/netflow-dashboard && docker compose -f docker/docker-compose.yml restart"
```

## Summary

- **Fast updates**: Use `docker cp` to inject files → Restart container (~5 seconds)
- **Python code only**: Copy to host → Restart container (~10 seconds)
- **Docker changes**: Copy files → Rebuild container (15-20 seconds)
- **Data always persists**: No data loss on updates
- **Always verify**: Check logs and health endpoint after update

## File Update Methods Comparison

| Method | Speed | Works For | When to Use |
|--------|-------|-----------|-------------|
| `docker cp` | ~5 sec | All files | **Recommended** - Fastest, works for everything |
| Copy to host + restart | ~10 sec | Python code only | Alternative for Python files |
| Full rebuild | 15-20 sec | Dockerfile/deps | Only when Dockerfile or requirements.txt changes |
