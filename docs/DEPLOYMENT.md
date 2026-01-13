# Deployment Instructions for PROX_NFDUMP Dashboard

## Quick Deployment (Recommended Method)

Use the automated deployment script for the easiest and most reliable deployment process.

### Using the Deployment Script

From your local repository directory:

```bash
./scripts/deploy.sh
```

This script will:
1. Push your changes to GitHub
2. Sync files to `/repo` on the server using tar
3. Copy files from `/repo` to the production directory (`/root`)
4. Show a summary of deployed files

**Note**: The script requires SSH access configured with key `~/.ssh/id_ed25519_192.168.0.70`.

---

## Manual Deployment (Alternative Method)

If you need to deploy manually or troubleshoot, follow these steps:

### Step 1: Push Changes to GitHub

```bash
git add .
git commit -m "Your commit message"
git push origin main
```

### Step 2: SSH to Proxmox Server

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.70 root@192.168.0.70
```

### Step 3: Sync Repository on Server

```bash
# Sync files to /repo using tar (from your local machine)
cd /path/to/PROX_NFDUMP
tar --exclude='.git' --exclude='.Jules' --exclude='*.pyc' --exclude='__pycache__' --exclude='.venv' -czf - . | \
ssh -i ~/.ssh/id_ed25519_192.168.0.70 root@192.168.0.70 "pct exec 122 -- bash -c 'cd /repo && tar -xzf -'"
```

### Step 4: Deploy to Production

```bash
# Copy files from /repo to production directory
pct exec 122 -- bash -c "cp -f /repo/netflow-dashboard.py /root/ && \
cp -rf /repo/static/* /root/static/ && \
cp -rf /repo/templates/* /root/templates/"
```

### Step 5: Restart Service

```bash
pct exec 122 -- systemctl restart netflow-dashboard
```

### Step 6: Verify

```bash
pct exec 122 -- systemctl status netflow-dashboard --no-pager -l
```

---

## Deployment Script Details

The `scripts/deploy.sh` script automates the deployment process:

**Configuration** (at the top of the script):
- `SSH_KEY`: Path to SSH key (`~/.ssh/id_ed25519_192.168.0.70`)
- `SSH_USER`: SSH username (`root`)
- `SSH_HOST`: Proxmox server IP (`192.168.0.70`)
- `LXC_ID`: Container ID (`122`)
- `REPO_PATH`: Repository path on server (`/repo`)
- `DEPLOY_PATH`: Production directory (`/root`)

**What it does**:
1. Pushes local changes to GitHub
2. Uses `tar` to sync files to `/repo` (avoids Git authentication issues)
3. Copies files from `/repo` to production directories
4. Displays a deployment summary

**File Exclusions** (to reduce transfer size):
- `.git` directory
- `.Jules` directory
- `*.pyc` files
- `__pycache__` directories
- `.venv` virtual environment

---

## Repository Setup on Server

The server maintains a Git repository at `/repo` that serves as a staging area for deployments.

**Initial Setup** (already completed):
```bash
# Repository is initialized at /repo
# Remote points to: https://github.com/legato3/PROX_NFDUMP.git
# Files are synced using tar to avoid GitHub authentication issues
```

**Repository Structure**:
- `/repo` - Git repository (staging area)
- `/root` - Production directory (actual deployment)
- Files are copied from `/repo` to `/root` during deployment

---

## Files Deployed

| File Type | Source | Destination |
|-----------|--------|-------------|
| Backend | `/repo/netflow-dashboard.py` | `/root/netflow-dashboard.py` |
| JavaScript | `/repo/static/app.js` | `/root/static/app.js` |
| JavaScript (min) | `/repo/static/app.min.js` | `/root/static/app.min.js` |
| JavaScript modules | `/repo/static/js/` | `/root/static/js/` |
| CSS | `/repo/static/style.css` | `/root/static/style.css` |
| CSS (min) | `/repo/static/style.min.css` | `/root/static/style.min.css` |
| HTML | `/repo/templates/index.html` | `/root/templates/index.html` |
| Config | `/repo/scripts/gunicorn_config.py` | `/root/gunicorn_config.py` |

---

## Troubleshooting

### Deployment Script Fails

**Check SSH connectivity**:
```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.70 root@192.168.0.70 "pct exec 122 -- echo 'Connection OK'"
```

**Check repository exists**:
```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.70 root@192.168.0.70 "pct exec 122 -- ls -la /repo"
```

**Manual file sync**:
```bash
# From local repository
tar --exclude='.git' -czf - . | \
ssh -i ~/.ssh/id_ed25519_192.168.0.70 root@192.168.0.70 \
"pct exec 122 -- bash -c 'cd /repo && tar -xzf -'"
```

### Service Fails After Deployment

**Check service status**:
```bash
pct exec 122 -- systemctl status netflow-dashboard --no-pager -l
```

**View recent logs**:
```bash
pct exec 122 -- journalctl -u netflow-dashboard -n 100 --no-pager
```

**View error logs only**:
```bash
pct exec 122 -- journalctl -u netflow-dashboard --no-pager | grep -i error
```

**Check Python syntax**:
```bash
pct exec 122 -- python3 -m py_compile /root/netflow-dashboard.py
```

**Test dashboard response**:
```bash
pct exec 122 -- curl -s http://localhost:8080/ | head -5
```

Or from your local machine:
```bash
curl -s http://192.168.0.74:8080/ | head -5
```

### Files Not Updating

**Verify files were copied**:
```bash
pct exec 122 -- ls -lh /root/netflow-dashboard.py /root/static/app.js /root/templates/index.html
```

**Check file modification times**:
```bash
pct exec 122 -- stat /root/netflow-dashboard.py /root/static/app.js
```

**Compare with repository**:
```bash
pct exec 122 -- diff /repo/netflow-dashboard.py /root/netflow-dashboard.py
```

---

## System Information

- **Proxmox Server**: 192.168.0.70
- **SSH User**: root
- **SSH Key**: ~/.ssh/id_ed25519_192.168.0.70
- **LXC Container**: 122 (PROX-NFDUMP)
- **Container IP**: 192.168.0.74
- **Dashboard URL**: http://192.168.0.74:8080
- **Service Name**: netflow-dashboard
- **Repository Path**: /repo (inside container)
- **Production Path**: /root (inside container)

---

## Deployment Checklist

- [ ] Commit and push changes to GitHub
- [ ] Run deployment script: `./scripts/deploy.sh`
- [ ] Verify deployment script completed successfully
- [ ] Check service status: `systemctl status netflow-dashboard`
- [ ] Test dashboard in browser: http://192.168.0.74:8080
- [ ] Check for errors in logs if issues occur

---

## Notes

- **Cache Busting**: The deployment script does not automatically increment CSS/JS version numbers. If you experience caching issues, manually update version numbers in `templates/index.html`.
- **Service Restart**: The deployment script does not automatically restart the service. Restart manually if needed: `systemctl restart netflow-dashboard`
- **File Permissions**: Files are copied with existing permissions. Ensure production files have correct ownership.
- **Rollback**: To rollback, check out a previous commit in `/repo` and redeploy:
  ```bash
  pct exec 122 -- bash -c "cd /repo && git checkout <commit-hash> && cp -f netflow-dashboard.py /root/ && cp -rf static/* /root/static/ && cp -rf templates/* /root/templates/"
  ```

---

## Docker Deployment

For Docker-based deployment on PROX-DOCKER-2 (192.168.0.73), see **[DEPLOYMENT_DOCKER.md](DEPLOYMENT_DOCKER.md)**.

The Docker deployment uses:
- **Server**: PROX-DOCKER-2 (192.168.0.73)
- **Dashboard URL**: http://192.168.0.73:3434
- **Container**: netflow-dashboard-test
- **Port**: 3434 (mapped to container port 8080)
