# Deployment Instructions for PROX_NFDUMP Dashboard

## Quick Deployment (When You Push New Code to GitHub)

Deployment is done over SSH to the Proxmox server, then executing commands in the LXC container.

### Step 1: SSH to Proxmox Server

```bash
ssh user@192.168.0.70
```

### Step 2: Deploy to Container 122

Once connected to the Proxmox server, run these commands to deploy to the LXC container:

```bash
# 1. Pull latest code from GitHub into container
pct exec 122 -- bash -c "cd /tmp/repo && git pull"

# 2. Copy files to production location
pct exec 122 -- bash -c "cp /tmp/repo/netflow-dashboard.py /root/ && \
cp /tmp/repo/static/*.js /root/static/ && \
cp /tmp/repo/static/*.css /root/static/ && \
cp -r /tmp/repo/static/js /root/static/ 2>/dev/null || true && \
cp /tmp/repo/templates/*.html /root/templates/"

# 3. Update CSS cache version (increment the number)
pct exec 122 -- sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html

# 4. Restart the service
pct exec 122 -- systemctl restart netflow-dashboard

# 5. Verify it's running
pct exec 122 -- systemctl status netflow-dashboard --no-pager -l
```

---

## Step-by-Step Explanation

### Step 1: SSH to Proxmox Server
```bash
ssh user@192.168.0.70
```
- Connect to the Proxmox host server
- Replace `user` with your SSH username

### Step 2: Pull Latest Code
```bash
pct exec 122 -- bash -c "cd /tmp/repo && git pull"
```
- Fetches your latest code from GitHub
- Updates the `/tmp/repo` directory inside container 122

### Step 3: Copy Files to Production
```bash
pct exec 122 -- bash -c "cp /tmp/repo/netflow-dashboard.py /root/ && \
cp /tmp/repo/static/*.js /root/static/ && \
cp /tmp/repo/static/*.css /root/static/ && \
cp -r /tmp/repo/static/js /root/static/ 2>/dev/null || true && \
cp /tmp/repo/templates/*.html /root/templates/"
```
- Copies updated Python backend to `/root/`
- Copies updated JavaScript files to `/root/static/`
- Copies updated CSS files to `/root/static/`
- Copies JavaScript modules from `/static/js/` directory
- Copies updated HTML templates to `/root/templates/`

### Step 4: Update CSS Version (Cache Busting)
```bash
pct exec 122 -- sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html
```
- Forces browsers to reload CSS by incrementing version
- Change `2.7.0` to current version and `2.8.0` to next version
- This prevents browser caching issues

### Step 5: Restart Service
```bash
pct exec 122 -- systemctl restart netflow-dashboard
```
- Stops and starts the Python Flask application
- Loads new code into memory

### Step 6: Verify
```bash
pct exec 122 -- systemctl status netflow-dashboard --no-pager -l
```
- Should show "active (running)" in green
- Check for any errors in the output

---

## Alternative: Deploy from Inside Container

You can also SSH directly into the container (if SSH is enabled) or enter it interactively:

```bash
# 1. SSH to Proxmox server
ssh user@192.168.0.70

# 2. Enter the container
pct exec 122 -- bash

# 3. Pull latest code
cd /tmp/repo && git pull

# 4. Copy files
cp netflow-dashboard.py /root/
cp static/*.js static/*.css /root/static/
cp -r static/js /root/static/ 2>/dev/null || true
cp templates/*.html /root/templates/

# 5. Update CSS version
sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html

# 6. Restart service
systemctl restart netflow-dashboard

# 7. Check status
systemctl status netflow-dashboard --no-pager -l

# 8. View logs if needed
journalctl -u netflow-dashboard -n 50 --no-pager

# 9. Exit container
exit
```

---

## Quick One-Liner (All Steps Combined)

After SSH'ing to the Proxmox server:

```bash
pct exec 122 -- bash -c "cd /tmp/repo && git pull && \
cp netflow-dashboard.py /root/ && \
cp static/*.js static/*.css /root/static/ && \
cp -r static/js /root/static/ 2>/dev/null || true && \
cp templates/*.html /root/templates/ && \
sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html && \
systemctl restart netflow-dashboard && \
sleep 2 && \
systemctl status netflow-dashboard --no-pager -l"
```

---

## Files to Deploy (Reference)

| File | Source | Destination |
|------|--------|-------------|
| Backend | `/tmp/repo/netflow-dashboard.py` | `/root/netflow-dashboard.py` |
| JavaScript | `/tmp/repo/static/app.js` | `/root/static/app.js` |
| JavaScript (min) | `/tmp/repo/static/app.min.js` | `/root/static/app.min.js` |
| JavaScript modules | `/tmp/repo/static/js/` | `/root/static/js/` |
| CSS | `/tmp/repo/static/style.css` | `/root/static/style.css` |
| CSS (min) | `/tmp/repo/static/style.min.css` | `/root/static/style.min.css` |
| HTML | `/tmp/repo/templates/index.html` | `/root/templates/index.html` |

---

## Troubleshooting

### Check if Service Failed
```bash
pct exec 122 -- systemctl status netflow-dashboard --no-pager -l
```

### View Recent Logs
```bash
pct exec 122 -- journalctl -u netflow-dashboard -n 100 --no-pager
```

### View Error Logs Only
```bash
pct exec 122 -- journalctl -u netflow-dashboard --no-pager | grep -i error
```

### Test Dashboard is Responding
```bash
pct exec 122 -- curl -s http://localhost:8080/ | head -5
```

Or from your local machine:
```bash
curl -s http://192.168.0.74:8080/ | head -5
```

### Check Python Syntax
```bash
pct exec 122 -- python3 -m py_compile /root/netflow-dashboard.py
```

---

## Current Version Tracking

When incrementing CSS version, check current version first:
```bash
pct exec 122 -- grep "style.css?v=" /root/templates/index.html
```

Update pattern:
- Current: `v=2.7.0` → Next: `v=2.8.0`
- Current: `v=2.8.0` → Next: `v=2.9.0`
- Current: `v=2.9.0` → Next: `v=3.0.0`

---

## System Information

- **Proxmox Server**: 192.168.0.70
- **LXC Container**: 122 (PROX-NFDUMP)
- **Container IP**: 192.168.0.74
- **Dashboard URL**: http://192.168.0.74:8080
- **Service Name**: netflow-dashboard
- **Repository**: /tmp/repo (inside container)
- **Production**: /root/ (inside container)

---

## Summary Checklist

- [ ] SSH to Proxmox server: `ssh user@192.168.0.70`
- [ ] Pull code: `pct exec 122 -- bash -c "cd /tmp/repo && git pull"`
- [ ] Copy Python backend
- [ ] Copy static files (JS/CSS)
- [ ] Copy HTML templates
- [ ] Increment CSS version
- [ ] Restart service
- [ ] Verify service is running
- [ ] Test dashboard in browser (http://192.168.0.74:8080)
