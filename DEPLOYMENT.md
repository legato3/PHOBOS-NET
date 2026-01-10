# Deployment Instructions for PROX_NFDUMP Dashboard

## Quick Deployment (When You Push New Code to GitHub)

### From Proxmox Host (192.168.0.80)

```bash
# 1. Pull latest code from GitHub into container
pct exec 122 -- bash -c "cd /tmp/repo && git pull"

# 2. Copy files to production location
pct exec 122 -- bash -c "cp /tmp/repo/netflow-dashboard.py /root/ && \
cp /tmp/repo/static/*.js /root/static/ && \
cp /tmp/repo/static/*.css /root/static/ && \
cp /tmp/repo/templates/*.html /root/templates/"

# 3. Update CSS cache version (increment the number)
pct exec 122 -- sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html

# 4. Restart the service
pct exec 122 -- systemctl restart netflow-dashboard

# 5. Verify it's running
pct exec 122 -- systemctl status netflow-dashboard
```

---

## Step-by-Step Explanation

### Step 1: Pull Latest Code
```bash
pct exec 122 -- bash -c "cd /tmp/repo && git pull"
```
- Fetches your latest code from GitHub
- Updates the `/tmp/repo` directory inside container 122

### Step 2: Copy Files to Production
```bash
pct exec 122 -- bash -c "cp /tmp/repo/netflow-dashboard.py /root/ && \
cp /tmp/repo/static/*.js /root/static/ && \
cp /tmp/repo/static/*.css /root/static/ && \
cp /tmp/repo/templates/*.html /root/templates/"
```
- Copies updated Python backend to `/root/`
- Copies updated JavaScript files to `/root/static/`
- Copies updated CSS files to `/root/static/`
- Copies updated HTML templates to `/root/templates/`

### Step 3: Update CSS Version (Cache Busting)
```bash
pct exec 122 -- sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html
```
- Forces browsers to reload CSS by incrementing version
- Change `2.7.0` to current version and `2.8.0` to next version
- This prevents browser caching issues

### Step 4: Restart Service
```bash
pct exec 122 -- systemctl restart netflow-dashboard
```
- Stops and starts the Python Flask application
- Loads new code into memory

### Step 5: Verify
```bash
pct exec 122 -- systemctl status netflow-dashboard
```
- Should show "active (running)" in green
- Check for any errors in the output

---

## Alternative: Deploy from Inside Container

```bash
# 1. Enter the container
pct exec 122 -- bash

# 2. Pull latest code
cd /tmp/repo && git pull

# 3. Copy files
cp netflow-dashboard.py /root/
cp static/*.js static/*.css /root/static/
cp templates/*.html /root/templates/

# 4. Update CSS version
sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html

# 5. Restart service
systemctl restart netflow-dashboard

# 6. Check status
systemctl status netflow-dashboard

# 7. View logs if needed
journalctl -u netflow-dashboard -n 50 --no-pager

# 8. Exit container
exit
```

---

## Quick One-Liner (All Steps Combined)

```bash
pct exec 122 -- bash -c "cd /tmp/repo && git pull && \
cp netflow-dashboard.py /root/ && \
cp static/*.js static/*.css /root/static/ && \
cp templates/*.html /root/templates/ && \
sed -i 's/v=2\.7\.0/v=2.8.0/' /root/templates/index.html && \
systemctl restart netflow-dashboard && \
sleep 2 && \
systemctl status netflow-dashboard"
```

---

## Files to Deploy (Reference)

| File | Source | Destination |
|------|--------|-------------|
| Backend | `/tmp/repo/netflow-dashboard.py` | `/root/netflow-dashboard.py` |
| JavaScript | `/tmp/repo/static/app.js` | `/root/static/app.js` |
| JavaScript (min) | `/tmp/repo/static/app.min.js` | `/root/static/app.min.js` |
| CSS | `/tmp/repo/static/style.css` | `/root/static/style.css` |
| CSS (min) | `/tmp/repo/static/style.min.css` | `/root/static/style.min.css` |
| HTML | `/tmp/repo/templates/index.html` | `/root/templates/index.html` |

---

## Troubleshooting

### Check if Service Failed
```bash
pct exec 122 -- systemctl status netflow-dashboard
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

- **Proxmox Host**: PHOBOS-PROX-2 (192.168.0.80)
- **LXC Container**: 122 (PROX-NFDUMP)
- **Container IP**: 192.168.0.74
- **Dashboard URL**: http://192.168.0.74:8080
- **Service Name**: netflow-dashboard
- **Repository**: /tmp/repo
- **Production**: /root/

---

## Summary Checklist

- [ ] Pull code: `git pull`
- [ ] Copy Python backend
- [ ] Copy static files (JS/CSS)
- [ ] Copy HTML templates
- [ ] Increment CSS version
- [ ] Restart service
- [ ] Verify service is running
- [ ] Test dashboard in browser (http://192.168.0.74:8080)
