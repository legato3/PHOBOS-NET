# Environment Optimization Analysis & Recommendations

## Current Environment Analysis

### System Resources
- **OS**: Debian 12 (Bookworm)
- **Memory**: 1GB total, ~144MB used (14%), 863MB free
- **CPU**: 4 cores
- **Disk**: 20GB total, 1.7GB used (9% - healthy)
- **Swap**: 512MB, 14MB used

### Application Status
- **Framework**: Flask 2.2.2
- **Server**: Flask development server (NOT production-ready)
- **Memory Usage**: 137MB (14% of total RAM)
- **Threading**: Enabled
- **Port**: 8080
- **Service**: systemd (systemd/netflow-dashboard.service)

## Issues Identified

### 🔴 Critical
1. **Using Flask Development Server**
   - Warning in logs: "This is a development server. Do not use it in a production deployment."
   - Single-threaded, not suitable for production
   - No worker process management
   - Poor performance under load

### ⚠️ High Priority
2. **No Resource Limits in systemd**
   - No memory limits (could exhaust container memory)
   - No CPU limits
   - No file descriptor limits
   - No task limits

3. **No Restart Policy Optimization**
   - No restart delays (immediate restarts on failure)
   - No backoff strategy
   - Could cause rapid restart loops

### 📋 Medium Priority
4. **Locale Warnings**
   - Multiple locale warnings in logs (cosmetic)
   - Can be fixed but not critical

5. **Memory Optimization Opportunities**
   - Could optimize for 1GB RAM constraint
   - Cache sizes could be tuned
   - Thread pool sizes could be optimized

## Optimization Recommendations

### 1. Install Gunicorn (Production WSGI Server)

```bash
pct exec 122 -- pip3 install gunicorn
```

### 2. Update systemd Service

Use the optimized service file (`systemd/netflow-dashboard-optimized.service`) which includes:
- Gunicorn with 1 worker, 8 threads (optimal for I/O-bound Flask app)
- Memory limits (512MB max, 400MB high water mark)
- File descriptor limits (65536)
- Task limits (100 max)
- Restart policy with backoff
- Graceful shutdown handling
- Background threads start once (syslog receiver needs single instance)

### 3. Service File Changes Needed

```ini
# Change from:
ExecStart=/usr/bin/python3 /root/netflow-dashboard.py

# To:
ExecStart=/usr/bin/gunicorn --bind 0.0.0.0:8080 \
    --workers 1 --threads 8 --worker-class gthread \
    --worker-connections 1000 --timeout 30 \
    --max-requests 2000 \
    --name netflow-dashboard \
    -c /root/scripts/gunicorn_config.py \
    netflow_dashboard:app
```

### 4. Fix Locale Warnings

```bash
pct exec 122 -- bash -c "
    echo 'export LC_ALL=en_US.UTF-8' >> /root/.bashrc
    echo 'export LANG=en_US.UTF-8' >> /root/.bashrc
"
```

### 5. Gunicorn Configuration Rationale

**Workers**: 1 (single worker ensures background threads start once, critical for syslog receiver)
**Threads**: 8 (optimal for I/O-bound Flask app, provides good concurrency)
**Memory**: 512MB limit (50% of container RAM, leaves room for system/nfdump)
**Max Requests**: 2000 (prevents memory leaks, higher since single worker)
**Why 1 worker?**: Background threads (especially syslog receiver on UDP port 514) must run only once. Multiple workers would create duplicate receivers, causing conflicts.

## Deployment Steps

1. Install Gunicorn
2. Backup current service file
3. Deploy optimized service file
4. Test configuration
5. Restart service
6. Monitor performance

## Expected Improvements

- ✅ Production-grade WSGI server (Gunicorn)
- ✅ Better concurrency (8 threads vs 1)
- ✅ Memory protection (limits prevent OOM)
- ✅ Graceful restarts (no rapid restart loops)
- ✅ Better resource utilization
- ✅ Reduced memory usage per request

## Monitoring After Deployment

```bash
# Check service status
pct exec 122 -- systemctl status netflow-dashboard

# Monitor memory usage
pct exec 122 -- systemctl show netflow-dashboard | grep Memory

# Check Gunicorn workers
pct exec 122 -- ps aux | grep gunicorn

# View logs
pct exec 122 -- journalctl -u netflow-dashboard -f
```
