#!/bin/bash
# Environment Optimization Script for PROX_NFDUMP
# Run this on the Proxmox host (192.168.0.70)

CONTAINER_ID=122

echo "🔧 Starting environment optimization for container $CONTAINER_ID..."

# Step 1: Install Gunicorn
echo "📦 Installing Gunicorn..."
pct exec $CONTAINER_ID -- pip3 install gunicorn --break-system-packages --quiet 2>/dev/null || pct exec $CONTAINER_ID -- pip3 install gunicorn --quiet

# Step 2: Backup current service file
echo "💾 Backing up current service file..."
pct exec $CONTAINER_ID -- cp /etc/systemd/system/netflow-dashboard.service /etc/systemd/system/netflow-dashboard.service.backup

# Step 3: Create Gunicorn-compatible module and config
echo "📝 Creating Gunicorn-compatible setup..."
pct exec $CONTAINER_ID -- bash -c "
    cd /root
    # Copy the main file so we can import it as a module
    if [ ! -f netflow_dashboard.py ]; then
        cp netflow-dashboard.py netflow_dashboard.py
        # The if __name__ block won't execute when imported, which is what we want
        # Background threads will be started by Gunicorn hooks
    fi
"

# Step 4: Deploy Gunicorn config file
echo "📄 Deploying Gunicorn configuration..."
pct exec $CONTAINER_ID -- bash -c 'cat > /root/gunicorn_config.py << "EOFCONFIG"
# Gunicorn configuration for netflow-dashboard
import sys
sys.path.insert(0, "/root")

def post_worker_init(worker):
    """Initialize background threads when worker starts (runs once with 1 worker)."""
    try:
        import netflow_dashboard
        netflow_dashboard.start_threat_thread()
        netflow_dashboard.start_trends_thread()
        netflow_dashboard.start_agg_thread()
        netflow_dashboard.start_syslog_thread()
    except Exception as e:
        worker.log.error(f"Error starting background threads: {e}")
EOFCONFIG
'

# Step 5: Deploy optimized service file (using Gunicorn)
echo "🚀 Deploying optimized service file..."
pct exec $CONTAINER_ID -- bash -c 'cat > /etc/systemd/system/netflow-dashboard.service << "EOFSERVICE"
[Unit]
Description=NetFlow Analytics Dashboard (Production)
After=network.target

[Service]
Type=notify
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/python3 -m gunicorn --bind 0.0.0.0:8080 --workers 1 --threads 8 --worker-class gthread --worker-connections 1000 --timeout 30 --graceful-timeout 30 --keep-alive 5 --max-requests 2000 --max-requests-jitter 100 --access-logfile - --error-logfile - --log-level info --name netflow-dashboard -c /root/gunicorn_config.py netflow_dashboard:app

# Resource Limits (optimized for 1GB RAM container)
MemoryMax=512M
MemoryHigh=400M
LimitNOFILE=65536
TasksMax=100

# Restart Policy
Restart=on-failure
RestartSec=5s
StartLimitInterval=300s
StartLimitBurst=5

# Process Management
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOFSERVICE
'

# Step 6: Fix locale warnings (optional)
echo "🌐 Fixing locale configuration..."
pct exec $CONTAINER_ID -- bash -c "
    if ! grep -q 'LC_ALL=en_US.UTF-8' /root/.bashrc 2>/dev/null; then
        echo 'export LC_ALL=en_US.UTF-8' >> /root/.bashrc
        echo 'export LANG=en_US.UTF-8' >> /root/.bashrc
    fi
"

# Step 7: Reload systemd and restart service
echo "🔄 Reloading systemd daemon..."
pct exec $CONTAINER_ID -- systemctl daemon-reload

echo "⏸️  Stopping current service..."
pct exec $CONTAINER_ID -- systemctl stop netflow-dashboard

echo "▶️  Starting optimized service..."
pct exec $CONTAINER_ID -- systemctl start netflow-dashboard

# Step 7: Wait and verify
sleep 3
echo "✅ Checking service status..."
pct exec $CONTAINER_ID -- systemctl status netflow-dashboard --no-pager -l | head -20

echo ""
echo "🎉 Optimization complete!"
echo ""
echo "📊 Verify with:"
echo "  pct exec $CONTAINER_ID -- systemctl status netflow-dashboard"
echo "  pct exec $CONTAINER_ID -- ps aux | grep gunicorn"
echo "  pct exec $CONTAINER_ID -- systemctl show netflow-dashboard | grep Memory"
