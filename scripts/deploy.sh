#!/bin/bash
# Deployment script for PROX_NFDUMP Dashboard
# Run this from Proxmox host (192.168.0.80)

CONTAINER_ID=122
NEW_VERSION="2.8.0"

echo "🚀 Starting deployment to container $CONTAINER_ID..."

# Step 1: Pull latest code from GitHub
echo "📥 Pulling latest code from GitHub..."
pct exec $CONTAINER_ID -- bash -c "cd /tmp/repo && git pull"

# Step 2: Copy files to production
echo "📋 Copying files to production..."
pct exec $CONTAINER_ID -- bash -c "
    cp /tmp/repo/netflow-dashboard.py /root/ && \
    cp -r /tmp/repo/static/js /root/static/ 2>/dev/null || mkdir -p /root/static/js && cp -r /tmp/repo/static/js/* /root/static/js/ && \
    cp /tmp/repo/static/*.js /root/static/ && \
    cp /tmp/repo/static/*.css /root/static/ && \
    cp /tmp/repo/templates/*.html /root/templates/
"

# Step 3: Update CSS/JS cache version
echo "🔢 Updating cache version to v$NEW_VERSION..."
pct exec $CONTAINER_ID -- bash -c "
    sed -i 's/v=2\.6\.1/v=$NEW_VERSION/' /root/templates/index.html && \
    sed -i 's/v=2\.7\.0/v=$NEW_VERSION/' /root/templates/index.html
"

# Step 4: Restart service
echo "🔄 Restarting netflow-dashboard service..."
pct exec $CONTAINER_ID -- systemctl restart netflow-dashboard

# Step 5: Wait a moment and verify
sleep 2
echo "✅ Checking service status..."
pct exec $CONTAINER_ID -- systemctl status netflow-dashboard --no-pager -l

echo ""
echo "🎉 Deployment complete!"
echo "📊 Dashboard URL: http://192.168.0.74:8080"
