#!/bin/bash
# Docker Deployment Script for Proxmox LXC
# Replaces systemd service with Docker container

set -e

PROXMOX_HOST="192.168.0.70"
LXC_ID="122"
REMOTE_USER="root"
COMPOSE_FILE="docker-compose.prod.yml"

echo "🚀 Deploying NetFlow Dashboard to Docker (LXC $LXC_ID)..."

# Check if Docker is installed on remote
echo "📋 Checking Docker installation..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- docker --version" || {
    echo "❌ Docker not installed on LXC container"
    echo "📝 Installing Docker..."
    ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c '
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        sh /tmp/get-docker.sh
        apt-get install -y docker-compose-plugin
        docker --version
    '"
}

# Stop old systemd service if running
echo "🛑 Stopping systemd service (if running)..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c '
    systemctl stop netflow-dashboard 2>/dev/null || true
    systemctl disable netflow-dashboard 2>/dev/null || true
'"

# Copy Docker files to server
echo "📦 Copying Docker files to server..."
cat Dockerfile | ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'cat > /root/Dockerfile'"
cat docker-compose.prod.yml | ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'cat > /root/docker-compose.prod.yml'"
cat netflow_dashboard.py | ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'cat > /root/netflow_dashboard.py'"
cat requirements.txt | ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'cat > /root/requirements.txt'"

# Copy application files
echo "📦 Copying application files..."
cat netflow-dashboard.py | ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'cat > /root/netflow-dashboard.py'"

# Copy templates directory
echo "📦 Copying templates..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'mkdir -p /root/templates'"
for file in templates/*.html; do
    if [ -f "$file" ]; then
        cat "$file" | ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'cat > /root/$(basename $file | sed \"s|templates/|templates/|\")'"
    fi
done

# Copy static directory
echo "📦 Copying static files..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'mkdir -p /root/static'"
for file in static/*.css static/*.js static/*.png static/*.min.*; do
    if [ -f "$file" ]; then
        cat "$file" | ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c 'cat > /root/static/$(basename $file)'"
    fi
done

# Prepare data directories
echo "📁 Preparing data directories..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c '
    cd /root
    mkdir -p data
    chmod 755 data
    chmod 644 firewall.db netflow-trends.sqlite threat-feeds.txt 2>/dev/null || true
'"

# Build Docker image
echo "🔨 Building Docker image..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c '
    cd /root
    docker compose -f ${COMPOSE_FILE} build
'"

# Start Docker container
echo "🚀 Starting Docker container..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- bash -c '
    cd /root
    docker compose -f ${COMPOSE_FILE} up -d
'"

# Wait for container to start
echo "⏳ Waiting for container to start..."
sleep 5

# Check status
echo "📋 Container status:"
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- docker compose -f ${COMPOSE_FILE} ps"

# Check logs
echo ""
echo "📋 Recent logs:"
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- docker compose -f ${COMPOSE_FILE} logs --tail=20"

# Test health endpoint
echo ""
echo "🔍 Testing health endpoint..."
ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${PROXMOX_HOST} "pct exec ${LXC_ID} -- curl -s http://localhost:8080/health | head -5" || echo "Health endpoint not ready yet"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📝 Useful commands:"
echo "   View logs:  ssh ${REMOTE_USER}@${PROXMOX_HOST} \"pct exec ${LXC_ID} -- docker compose -f ${COMPOSE_FILE} logs -f\""
echo "   Restart:    ssh ${REMOTE_USER}@${PROXMOX_HOST} \"pct exec ${LXC_ID} -- docker compose -f ${COMPOSE_FILE} restart\""
echo "   Stop:       ssh ${REMOTE_USER}@${PROXMOX_HOST} \"pct exec ${PROXMOX_HOST} -- docker compose -f ${COMPOSE_FILE} down\""
echo ""
echo "🌐 Dashboard: http://192.168.0.70:8080 (or your server IP)"
