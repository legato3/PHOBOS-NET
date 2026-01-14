#!/bin/bash
# Deploy script for PROX-DOCKER-2 server
# Usage: ./docker/DEPLOY_TO_SERVER.sh

set -e

SERVER="192.168.0.73"
USER="root"
REMOTE_DIR="/root/netflow-dashboard"

echo "🚀 Deploying NetFlow Dashboard to $SERVER..."

# Create remote directory
echo "📁 Creating remote directory..."
ssh $USER@$SERVER "mkdir -p $REMOTE_DIR/docker"

# Copy docker files
echo "📦 Copying Docker files..."
scp docker/docker-compose.yml $USER@$SERVER:$REMOTE_DIR/docker/
scp docker/Dockerfile $USER@$SERVER:$REMOTE_DIR/docker/
scp docker/docker-entrypoint.sh $USER@$SERVER:$REMOTE_DIR/docker/
scp docker/.dockerignore $USER@$SERVER:$REMOTE_DIR/docker/ 2>/dev/null || true

# Copy application files (excluding large/unnecessary files)
echo "📦 Copying application files..."
ssh $USER@$SERVER "mkdir -p $REMOTE_DIR/{templates,static,scripts,sample_data}"
scp netflow-dashboard.py $USER@$SERVER:$REMOTE_DIR/

scp -r templates/* $USER@$SERVER:$REMOTE_DIR/templates/
scp -r static/* $USER@$SERVER:$REMOTE_DIR/static/
scp scripts/gunicorn_config.py $USER@$SERVER:$REMOTE_DIR/scripts/
scp -r sample_data/* $USER@$SERVER:$REMOTE_DIR/sample_data/ 2>/dev/null || true

# Build and start container
echo "🔨 Building and starting container..."
ssh $USER@$SERVER "cd $REMOTE_DIR && docker-compose -f docker/docker-compose.yml down 2>/dev/null || true"
ssh $USER@$SERVER "cd $REMOTE_DIR && docker-compose -f docker/docker-compose.yml build --no-cache"
ssh $USER@$SERVER "cd $REMOTE_DIR && docker-compose -f docker/docker-compose.yml up -d"

# Wait for container to start
echo "⏳ Waiting for container to start..."
sleep 5

# Check status
echo "📊 Container status:"
ssh $USER@$SERVER "docker ps | grep netflow-dashboard || docker-compose -f $REMOTE_DIR/docker/docker-compose.yml ps"

echo ""
echo "✅ Deployment complete!"
echo "🌐 Dashboard should be available at: http://192.168.0.73:8080"
echo ""
echo "To view logs:"
echo "  ssh $USER@$SERVER 'docker logs phobos-net -f'"
echo ""
echo "To check syslog status:"
echo "  ssh $USER@$SERVER 'curl -s http://localhost:8080/api/server/health | grep -A 6 syslog'"
