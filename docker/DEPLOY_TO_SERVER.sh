#!/bin/bash
# Deploy script for PROX-DOCKER-2 server
# Usage: ./docker/DEPLOY_TO_SERVER.sh

set -e

SERVER="192.168.0.73"
USER="root"
SSH_KEY="$HOME/.ssh/id_ed25519_192.168.0.73"
REMOTE_DIR="/root/netflow-dashboard"

echo "🚀 Deploying NetFlow Dashboard to $SERVER..."

# Create remote directory
echo "📁 Creating remote directory..."
ssh -i "$SSH_KEY" $USER@$SERVER "mkdir -p $REMOTE_DIR/docker"

# Copy docker files
echo "📦 Copying Docker files..."
scp -i "$SSH_KEY" docker/docker-compose.yml $USER@$SERVER:$REMOTE_DIR/docker/
scp -i "$SSH_KEY" docker/Dockerfile $USER@$SERVER:$REMOTE_DIR/docker/
scp -i "$SSH_KEY" docker/docker-entrypoint.sh $USER@$SERVER:$REMOTE_DIR/docker/
scp -i "$SSH_KEY" docker/.dockerignore $USER@$SERVER:$REMOTE_DIR/docker/ 2>/dev/null || true

# Copy application files (excluding large/unnecessary files)
echo "📦 Copying application files..."
ssh -i "$SSH_KEY" $USER@$SERVER "mkdir -p $REMOTE_DIR/{templates,static,scripts,sample_data}"
scp -i "$SSH_KEY" netflow-dashboard.py $USER@$SERVER:$REMOTE_DIR/

scp -i "$SSH_KEY" -r templates/* $USER@$SERVER:$REMOTE_DIR/templates/
scp -i "$SSH_KEY" -r static/* $USER@$SERVER:$REMOTE_DIR/static/
scp -i "$SSH_KEY" scripts/gunicorn_config.py $USER@$SERVER:$REMOTE_DIR/scripts/
scp -i "$SSH_KEY" -r sample_data/* $USER@$SERVER:$REMOTE_DIR/sample_data/ 2>/dev/null || true

# Build and start container
echo "🔨 Building and starting container..."
ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker-compose -f docker/docker-compose.yml down 2>/dev/null || true"
ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker-compose -f docker/docker-compose.yml build --no-cache"
ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker-compose -f docker/docker-compose.yml up -d"

# Wait for container to start
echo "⏳ Waiting for container to start..."
sleep 5

# Check status
echo "📊 Container status:"
ssh -i "$SSH_KEY" $USER@$SERVER "docker ps | grep netflow-dashboard || docker-compose -f $REMOTE_DIR/docker/docker-compose.yml ps"

echo ""
echo "✅ Deployment complete!"
echo "🌐 Dashboard should be available at: http://192.168.0.73:8080"
echo ""
echo "To view logs:"
echo "  ssh $USER@$SERVER 'docker logs phobos-net -f'"
echo ""
echo "To check syslog status:"
echo "  ssh $USER@$SERVER 'curl -s http://localhost:8080/api/server/health | grep -A 6 syslog'"
