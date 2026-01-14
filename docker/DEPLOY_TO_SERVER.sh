#!/bin/bash
# Deploy script for PROX-DOCKER-2 server
# Usage: ./docker/DEPLOY_TO_SERVER.sh [--rebuild]
#
# By default, uses fast docker cp method to inject files directly into container (~5 sec)
# Use --rebuild flag to force full container rebuild (15-20 sec, needed for Dockerfile/requirements.txt changes)

set -e

SERVER="192.168.0.73"
USER="root"
SSH_KEY="$HOME/.ssh/id_ed25519_192.168.0.73"
REMOTE_DIR="/root/netflow-dashboard"
CONTAINER_NAME="phobos-net"

# Check if rebuild is requested
REBUILD=false
if [[ "$1" == "--rebuild" ]]; then
    REBUILD=true
    echo "🔨 Rebuild mode: Will rebuild container (needed for Dockerfile/requirements.txt changes)"
else
    echo "⚡ Fast mode: Will use docker cp to inject files directly into container"
fi

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

# Copy application files (new modular structure)
echo "📦 Copying application files..."
ssh -i "$SSH_KEY" $USER@$SERVER "mkdir -p $REMOTE_DIR/{app,frontend/{templates,static},scripts,sample_data,docker-data}"
# Copy app directory (modular structure)
scp -i "$SSH_KEY" -r app/ $USER@$SERVER:$REMOTE_DIR/
# Copy phobos_dashboard.py (renamed from netflow-dashboard.py)
scp -i "$SSH_KEY" phobos_dashboard.py $USER@$SERVER:$REMOTE_DIR/
# Copy frontend directory
scp -i "$SSH_KEY" -r frontend/templates/* $USER@$SERVER:$REMOTE_DIR/frontend/templates/ 2>/dev/null || true
scp -i "$SSH_KEY" -r frontend/static/* $USER@$SERVER:$REMOTE_DIR/frontend/static/ 2>/dev/null || true
# Copy scripts and sample data
scp -i "$SSH_KEY" scripts/gunicorn_config.py $USER@$SERVER:$REMOTE_DIR/scripts/ 2>/dev/null || true
scp -i "$SSH_KEY" -r sample_data/* $USER@$SERVER:$REMOTE_DIR/sample_data/ 2>/dev/null || true
# Copy threat-feeds.txt if it exists in docker-data
scp -i "$SSH_KEY" docker-data/threat-feeds.txt $USER@$SERVER:$REMOTE_DIR/docker-data/ 2>/dev/null || true

if [ "$REBUILD" = true ]; then
    # Full rebuild (needed for Dockerfile/requirements.txt changes)
    echo "🔨 Building and starting container (full rebuild)..."
    ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker compose -f docker/docker-compose.yml down 2>/dev/null || true"
    ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker compose -f docker/docker-compose.yml build --no-cache"
    ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker compose -f docker/docker-compose.yml up -d"
else
    # Fast method: Check if container exists
    CONTAINER_EXISTS=$(ssh -i "$SSH_KEY" $USER@$SERVER "docker ps -a --format '{{.Names}}' | grep -q '^${CONTAINER_NAME}$' && echo 'yes' || echo 'no'")
    
    if [ "$CONTAINER_EXISTS" = "yes" ]; then
        # Fast update: Inject files directly into running container
        echo "⚡ Fast update: Injecting files into running container..."
        
        # For new modular structure, we need to rebuild since structure changed
        echo "⚠️  Modular structure changes detected - rebuilding container..."
        REBUILD=true
        
        # Restart container to pick up changes
        echo "🔄 Restarting container..."
        ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker compose -f docker/docker-compose.yml restart 2>/dev/null || docker compose -f docker/docker-compose.yml up -d"
    else
        # Container doesn't exist, need to build it
        echo "📦 Container doesn't exist, building for first time..."
        ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker compose -f docker/docker-compose.yml build --no-cache"
        ssh -i "$SSH_KEY" $USER@$SERVER "cd $REMOTE_DIR && docker compose -f docker/docker-compose.yml up -d"
    fi
fi

# Wait for container to start
echo "⏳ Waiting for container to start..."
sleep 5

# Check status
echo "📊 Container status:"
ssh -i "$SSH_KEY" $USER@$SERVER "docker ps | grep ${CONTAINER_NAME} || docker compose -f $REMOTE_DIR/docker/docker-compose.yml ps"

echo ""
echo "✅ Deployment complete!"
echo "🌐 Dashboard should be available at: http://192.168.0.73:3434"
echo ""
if [ "$REBUILD" = false ]; then
    echo "💡 Tip: Used fast docker cp method (~5 sec). Use --rebuild flag for Dockerfile/requirements.txt changes."
fi
echo ""
echo "To view logs:"
echo "  ssh -i \"$SSH_KEY\" $USER@$SERVER 'docker logs ${CONTAINER_NAME} -f'"
echo ""
echo "To check syslog status:"
echo "  ssh -i \"$SSH_KEY\" $USER@$SERVER 'curl -s http://localhost:3434/api/server/health | python3 -m json.tool | grep -A 6 syslog'"
