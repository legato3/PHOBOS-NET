#!/bin/bash
# Deployment script using Git repository on server
# Usage: ./scripts/deploy.sh

set -e

# --- Configuration ---
SSH_KEY="${HOME}/.ssh/id_ed25519_192.168.0.70"
SSH_USER="root"
SSH_HOST="192.168.0.70"
LXC_ID="122"
CONTAINER_IP="192.168.0.74"
REPO_PATH="/repo"
DEPLOY_PATH="/root"

# --- Main Script ---

echo "🚀 Starting deployment..."

# Ensure we're in the repo root
cd "$(dirname "$0")/.."

# 1. Check for uncommitted changes (Safety Check)
if [ -n "$(git status --porcelain)" ]; then
    echo "⚠️  Uncommitted changes detected:"
    git status --short
    read -p "❓ Continue deployment anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Deployment aborted."
        exit 1
    fi
    echo "⚠️  Proceeding with uncommitted changes (local files will be deployed)..."
fi

# 2. Push changes to GitHub (Optional but recommended)
echo "📤 Pushing changes to GitHub..."
git push origin main || echo "⚠️  Git push failed. Continuing with local file sync..."

# 3. SSH to server and deploy
echo "📥 Syncing files to server container..."

# Create a tarball of the current directory, excluding unnecessary files
# We stream this directly to the SSH command -> pct exec -> tar extract
tar --exclude='.git' --exclude='.Jules' --exclude='*.pyc' --exclude='__pycache__' \
    --exclude='.venv' --exclude='.DS_Store' --exclude='tests' \
    -czf - . | \
ssh -i "$SSH_KEY" "${SSH_USER}@${SSH_HOST}" "pct exec ${LXC_ID} -- bash -c '
    set -e
    
    # 3a. Setup Repo/Staging Area
    mkdir -p ${REPO_PATH}
    cd ${REPO_PATH}
    
    echo \"📦 Extracting files...\"
    tar -xzf -
    
    # 3b. Install Dependencies
    echo \"📦 Installing dependencies...\"
    # Assuming system python as per service file (ExecStart=/usr/bin/python3)
    # Using --break-system-packages if needed for newer Debian/Ubuntu, or standard pip otherwise
    if pip3 install --break-system-packages -r requirements.txt 2>/dev/null; then
        echo \"✅ Dependencies installed (using --break-system-packages)\"
    else
        pip3 install -r requirements.txt
        echo \"✅ Dependencies installed\"
    fi
    
    echo \"📋 Updating deployment directory...\"
    
    # 3c. Clean and Copy Files
    # Remove old static/templates to ensure clean state (no stale files)
    rm -rf ${DEPLOY_PATH}/static ${DEPLOY_PATH}/templates
    
    # Copy new files
    cp -f netflow-dashboard.py ${DEPLOY_PATH}/
    cp -f requirements.txt ${DEPLOY_PATH}/
    
    mkdir -p ${DEPLOY_PATH}/static
    cp -rf static/* ${DEPLOY_PATH}/static/
    
    mkdir -p ${DEPLOY_PATH}/templates
    cp -rf templates/* ${DEPLOY_PATH}/templates/
    
    # Gunicorn config if applicable
    if [ -d scripts ] && [ -f scripts/gunicorn_config.py ]; then
        mkdir -p ${DEPLOY_PATH}/scripts
        cp -f scripts/gunicorn_config.py ${DEPLOY_PATH}/scripts/
    fi
    
    echo \"✅ Files updated in ${DEPLOY_PATH}\"
    
    # 3d. Restart Service
    echo \"🔄 Restarting netflow-dashboard service...\"
    systemctl restart netflow-dashboard
    
    # Wait a moment for service to come up
    sleep 3
    
    echo \"📋 Service Status:\"
    systemctl is-active netflow-dashboard
'"

# 4. Verify deployment (Health Check)
echo "🔍 Verifying deployment at http://${CONTAINER_IP}:8080..."

if curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://${CONTAINER_IP}:8080" | grep -q "200"; then
    echo "✅ Health check passed! Site is reachable."
else
    echo "⚠️  Health check failed. Site might be down or starting up slow."
    echo "   Check logs on server: ssh ${SSH_USER}@${SSH_HOST} \"pct exec ${LXC_ID} -- journalctl -u netflow-dashboard -n 50\""
fi

echo ""
echo "✅ Deployment completed!"
echo "🌐 Dashboard URL: http://${CONTAINER_IP}:8080"

