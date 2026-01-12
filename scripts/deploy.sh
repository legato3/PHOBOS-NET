#!/bin/bash
# Deployment script using Git repository on server
# Usage: ./scripts/deploy.sh

set -e

SSH_KEY="${HOME}/.ssh/id_ed25519_192.168.0.70"
SSH_USER="root"
SSH_HOST="192.168.0.70"
LXC_ID="122"
REPO_PATH="/repo"
DEPLOY_PATH="/root"

echo "🚀 Starting deployment..."

# Push changes to GitHub first
echo "📤 Pushing changes to GitHub..."
git push origin main

# SSH to server and deploy using tar (more reliable than git fetch for auth issues)
echo "📥 Syncing files to server repository..."
cd "$(dirname "$0")/.."
tar --exclude='.git' --exclude='.Jules' --exclude='*.pyc' --exclude='__pycache__' --exclude='.venv' -czf - . | \
ssh -i "$SSH_KEY" "${SSH_USER}@${SSH_HOST}" "pct exec ${LXC_ID} -- bash -c '
    mkdir -p ${REPO_PATH}
    cd ${REPO_PATH}
    tar -xzf -
    echo \"✅ Files synced to ${REPO_PATH}\"
    
    echo \"📋 Copying files to deployment directory...\"
    
    # Copy Python application
    cp -f netflow-dashboard.py ${DEPLOY_PATH}/
    
    # Copy static files
    mkdir -p ${DEPLOY_PATH}/static
    cp -rf static/* ${DEPLOY_PATH}/static/
    
    # Copy templates
    mkdir -p ${DEPLOY_PATH}/templates
    cp -rf templates/* ${DEPLOY_PATH}/templates/
    
    # Copy scripts if needed
    if [ -d scripts ]; then
        mkdir -p ${DEPLOY_PATH}/scripts
        cp -f scripts/gunicorn_config.py ${DEPLOY_PATH}/ 2>/dev/null || true
    fi
    
    echo \"✅ Files copied to deployment directory\"
    echo \"📊 Deployment summary:\"
    ls -lh ${DEPLOY_PATH}/netflow-dashboard.py 2>/dev/null | awk \"{print \\\$9, \\\$5}\"
    ls -lh ${DEPLOY_PATH}/static/*.js ${DEPLOY_PATH}/static/*.css 2>/dev/null | awk \"{print \\\$9, \\\$5}\" | head -5
    
    echo \"\"
    echo \"🔄 Restarting netflow-dashboard service...\"
    systemctl restart netflow-dashboard
    sleep 2
    
    echo \"\"
    echo \"📋 Service Status:\"
    systemctl status netflow-dashboard --no-pager -l | head -15
'"

echo ""
echo "✅ Deployment completed successfully!"
echo "🌐 Dashboard URL: http://192.168.0.74:8080"
