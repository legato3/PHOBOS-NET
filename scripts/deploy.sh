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

# SSH to server and deploy
echo "📥 Pulling latest changes on server..."
ssh -i "$SSH_KEY" "${SSH_USER}@${SSH_HOST}" "pct exec ${LXC_ID} -- bash -c '
    cd ${REPO_PATH}
    git fetch origin
    git reset --hard origin/main
    
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
    
    echo \"✅ Files copied successfully\"
    echo \"📊 Deployment path contents:\"
    ls -lh ${DEPLOY_PATH}/netflow-dashboard.py ${DEPLOY_PATH}/static/*.js ${DEPLOY_PATH}/static/*.css 2>/dev/null | head -10
'"

echo ""
echo "✅ Deployment completed successfully!"
echo "💡 Note: Restart the service manually if needed: systemctl restart netflow-dashboard"
