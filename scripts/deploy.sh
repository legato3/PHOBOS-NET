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
echo "📥 Updating repository on server..."
ssh -i "$SSH_KEY" "${SSH_USER}@${SSH_HOST}" "pct exec ${LXC_ID} -- bash -c '
    # Initialize repo if it doesn't exist
    if [ ! -d ${REPO_PATH}/.git ]; then
        echo \"Initializing repository...\"
        mkdir -p ${REPO_PATH}
        cd ${REPO_PATH}
        git init
        git remote add origin https://github.com/legato3/PROX_NFDUMP.git 2>/dev/null || git remote set-url origin https://github.com/legato3/PROX_NFDUMP.git
    fi
    
    cd ${REPO_PATH}
    # Try to fetch, but continue if it fails (network/auth issues)
    git fetch origin 2>/dev/null || echo \"Note: Could not fetch from GitHub (may require auth). Using local files.\"
    # If we have a remote branch reference, use it, otherwise just use current files
    if git rev-parse --verify origin/main >/dev/null 2>&1; then
        git reset --hard origin/main
    else
        echo \"Using local repository files...\"
    fi
    
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
