#!/bin/bash
# Setup SSH key for PROX-DOCKER-2 server
# This script will install the SSH public key on the server

set -e

SERVER="192.168.0.73"
USER="root"
KEY_FILE="$HOME/.ssh/id_ed25519_192.168.0.73"
PUB_KEY_FILE="${KEY_FILE}.pub"

echo "🔑 Setting up SSH key authentication for $USER@$SERVER..."

# Check if key exists
if [ ! -f "$PUB_KEY_FILE" ]; then
    echo "❌ Public key not found at $PUB_KEY_FILE"
    echo "Creating SSH key..."
    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "netflow-dashboard-deploy"
fi

echo "📋 Public key to install:"
cat "$PUB_KEY_FILE"
echo ""

echo "Please run this command manually (you'll be prompted for password: c_2580_C):"
echo ""
echo "cat $PUB_KEY_FILE | ssh $USER@$SERVER 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo \"SSH key installed successfully\"'"
echo ""

read -p "Have you installed the SSH key? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Testing SSH key authentication..."
    ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no $USER@$SERVER "echo '✅ SSH key authentication successful!' && uname -a"
else
    echo "Please install the SSH key first, then run this script again."
    exit 1
fi
