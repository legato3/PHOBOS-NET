#!/bin/bash
# Install SSH key on PROX-DOCKER-2 server
# Uses expect to automate password entry

set -e

SERVER="192.168.0.73"
USER="root"
PASSWORD="c_2580_C"
KEY_FILE="$HOME/.ssh/id_ed25519_192.168.0.73"
PUB_KEY_FILE="${KEY_FILE}.pub"

echo "🔑 Installing SSH key on $USER@$SERVER..."

# Check if key exists
if [ ! -f "$PUB_KEY_FILE" ]; then
    echo "❌ Public key not found. Creating..."
    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "netflow-dashboard-deploy"
fi

# Read public key
PUBKEY=$(cat "$PUB_KEY_FILE")

# Install using expect or manual method
if command -v expect >/dev/null 2>&1; then
    echo "Using expect to automate installation..."
    expect <<EOF
set timeout 30
spawn ssh -o StrictHostKeyChecking=no $USER@$SERVER "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$PUBKEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'SUCCESS'"
expect {
    "password:" { send "$PASSWORD\r"; exp_continue }
    "Permission denied" { exit 1 }
    "SUCCESS" { exit 0 }
    timeout { exit 1 }
}
expect eof
EOF
else
    echo "expect not found. Please run this command manually:"
    echo ""
    echo "cat $PUB_KEY_FILE | ssh $USER@$SERVER 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo \"SSH key installed\"'"
    echo ""
    echo "Password: $PASSWORD"
    exit 1
fi

echo "✅ SSH key installation complete!"
echo "Testing connection..."
ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no $USER@$SERVER "echo '✅ SSH key authentication successful!'" || {
    echo "❌ SSH key authentication failed. Please check the installation."
    exit 1
}
