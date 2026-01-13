#!/bin/bash
set -e

# Start nfcapd in the background for NetFlow collection
echo "Starting nfcapd NetFlow collector..."
nfcapd -l /var/cache/nfdump -p 2055 -y -B 8388608 -e -t 300 -D -P /var/run/nfcapd.pid

# Wait a moment for nfcapd to start
sleep 1

# Start Gunicorn (production server)
echo "Starting Gunicorn application server..."
exec python3 -m gunicorn \
    --bind 0.0.0.0:8080 \
    --workers 1 \
    --threads 8 \
    --worker-class gthread \
    --worker-connections 1000 \
    --timeout 30 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --max-requests 2000 \
    --max-requests-jitter 100 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    --name netflow-dashboard \
    -c /app/gunicorn_config.py \
    netflow_dashboard:app
