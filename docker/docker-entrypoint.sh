#!/bin/bash
set -e

# Configuration with defaults
NFCAPD_PORT=${NFCAPD_PORT:-2055}
NFCAPD_DIR=${NFCAPD_DIR:-/var/cache/nfdump}
WEB_PORT=${WEB_PORT:-8080}
WORKERS=${GUNICORN_WORKERS:-1}
THREADS=${GUNICORN_THREADS:-8}

# Start nfcapd in the background for NetFlow collection
echo "Starting nfcapd NetFlow collector on port $NFCAPD_PORT..."
# -w: working directory (output directory for flow files)
# -D: daemonize (run in background)
# -p: port to listen on
# -y: use LZ4 compression
# -B: socket buffer size (8MB)
# -e: enable auto-expire
# -t: rotation interval (300 seconds = 5 minutes)
# -P: PID file location
nfcapd -w "$NFCAPD_DIR" -D -p "$NFCAPD_PORT" -y -B 8388608 -e -t 300 -P /tmp/nfcapd.pid

# Wait a moment for nfcapd to start
sleep 1

# Create log file
touch /app/data/phobos-net.log
# Tail log file to stdout in background so Docker follows it
tail -F /app/data/phobos-net.log &

# Start Gunicorn (production server)
echo "Starting Gunicorn application server on port $WEB_PORT..."
exec python3 -m gunicorn \
    --bind "0.0.0.0:$WEB_PORT" \
    --workers 2 \
    --threads 8 \
    --worker-class gthread \
    --worker-connections 1000 \
    --backlog 2048 \
    --timeout 120 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --max-requests 5000 \
    --max-requests-jitter 1000 \
    --access-logfile /app/data/phobos-net.log \
    --error-logfile /app/data/phobos-net.log \
    --log-level info \
    --name phobos-net \
    -c /app/gunicorn_config.py \
    app:app
