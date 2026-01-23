FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nfdump \
    dnsutils \
    curl \
    python3-pysnmp4 \
    snmp \
    nmap \
    iproute2 \
    iputils-ping \
    traceroute \
    whois \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw+ep /bin/ping

# Add OCI image labels
LABEL org.opencontainers.image.title="PHOBOS-NET"
LABEL org.opencontainers.image.description="Self-hosted, read-only network observability and threat detection"
LABEL org.opencontainers.image.source="https://github.com/legato3/PHOBOS-NET"

# Install Python dependencies directly (requirements.txt removed)
RUN pip install --no-cache-dir \
    flask \
    flask-compress \
    requests \
    maxminddb \
    dnspython \
    flask-login \
    gunicorn>=21.2.0

# Copy application files
# Copy the entire app directory structure
COPY app/ ./app/

# Setup /opt/phobos directories for static config and geoip
RUN mkdir -p /opt/phobos/config /opt/phobos/geoip

COPY docker-data/threat-feeds.txt /opt/phobos/config/threat-feeds.txt
COPY docker-data/GeoLite2-City.mmdb /opt/phobos/geoip/GeoLite2-City.mmdb
COPY docker-data/GeoLite2-ASN.mmdb /opt/phobos/geoip/GeoLite2-ASN.mmdb
COPY docker-data/GeoLite2-Country.mmdb /opt/phobos/geoip/GeoLite2-Country.mmdb
COPY scripts/gunicorn_config.py ./gunicorn_config.py
COPY docker/docker-entrypoint.sh ./docker-entrypoint.sh
COPY frontend/ ./frontend/

# Create a non-root user and group
RUN groupadd -r phobos && useradd -r -g phobos -u 1000 phobos

# Create directories and set permissions for non-root user
RUN mkdir -p /var/cache/nfdump /root /var/run /app/data \
    && chown -R phobos:phobos /app /opt/phobos /var/cache/nfdump /var/run /app/data

# Make entrypoint script executable
RUN chmod +x docker-entrypoint.sh

# Expose ports
# 8080: Web Dashboard
# 2055: NetFlow (nfcapd)
# 5514: Syslog (internal)
# 5515: Firewall Syslog (internal)
EXPOSE 8080 2055 5514/udp 5515/udp

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    SYSLOG_PORT=5514 \
    FIREWALL_SYSLOG_PORT=5515 \
    PATH="/home/phobos/.local/bin:$PATH"

# Switch to non-root user
USER phobos

# Use entrypoint script to start nfcapd and Gunicorn
ENTRYPOINT ["/app/docker-entrypoint.sh"]
