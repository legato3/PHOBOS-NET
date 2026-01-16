FROM python:3.11-slim

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
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY docker-data/requirements.txt .

# Install Python dependencies (including gunicorn for production)
RUN pip install --no-cache-dir -r requirements.txt gunicorn>=21.2.0

# Copy application files
# Copy the entire app directory structure
COPY app/ ./app/
COPY docker-data/threat-feeds.txt .
COPY scripts/gunicorn_config.py ./gunicorn_config.py
COPY docker/docker-entrypoint.sh ./docker-entrypoint.sh
COPY frontend/templates/ ./frontend/templates/
COPY frontend/static/ ./frontend/static/
#COPY sample_data/ ./sample_data/

# Make entrypoint script executable
RUN chmod +x docker-entrypoint.sh

# Create directories for data (if needed)
RUN mkdir -p /var/cache/nfdump /root /var/run

# Expose port
EXPOSE 8080

# Set environment variables (can be overridden in docker-compose)
ENV PYTHONUNBUFFERED=1

# Use entrypoint script to start nfcapd and Gunicorn
ENTRYPOINT ["/app/docker-entrypoint.sh"]
