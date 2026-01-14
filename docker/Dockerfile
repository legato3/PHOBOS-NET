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
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY sample_data/requirements.txt .

# Install Python dependencies (including gunicorn for production)
RUN pip install --no-cache-dir -r requirements.txt gunicorn>=21.2.0

# Copy application files
COPY netflow-dashboard.py .
COPY docker-data/threat-feeds.txt .
COPY scripts/gunicorn_config.py ./gunicorn_config.py
COPY docker/docker-entrypoint.sh ./docker-entrypoint.sh
COPY templates/ ./templates/
COPY static/ ./static/
COPY sample_data/ ./sample_data/

# Make entrypoint script executable
RUN chmod +x docker-entrypoint.sh

# Create symlink for module import (netflow_dashboard:app)
# Production uses netflow_dashboard:app but file is netflow-dashboard.py
RUN ln -s netflow-dashboard.py netflow_dashboard.py

# Create directories for data (if needed)
RUN mkdir -p /var/cache/nfdump /root /var/run

# Expose port
EXPOSE 8080

# Set environment variables (can be overridden in docker-compose)
ENV PYTHONUNBUFFERED=1

# Use entrypoint script to start nfcapd and Gunicorn
ENTRYPOINT ["/app/docker-entrypoint.sh"]
