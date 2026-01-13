FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nfdump \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies (including gunicorn for production)
RUN pip install --no-cache-dir -r requirements.txt gunicorn>=21.2.0

# Copy application files
COPY netflow-dashboard.py .
COPY threat-feeds.txt .
COPY scripts/gunicorn_config.py ./gunicorn_config.py
COPY templates/ ./templates/
COPY static/ ./static/
COPY sample_data/ ./sample_data/

# Create symlink for module import (netflow_dashboard:app)
# Production uses netflow_dashboard:app but file is netflow-dashboard.py
RUN ln -s netflow-dashboard.py netflow_dashboard.py

# Create directories for data (if needed)
RUN mkdir -p /var/cache/nfdump /root

# Expose port
EXPOSE 8080

# Set environment variables (can be overridden in docker-compose)
ENV PYTHONUNBUFFERED=1

# Run the application with Gunicorn (production setup)
# Using same settings as production: 1 worker, 8 threads, gthread worker class
CMD ["python3", "-m", "gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "1", \
     "--threads", "8", \
     "--worker-class", "gthread", \
     "--worker-connections", "1000", \
     "--timeout", "30", \
     "--graceful-timeout", "30", \
     "--keep-alive", "5", \
     "--max-requests", "2000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "--name", "netflow-dashboard", \
     "-c", "/app/gunicorn_config.py", \
     "netflow_dashboard:app"]
