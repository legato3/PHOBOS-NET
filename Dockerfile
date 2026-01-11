# Dockerfile for NetFlow Analytics Dashboard
# Mimics the production server environment

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASK_APP=netflow-dashboard.py
ENV FLASK_ENV=production

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nfdump \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn>=21.2.0

# Copy application files
COPY netflow-dashboard.py .
COPY netflow_dashboard.py .
COPY templates/ ./templates/
COPY static/ ./static/
COPY scripts/ ./scripts/

# Create necessary directories
RUN mkdir -p /var/cache/nfdump /app/data && \
    chmod 755 /var/cache/nfdump /app/data

# Create a non-root user (optional, for security)
# Note: Commented out for production to match current setup (root user)
# RUN useradd -m -u 1000 appuser && \
#     chown -R appuser:appuser /app /var/cache/nfdump

# Switch to non-root user (commented for production compatibility)
# USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run with Gunicorn (matching production setup)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--worker-class", "gthread", "--timeout", "30", "--name", "netflow-dashboard", "netflow_dashboard:app"]
