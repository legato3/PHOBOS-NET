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

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY netflow-dashboard.py .
COPY threat-feeds.txt .
COPY templates/ ./templates/
COPY static/ ./static/
COPY sample_data/ ./sample_data/

# Create directories for data (if needed)
RUN mkdir -p /var/cache/nfdump /root

# Expose port
EXPOSE 8080

# Set environment variables (can be overridden in docker-compose)
ENV FLASK_APP=netflow-dashboard.py
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python3", "netflow-dashboard.py"]
