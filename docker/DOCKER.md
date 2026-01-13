# Docker Test Environment

This document describes how to run the NetFlow Dashboard in a Docker container for testing and development.

## Quick Start

### Using Docker Compose (Recommended)

From the project root directory:

```bash
# Build and start the container
docker-compose -f docker/docker-compose.yml up -d

# View logs
docker-compose -f docker/docker-compose.yml logs -f

# Stop the container
docker-compose -f docker/docker-compose.yml down
```

Or from the `docker/` directory:

```bash
cd docker
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

The dashboard will be available at `http://localhost:8080`

### Using Docker directly

From the project root directory:

```bash
# Build the image
docker build -f docker/Dockerfile -t netflow-dashboard .

# Run the container
docker run -d \
  --name netflow-dashboard-test \
  -p 8080:8080 \
  -p 2055:2055/udp \
  -p 514:514/udp \
  -v $(pwd)/docker-data:/app/data \
  netflow-dashboard

# View logs
docker logs -f netflow-dashboard-test

# Stop and remove
docker stop netflow-dashboard-test
docker rm netflow-dashboard-test
```

## Features

- **Sample Data**: The application automatically uses sample data from `sample_data/nfdump_flows.csv` when nfdump is not available or when no NetFlow files are present
- **SQLite Databases**: Database files are stored in the `docker-data/` directory (created automatically)
- **Hot Reload**: For development, mount the code directory as a volume (see Development section)

## Environment Variables

You can override default settings using environment variables in `docker-compose.yml`:

```yaml
environment:
  - DNS_SERVER=192.168.0.6
  - SNMP_HOST=192.168.0.1
  - SNMP_COMMUNITY=your_community
  - FIREWALL_DB_PATH=/app/data/firewall.db
  - TRENDS_DB_PATH=/app/data/netflow-trends.sqlite
  - VIRUSTOTAL_API_KEY=your_key
  - ABUSEIPDB_API_KEY=your_key
```

## Development Mode

For development with live code reloading, modify `docker-compose.yml`:

```yaml
services:
  netflow-dashboard:
    volumes:
      # Mount source code for live reload
      - ./netflow-dashboard.py:/app/netflow-dashboard.py
      - ./templates:/app/templates
      - ./static:/app/static
      - ./docker-data:/app/data
    environment:
      - FLASK_DEBUG=true
```

Note: The Flask development server will auto-reload on file changes when `FLASK_DEBUG=true`.

## Data Persistence

Database files and other data are stored in the `docker-data/` directory:

```
docker-data/
├── firewall.db          # Firewall syslog database
└── netflow-trends.sqlite # NetFlow trends database
```

To reset the test environment, simply delete the `docker-data/` directory:

```bash
rm -rf docker-data/
docker-compose up -d
```

## Testing with Sample Data

The application includes sample NetFlow data in `sample_data/nfdump_flows.csv`. When running in Docker:

1. The application will automatically detect if nfdump files are missing
2. It will fall back to using the sample data
3. All dashboard features will work with the sample data

## Health Check

The container includes a health check that verifies the `/health` endpoint. Check container health:

```bash
docker ps  # Look for "healthy" status
docker inspect netflow-dashboard-test | grep -A 10 Health
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs netflow-dashboard

# Check if port is already in use
lsof -i :8080
```

### Permission issues

If you encounter permission issues with mounted volumes:

```bash
# Fix permissions (macOS/Linux)
sudo chown -R $USER:$USER docker-data/
```

### Reset everything

From the project root:

```bash
# Stop and remove containers, volumes, and images
docker-compose -f docker/docker-compose.yml down -v
docker rmi netflow-dashboard-test netflow-dashboard

# Rebuild from scratch
docker-compose -f docker/docker-compose.yml build --no-cache
docker-compose -f docker/docker-compose.yml up -d
```

Or from the `docker/` directory:

```bash
cd docker
docker-compose down -v
docker rmi netflow-dashboard-test netflow-dashboard
docker-compose build --no-cache
docker-compose up -d
```

## Services Running in Container

The Docker container runs multiple services:

1. **nfcapd** - NetFlow collector (UDP port 2055)
   - Collects NetFlow data from network devices
   - Stores data in `/var/cache/nfdump` with LZ4 compression
   - 5-minute file rotation, auto-expire enabled
   - Runs in background via entrypoint script

2. **Gunicorn** - Production WSGI server (port 8080)
   - Serves the Flask dashboard application
   - 1 worker, 8 threads (gthread worker class)
   - Matches production configuration

3. **Syslog Receiver** - UDP port 514
   - Receives firewall syslog messages
   - Started automatically by the Flask application
   - Stores data in SQLite database

4. **SNMP Support** - python3-pysnmp4 installed
   - Available for SNMP polling (configured via environment variables)
   - Set `SNMP_HOST` and `SNMP_COMMUNITY` to enable

## Ports Exposed

- **8080/tcp** - Web dashboard (HTTP)
- **2055/udp** - NetFlow collection (nfcapd)
- **514/udp** - Syslog receiver

To receive NetFlow data, configure your router/firewall to send NetFlow exports to the container's IP on port 2055.

## Production Considerations

This Docker setup matches production configuration. For production deployment:

1. Use a production WSGI server (Gunicorn) instead of Flask's development server
2. Set up proper logging and log rotation
3. Configure resource limits (CPU, memory)
4. Use environment-specific secrets management
5. Set up proper networking and security policies
6. Consider using the optimized systemd service instead (see `systemd/netflow-dashboard-optimized.service`)

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for production deployment instructions.
