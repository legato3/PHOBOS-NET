# Docker Setup for Local Testing

This Docker setup mimics the production server environment for local testing.

## Prerequisites

- Docker Desktop (or Docker + Docker Compose)
- Git (to clone the repository)

## Quick Start

1. **Build and start the container:**
   ```bash
   docker-compose up --build
   ```
   Or with newer Docker:
   ```bash
   docker compose up --build
   ```

2. **Access the dashboard:**
   Open http://localhost:8080 in your browser

3. **Stop the container:**
   ```bash
   docker-compose down
   ```
   Or:
   ```bash
   docker compose down
   ```

## Development Mode

To enable live file editing (without rebuilding), uncomment the volume mounts in `docker-compose.yml`:

```yaml
volumes:
  - ./static:/app/static:ro
  - ./templates:/app/templates:ro
```

Then restart:
```bash
docker-compose restart
```

## Testing with Sample Data

If you have sample nfdump data, place it in `./sample_data/` directory. The container will mount it at `/var/cache/nfdump`.

## Database Persistence

Database files are stored in `./data/` directory and persist across container restarts.

## Troubleshooting

- **Port already in use:** Change the port in `docker-compose.yml` (e.g., `"8081:8080"`)
- **Container won't start:** Check logs with `docker-compose logs`
- **No data showing:** Ensure nfdump data is available or the app is configured for demo mode

## Production vs Local

This Docker setup matches the production environment:
- Python 3.11
- Gunicorn with same configuration
- nfdump tools installed
- Same port (8080)
