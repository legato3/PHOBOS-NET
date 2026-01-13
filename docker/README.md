# Docker Setup

This directory contains all Docker-related files for running the NetFlow Dashboard in a containerized environment.

## Files

- **Dockerfile** - Container image definition
- **docker-compose.yml** - Docker Compose configuration
- **docker-entrypoint.sh** - Entrypoint script that starts nfcapd and Gunicorn
- **DOCKER.md** - Comprehensive Docker documentation and usage guide
- **.dockerignore** - Files to exclude from Docker build context

## Quick Start

From the project root directory:

```bash
cd docker
docker-compose up -d --build
```

Or from the project root:

```bash
docker-compose -f docker/docker-compose.yml up -d --build
```

## Documentation

See [DOCKER.md](DOCKER.md) for detailed usage instructions, configuration options, and troubleshooting.
