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

- **[DOCKER.md](DOCKER.md)** - Comprehensive Docker documentation and usage guide
- **[DEPLOY_PRODUCTION.md](DEPLOY_PRODUCTION.md)** - Quick deployment guide for PROX-DOCKER-2
- **[../docs/DEPLOYMENT_DOCKER.md](../docs/DEPLOYMENT_DOCKER.md)** - Complete Docker deployment instructions

## Quick Reference

- **Local Development**: `docker compose -f docker/docker-compose.yml up -d`
- **Dashboard URL**: http://localhost:3434
- **Production Server**: PROX-DOCKER-2 (192.168.0.73:3434)
- **Ports**: 3434 (HTTP), 514 (UDP Syslog), 2055 (UDP NetFlow)
