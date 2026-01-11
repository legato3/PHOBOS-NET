# Docker Deployment Guide - Replacing LXC Systemd Service

This guide explains how to migrate from the systemd service to Docker on your Proxmox LXC container.

## Prerequisites

1. Docker and Docker Compose installed on LXC container 122
2. Backup of current data (databases, nfdump files)
3. Access to Proxmox host (192.168.0.70)

## Migration Steps

### 1. Install Docker on LXC Container

```bash
# From Proxmox host
pct exec 122 -- bash -c '
    # Update package list
    apt-get update
    
    # Install Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    
    # Install Docker Compose (plugin)
    apt-get install -y docker-compose-plugin
    
    # Verify installation
    docker --version
    docker compose version
'
```

### 2. Stop Current Service

```bash
pct exec 122 -- systemctl stop netflow-dashboard
pct exec 122 -- systemctl disable netflow-dashboard
```

### 3. Prepare Data Directories

```bash
pct exec 122 -- bash -c '
    cd /root
    
    # Create data directory if it doesn't exist
    mkdir -p data
    
    # Ensure proper permissions
    chmod 755 data
    chmod 644 firewall.db netflow-trends.sqlite threat-feeds.txt 2>/dev/null || true
'
```

### 4. Deploy Docker Setup

```bash
# From your local machine (or clone on server)
# Copy Docker files to server
pct exec 122 -- bash -c '
    cd /root
    
    # If using git (recommended)
    # git clone <repo> /tmp/repo
    # cp /tmp/repo/Dockerfile /tmp/repo/docker-compose.prod.yml /tmp/repo/netflow_dashboard.py .
    
    # Or manually copy files (see deployment script)
'
```

### 5. Build and Start Docker Container

```bash
pct exec 122 -- bash -c '
    cd /root
    docker compose -f docker-compose.prod.yml build
    docker compose -f docker-compose.prod.yml up -d
'
```

### 6. Verify Deployment

```bash
# Check container status
pct exec 122 -- docker compose -f docker-compose.prod.yml ps

# Check logs
pct exec 122 -- docker compose -f docker-compose.prod.yml logs -f

# Test health endpoint
curl http://localhost:8080/health
```

### 7. Update Deployment Script (Optional)

Create a deployment script that uses Docker instead of systemd:

```bash
#!/bin/bash
# deploy-docker.sh

pct exec 122 -- bash -c "
    cd /root
    git pull  # if using git
    docker compose -f docker-compose.prod.yml build
    docker compose -f docker-compose.prod.yml up -d --force-recreate
    docker compose -f docker-compose.prod.yml logs --tail=50
"
```

## Data Persistence

All critical data is persisted via volumes:
- `/var/cache/nfdump` - NetFlow data files
- `./data/` - Application data
- `./firewall.db` - Firewall logs database
- `./netflow-trends.sqlite` - NetFlow trends database
- `./threat-feeds.txt` - Threat feed configuration
- `./threat-ips.txt` - Threat IP cache

## Rollback Plan

If you need to rollback to systemd:

```bash
pct exec 122 -- bash -c '
    # Stop Docker container
    docker compose -f docker-compose.prod.yml down
    
    # Restart systemd service
    systemctl start netflow-dashboard
    systemctl enable netflow-dashboard
'
```

## Maintenance Commands

```bash
# View logs
pct exec 122 -- docker compose -f docker-compose.prod.yml logs -f

# Restart container
pct exec 122 -- docker compose -f docker-compose.prod.yml restart

# Update and redeploy
pct exec 122 -- bash -c '
    cd /root
    docker compose -f docker-compose.prod.yml build
    docker compose -f docker-compose.prod.yml up -d
'

# Stop container
pct exec 122 -- docker compose -f docker-compose.prod.yml down
```

## Benefits of Docker Deployment

1. **Consistency**: Same environment across dev and prod
2. **Isolation**: Better resource management
3. **Easier Updates**: Rebuild and redeploy
4. **Portability**: Can move to different hosts easily
5. **Version Control**: Docker images are versioned

## Resource Limits

The Docker compose file includes resource limits matching your LXC constraints:
- CPU: 4 cores
- Memory: 512MB max, 256MB reserved

Adjust these in `docker-compose.prod.yml` if needed.
