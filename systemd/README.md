# Systemd Service Files

Systemd service definitions for the NetFlow dashboard.

## Service Files

- **netflow-dashboard.service** - Basic systemd service (development/testing)
- **netflow-dashboard-optimized.service** - Production-optimized service with Gunicorn, resource limits, and restart policies

## Installation

### Development/Testing
```bash
cp netflow-dashboard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable netflow-dashboard.service
systemctl start netflow-dashboard.service
```

### Production
```bash
cp netflow-dashboard-optimized.service /etc/systemd/system/netflow-dashboard.service
systemctl daemon-reload
systemctl enable netflow-dashboard.service
systemctl start netflow-dashboard.service
```

## Configuration

For production deployment, see:
- [../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) - Deployment guide
- [../docs/ENVIRONMENT_OPTIMIZATION.md](../docs/ENVIRONMENT_OPTIMIZATION.md) - Environment optimization
- [../scripts/gunicorn_config.py](../scripts/gunicorn_config.py) - Gunicorn configuration
