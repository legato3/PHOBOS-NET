# Scripts Directory

Utility scripts for deployment, maintenance, and development.

## Deployment Scripts

- **deploy.sh** - Quick deployment script for Proxmox LXC containers
- **optimize_environment.sh** - Automated environment optimization (Gunicorn, systemd, resource limits)

## Maintenance Scripts

- **nfcapd-retention.sh** - NetFlow data retention cleanup script (7-day retention)

## Development Scripts

- **minify.py** - CSS/JS minification tool
- **test_html_validation.py** - HTML validation testing
- **verify_map.py** - Map visualization verification

## Configuration Files

- **gunicorn_config.py** - Gunicorn WSGI server configuration
- **netflow-smtp.json.example** - SMTP configuration template

## Usage

See [../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) for deployment instructions.
See [../docs/LOGGING_IMPROVEMENTS.md](../docs/LOGGING_IMPROVEMENTS.md) for retention script usage.
