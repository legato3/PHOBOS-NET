# PROX_NFDUMP - NetFlow Analytics Dashboard

Real-time network traffic monitoring dashboard for Proxmox LXC using nfdump and Flask.

## Overview

This dashboard provides real-time visualization of NetFlow data captured from network traffic. It's designed to run in **Proxmox LXC 122** (PROX-NFDUMP) and displays:

- **Real-time bandwidth monitoring** with historical graphs
- **Top traffic sources and destinations** with DNS and GeoIP resolution
- **Protocol distribution analysis** (TCP, UDP, ICMP, etc.)
- **Port and service usage statistics**
- **Active network conversations** between hosts
- **Threat detection** using IP reputation feeds
- **Email/webhook alerts** for suspicious activity

## Features

- 🚀 **Optimized Performance**: Aggressive caching and rate limiting to minimize CPU usage
- 📊 **Interactive Charts**: Real-time bandwidth and flow rate visualization using Chart.js
- 🔍 **DNS Resolution**: Automatic hostname resolution with caching
- 🌍 **GeoIP Lookup**: Country/city/ASN detection using MaxMind GeoLite2 databases
- 🎯 **Service Detection**: Automatic identification of common network services
- 🛡️ **Threat Intelligence**: Integration with IP threat feeds
- 📧 **Alerting**: Email and webhook notifications for suspicious activity
- 🔄 **Auto-refresh**: Dashboard updates every 30 seconds
- 🎨 **Modern UI**: Responsive design with gradient styling

## Requirements

- Debian/Ubuntu Linux (tested on Debian in Proxmox LXC)
- nfdump (for NetFlow data processing)
- Python 3.7+
- Flask
- maxminddb (for GeoIP)
- requests (for threat feeds)
- Network traffic mirrored to the container

## Installation

### 1. Install Dependencies

```bash
apt-get update
apt-get install -y nfdump python3 python3-pip git
pip3 install flask maxminddb requests
```

### 2. Setup nfdump Data Collection

Ensure nfdump is collecting NetFlow data to `/var/cache/nfdump`:

```bash
mkdir -p /var/cache/nfdump
# Configure your NetFlow collector (e.g., nfcapd, softflowd, etc.)
```

### 3. Download GeoIP Databases

Download MaxMind GeoLite2 databases:

```bash
cd /root
# Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind
# Place them in /root/
```

### 4. Deploy the Dashboard

```bash
# Clone this repository
git clone https://github.com/legato3/PROX_NFDUMP.git
cd PROX_NFDUMP

# Copy files to /root
cp netflow-dashboard.py /root/
chmod +x /root/netflow-dashboard.py

# Optional: Configure SMTP for email alerts
cp netflow-smtp.json.example /root/netflow-smtp.json
# Edit with your SMTP settings
```

### 5. Run the Dashboard

**Manual Start:**
```bash
python3 /root/netflow-dashboard.py
```

**Systemd Service (recommended):**
```bash
cat > /etc/systemd/system/netflow-dashboard.service << 'EOL'
[Unit]
Description=NetFlow Analytics Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /root/netflow-dashboard.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable netflow-dashboard
systemctl start netflow-dashboard
```

**Access the dashboard:**
Open your browser to `http://<LXC-IP>:8080`

## Configuration

### DNS Server
The dashboard uses DNS server for reverse lookups. Default is `192.168.0.1`. Modify in the code:

```python
DNS_SERVER = "192.168.0.1"
```

### Email Alerts (netflow-smtp.json)
```json
{
  "host": "smtp.gmail.com",
  "port": 587,
  "user": "your-email@gmail.com",
  "password": "your-app-password",
  "from": "your-email@gmail.com",
  "to": ["recipient@gmail.com"],
  "use_tls": true
}
```

**Note:** For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833).

### Threat Intelligence
Create `/root/threat-feed.url` with a URL to an IP threat feed:

```
https://example.com/threat-feed.txt
```

The dashboard will download and check IPs against this list.

## API Endpoints

- `GET /` - Main dashboard UI
- `GET /api/overview` - Traffic statistics (cached 30s)
- `GET /api/bandwidth` - Bandwidth time series (cached 60s)
- `GET /api/conversations` - Top network conversations (cached 60s)
- `GET /api/ip-detail/<ip>` - Detailed info about specific IP
- `GET /api/sparklines` - Sparkline data for trending
- `GET /api/metrics` - Dashboard performance metrics
- `GET /api/alerts` - Recent security alerts

All API endpoints include rate limiting to prevent abuse.

## License

MIT License - Feel free to modify and distribute.

## Credits

Developed for Proxmox homelab network monitoring in LXC 122 (PROX-NFDUMP).

Co-Authored-By: Warp <agent@warp.dev>