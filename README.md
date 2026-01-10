# PROX_NFDUMP

NetFlow Analytics Dashboard for Proxmox LXC 122 - Real-time network traffic monitoring using nfdump, Flask, GeoIP, and threat intelligence.

## 🚀 Features

### Real-Time Monitoring
- **Live Dashboard** with Alpine.js and Cyberpunk Glassmorphism theme
- **Bandwidth Analytics** with 5-minute granular caching
- **Top 10 Lists**: Sources, Destinations, Protocols, Ports
- **Geo-Location**: Country and ASN tracking
- **TCP Flags Widget**: Detailed protocol analysis
- **Duration Widget**: Flow timing information
- **SNMP Firewall Monitoring**: Real-time OPNsense health metrics (CPU, Memory, Uptime, Load)

### Threat Intelligence
- **Multi-Feed Support**: Aggregate IPs from multiple threat feeds
  - Emerging Threats Compromised IPs (~500)
  - CINS Score Bad Actors (~15K)
  - Blocklist.de Attack Sources (~23K)
  - FeodoTracker Malware C2 (monitored)
- **Automatic Deduplication**: Set-based IP merging (~38K unique IPs)
- **Per-Feed Error Handling**: Continues if individual feeds fail
- **Real-Time Matching**: Alerts on threat IP detection

### Performance Optimizations
- **60-second Server-Side Caching**: All stats endpoints
- **Granular Bandwidth Caching**: Efficient historical data
- **nfdump Call Consolidation**: Reduced redundant queries
- **Parallel Processing**: ThreadPoolExecutor for concurrent operations
- **Request Coalescing**: Prevents thundering herd problems

### UI/UX
- **Notification Center**: Bell icon with dropdown alerts
- **Alert Dismissal**: Client-side using localStorage  
- **Grouped Alerts**: By severity (Critical, High, Medium, Low)
- **Dark Glass Theme**: Neon accents with condensed tables
- **Actions Menu**: Integrated controls

## 📋 Requirements

### System
- Proxmox LXC container
- Debian/Ubuntu-based Linux
- Network access for NetFlow data collection

### Software Dependencies
```bash
apt-get update
apt-get install -y nfdump python3 python3-pip python3-dnspython git snmp python3-pysnmp4
```

### Python Packages
```bash
pip3 install flask maxminddb requests
```

### GeoIP Databases
```bash
mkdir -p /usr/share/GeoIP
cd /usr/share/GeoIP
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
```

## 🔧 Installation

### 1. Clone Repository
```bash
cd /root
git clone https://github.com/legato3/PROX_NFDUMP.git
cd PROX_NFDUMP
```

### 2. Deploy Files
```bash
cp netflow-dashboard.py /root/
cp threat-feeds.txt /root/
cp -r static templates /root/
```

### 3. Configure Threat Feeds (Optional)
Edit `/root/threat-feeds.txt` to customize threat intelligence sources.

### 4. Install Systemd Service
```bash
cp netflow-dashboard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable netflow-dashboard.service
systemctl start netflow-dashboard.service
```

## 🌐 Access

Dashboard: `http://<LXC-IP>:8080`

## 📊 Key API Endpoints

- `/api/stats/summary` - Overview statistics
- `/api/stats/sources` - Top source IPs
- `/api/stats/destinations` - Top destination IPs  
- `/api/bandwidth` - Bandwidth time series
- `/api/stats/firewall` - Firewall health metrics (SNMP)
- `/api/alerts_history` - Historical alerts
- `/api/thresholds` - GET current alert thresholds / POST to update

## 🔍 Sample Data

The `sample_data/` directory contains real NetFlow examples and format documentation to help AI agents understand data structures.

## 🎯 Recent Updates

### v2.4 - January 10, 2026

- **Security Center Enhancements**: 3 new widgets + 8 detection algorithms
  - Attack Timeline: 24h hourly breakdown chart
  - MITRE ATT&CK Heatmap: Technique coverage visualization
  - Protocol Anomalies: Deviation detection with baseline tracking
- **Advanced Detection Algorithms**:
  - Port Scan Detection (T1046)
  - Brute Force Detection (T1110)
  - Data Exfiltration (T1041)
  - DNS Tunneling (T1071.004)
  - Lateral Movement (T1021)
  - Protocol Anomalies (T1095)
  - Off-Hours Activity (T1029)
  - New External Connections
- **Enhanced Existing Widgets**:
  - Security Score with trend indicator (↑/↓)
  - Alert History with severity/type filtering
  - Threat Detections with block button
- **Bug Fix**: Network Risk Index calculation error resolved

### v2.3 - January 10, 2026

- Configuration Settings modal for DNS, SNMP, paths
- Clickable Firewall Health widgets with detail modals
- Feed Health widget optimization

### v2.2 - January 9, 2026

- Advanced SNMP widgets: real-time WAN/LAN Mbps, utilization, swap usage
- Interface error/discard rates with WARN/ALERT highlighting
- TCP reliability (fails/s, retrans/s) and UDP rate widgets
- User-editable thresholds with persistence (`/api/thresholds` + modal)
- Env var overrides for SNMP and config paths

### v2.1 - January 9, 2026

- **SNMP Firewall Monitoring**: Integrated OPNsense health metrics
- **Firewall Dashboard Widgets**: CPU, Memory, Uptime, Load Average
- **Auto-Formatted Uptime**: Human-readable display (e.g., "17h 44m")
- **30-Second SNMP Cache**: Optimized polling with thread-safe locking

### v2.0 - January 2026

- **Notification Center**: Header-based alert dropdown
- **CPU Optimization**: Granular caching, nfdump consolidation
- **Multi-Feed Support**: Aggregate ~38K threat IPs from 4 sources
- **Performance**: 60s caching, parallel processing
- **UI Modernization**: Alpine.js, Cyberpunk theme
- **New Widgets**: TCP Flags, ASN, Duration analysis

## 🤝 Contributing

See `sample_data/README.md` for data format documentation.

## 🔗 Repository

https://github.com/legato3/PROX_NFDUMP

## ⚙️ Environment Variables

The dashboard supports configuration via environment variables:

- `SNMP_HOST` (default: 192.168.0.1)
- `SNMP_COMMUNITY` (default: Phoboshomesnmp_3)
- `DNS_SERVER` (default: 192.168.0.6)
- `SMTP_CFG_PATH` (default: /root/netflow-smtp.json)
- `NOTIFY_CFG_PATH` (default: /root/netflow-notify.json)
- `THRESHOLDS_CFG_PATH` (default: /root/netflow-thresholds.json)

Thresholds API payload example (POST /api/thresholds):
```json
{
  "util_warn": 70, "util_crit": 90,
  "resets_warn": 0.1, "resets_crit": 1.0,
  "ip_err_warn": 0.1, "ip_err_crit": 1.0,
  "icmp_err_warn": 0.1, "icmp_err_crit": 1.0,
  "if_err_warn": 0.1, "if_err_crit": 1.0,
  "tcp_fails_warn": 0.5, "tcp_fails_crit": 2.0,
  "tcp_retrans_warn": 1.0, "tcp_retrans_crit": 5.0
}
```
