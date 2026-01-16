# PHOBOS-NET

**PHOBOS-NET v1.0** - Real-time network traffic monitoring dashboard for Proxmox LXC 122 using nfdump, Flask, GeoIP, and threat intelligence.

*Note: PROX_NFDUMP is the repository name. The application is branded as PHOBOS-NET.*

## 🚀 Features

### Real-Time Monitoring
- **Live Dashboard** with Alpine.js and TrueNAS-style theme
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

### Security Center
- **Risk Index**: Real-time network risk scoring (0-100) based on traffic patterns
- **MITRE ATT&CK**: Heatmap visualization of detected techniques
- **Attack Timeline**: 24-hour hourly breakdown of security events
- **Anomaly Detection**:
  - Port Scans & Brute Force
  - Data Exfiltration
  - DNS Tunneling
  - Lateral Movement
  - Protocol Anomalies
  - Off-Hours Activity

### Firewall
- **Flow Search**: Advanced multi-criteria search for investigation
- **Alert Correlation**: Group related alerts into attack chains
- **IP Investigation**: Detailed IP drill-down with traffic patterns and related IPs

### AI Assistant
- **Integrated Chat**: DeepSeek Coder v2 integration via Ollama
- **Context Aware**: Helper for analyzing network patterns and explaining alerts
- **Streaming Support**: Real-time response streaming

### Performance Optimizations
- **Asset Minification**: 38% smaller CSS/JS (-90 KB total)
- **60-second Server-Side Caching**: All stats endpoints
- **Granular Bandwidth Caching**: Efficient historical data
- **Batch API**: Fetch multiple datasets in a single HTTP request
- **nfdump Call Consolidation**: Reduced redundant queries
- **Parallel Processing**: ThreadPoolExecutor for concurrent operations
- **Request Coalescing**: Prevents thundering herd problems
- **Service Worker**: Offline-first PWA with smart caching
- **Lazy Loading**: Intersection Observer for on-demand data fetching
- **Resource Hints**: Preconnect and DNS prefetch for external resources

### Accessibility (WCAG 2.1 Level AA)
- **Keyboard Navigation**: Skip links, focus indicators, documented shortcuts
- **Screen Reader Support**: ARIA labels, roles, and states
- **Semantic HTML5**: Proper landmarks and heading hierarchy
- **Reduced Motion**: Respects user preference for animations
- **Mobile-First Design**: Touch-friendly 44px minimum targets

### UI/UX
- **Notification Center**: Bell icon with dropdown alerts
- **Alert Dismissal**: Client-side using localStorage  
- **Grouped Alerts**: By severity (Critical, High, Medium, Low)
- **TrueNAS-Style Theme**: Clean interface with TrueNAS blue accents and condensed tables
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
# Optional: deploy the modular runtime to a system directory
mkdir -p /root/netflow-dashboard
cp -r app frontend scripts threat-feeds.txt /root/netflow-dashboard/
```

### 3. Configure Threat Feeds (Optional)
Edit `/root/threat-feeds.txt` to customize threat intelligence sources.

### 4. Install Systemd Service
```bash
cp systemd/netflow-dashboard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable netflow-dashboard.service
systemctl start netflow-dashboard.service
```

For production deployment with Gunicorn, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and [docs/ENVIRONMENT_OPTIMIZATION.md](docs/ENVIRONMENT_OPTIMIZATION.md).

## 🌐 Access

Dashboard: `http://<LXC-IP>:8080`

## 📊 Key API Endpoints

### Core Statistics
- `/api/stats/summary` - Overview statistics
- `/api/stats/sources` - Top source IPs
- `/api/stats/destinations` - Top destination IPs
- `/api/stats/ports` - Top ports
- `/api/stats/protocols` - Protocol usage
- `/api/bandwidth` - Bandwidth time series

### Security Center
- `/api/security/score` - Current security score (0-100)
- `/api/security/risk_index` - Detailed risk factors
- `/api/security/mitre-heatmap` - MITRE ATT&CK coverage
- `/api/security/attack-timeline` - 24h attack timeline
- `/api/stats/threats` - Active detected threats

### Firewall
- `/api/forensics/flow-search` - Search flows by IP, port, protocol
- `/api/forensics/alert_correlation` - Correlated alert chains
- `/api/ip_detail/<ip>` - Deep dive IP investigation

### Firewall Integration
- `/api/stats/firewall` - Health metrics (SNMP)
- `/api/firewall/logs/stats` - Block statistics
- `/api/firewall/logs/recent` - Recent block logs

### AI Assistant
- `/api/ollama/chat` - Chat interface with LLM
- `/api/ollama/models` - Available models

### System & Performance
- `/api/performance/metrics` - Performance and observability metrics (see Observability section below)
- `/api/server/health` - Dashboard server health
- `/api/stats/batch` - Batch data fetching
- `/api/performance/metrics` - API latency and cache stats
- `/health` - Service health check
- `/metrics` - Prometheus metrics

## 🔍 Sample Data

The `sample_data/` directory contains real NetFlow examples and format documentation to help AI agents understand data structures.

## 📋 Release Notes

For detailed release notes and version history, see **[docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md)**.

**v1.0** (Stable) - Production-ready investigation platform with trust-first design, explainable health states, and adaptive baselines. See release notes for complete details.

## 🎯 Recent Updates

### v2.7 - January 11, 2026

- **Logging & Monitoring Improvements**:
  - NetFlow 7-day retention policy (automatic cleanup via nfexpire)
  - Syslog batch inserts (10-50x performance improvement)
  - Disk space monitoring with alerts
  - Health check endpoint (`/health`) for monitoring
  - Database optimization (weekly VACUUM only)
- **Repository Organization**: Documentation and scripts organized into `docs/` and `scripts/` directories

### v2.6 - January 10, 2026

- **Analytics Section Expansion**: 3 new widgets (11 total)
  - Flow Statistics: Total flows, avg duration, avg size, bytes/packet, duration distribution bars
  - Protocol Mix: Doughnut chart visualization of protocol traffic
  - Network Health: Health score (0-100) with indicators for TCP resets, SYN-only flows, ICMP traffic, tiny flows
- **Enhanced Long Flows Widget**:
  - Stats summary (longest, average, total flows)
  - Visual duration bars with percentage
  - Protocol name display
  - Bytes transferred per flow
  - Hostname resolution
  - Helpful explanation tooltip

### v2.5 - January 10, 2026

- **Top Stats Section Expansion**: 3 new widgets (8 total)
  - Top Talkers: Source→Destination IP pairs with highest traffic
  - Top Services: Traffic by service name (aggregated from ports)
  - Traffic by Hour: 24-hour distribution chart with peak hour indicator
- Sources and Destinations now appear first in the grid

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
- **UI Modernization**: Alpine.js, TrueNAS-style theme
- **New Widgets**: TCP Flags, ASN, Duration analysis

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and [sample_data/README.md](sample_data/README.md) for data format documentation.

## 🔗 Repository

https://github.com/legato3/PROX_NFDUMP

## 📊 Observability & Performance Metrics

The dashboard includes lightweight observability instrumentation to monitor performance without changing behavior.

### Metrics Endpoint

Access metrics via `/api/performance/metrics`:

```json
{
  "summary": {
    "total_requests": 1234,
    "avg_response_time_ms": 45.2,
    "error_count": 5,
    "error_rate_percent": 0.41,
    "cache_hit_rate_percent": 85.3,
    "cache_hits": 1053,
    "cache_misses": 181,
    "slow_requests": 12
  },
  "endpoints": {
    "api_stats_summary": {
      "count": 150,
      "avg_ms": 32.1,
      "min_ms": 15.2,
      "max_ms": 245.8,
      "p95_ms": 89.5
    }
  },
  "subprocess": {
    "total_calls": 542,
    "success_count": 538,
    "failure_count": 3,
    "timeout_count": 1,
    "avg_ms": 123.4,
    "max_ms": 3421.0,
    "p95_ms": 456.7,
    "success_rate_percent": 99.26
  },
  "services": {
    "calculate_security_score": {
      "call_count": 89,
      "avg_ms": 12.3,
      "total_time_ms": 1094.7,
      "min_ms": 8.1,
      "max_ms": 45.6,
      "p95_ms": 22.4
    },
    "run_all_detections": {
      "call_count": 42,
      "avg_ms": 234.5,
      "total_time_ms": 9849.0,
      "min_ms": 156.2,
      "max_ms": 567.8,
      "p95_ms": 412.3
    },
    "get_snmp_data": {
      "call_count": 120,
      "avg_ms": 45.6,
      "total_time_ms": 5472.0,
      "min_ms": 23.1,
      "max_ms": 234.5,
      "p95_ms": 89.2
    }
  }
}
```

### Tracked Metrics

1. **API Request Metrics**
   - Request count, average response time, error rate
   - Per-endpoint statistics (avg, min, max, p95)
   - Slow request count (>1s by default)

2. **Subprocess Metrics** (nfdump calls)
   - Total calls, success/failure/timeout counts
   - Execution time statistics
   - Success rate

3. **Service Function Metrics**
   - Execution time for hot paths:
     - `calculate_security_score()` - Security score calculation
     - `run_all_detections()` - Threat detection orchestration
     - `get_snmp_data()` - SNMP polling

4. **Cache Metrics**
   - Cache hit/miss counts and rates

### Guardrails & Warnings

The system logs warnings when performance thresholds are exceeded:

- **Subprocess warnings**: When nfdump execution exceeds threshold (default: 5000ms)
- **Cache miss rate warnings**: When cache miss rate exceeds threshold (default: 50%)
- **Slow request warnings**: When API routes exceed threshold (default: 2000ms)
- **Service function warnings**: When service functions exceed threshold (default: 500ms)

### Configuration

Thresholds are configurable via environment variables:

```bash
export OBS_NFDUMP_WARN_MS=5000          # Warn if nfdump > 5s
export OBS_CACHE_MISS_RATE_WARN=0.5     # Warn if cache miss rate > 50%
export OBS_ROUTE_SLOW_MS=1000           # Flag route as slow if > 1s
export OBS_ROUTE_SLOW_WARN_MS=2000      # Warn if route > 2s
export OBS_SERVICE_SLOW_MS=500          # Warn if service function > 500ms
```

Warnings are logged to stderr with `[OBSERVABILITY]` prefix and can be redirected to log files.

### Implementation Notes

- All instrumentation is **passive** - does not modify application behavior
- Metrics are thread-safe using locks
- Low overhead - minimal performance impact (<1% typical)
- No external dependencies - uses Python standard library logging
- Metrics are additive - existing functionality unchanged

---

## ⚙️ Environment Variables

The dashboard supports configuration via environment variables:

### Core Configuration
- `SNMP_HOST` (default: 192.168.0.1)
- `SNMP_COMMUNITY` (default: Phoboshomesnmp_3)
- `DNS_SERVER` (default: 192.168.0.6)
- `OLLAMA_URL` (default: http://192.168.0.88:11434)
- `SMTP_CFG_PATH` (default: /root/netflow-smtp.json)
- `NOTIFY_CFG_PATH` (default: /root/netflow-notify.json)
- `THRESHOLDS_CFG_PATH` (default: /root/netflow-thresholds.json)
- `FIREWALL_DB_PATH` (default: /root/firewall.db)

### Observability Thresholds
- `OBS_NFDUMP_WARN_MS` (default: 5000) - Warn if nfdump execution > 5s
- `OBS_CACHE_MISS_RATE_WARN` (default: 0.5) - Warn if cache miss rate > 50%
- `OBS_ROUTE_SLOW_MS` (default: 1000) - Flag route as slow if > 1s
- `OBS_ROUTE_SLOW_WARN_MS` (default: 2000) - Warn if route > 2s
- `OBS_SERVICE_SLOW_MS` (default: 500) - Warn if service function > 500ms

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

## 📚 Documentation

See the **[docs/](docs/)** directory for comprehensive documentation:

- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Deployment instructions
- **[docs/AGENTS.md](docs/AGENTS.md)** - Architecture guide for developers/AI agents
- **[docs/PERFORMANCE.md](docs/PERFORMANCE.md)** - Performance optimization guide
- **[docs/NFCAPD_SETUP.md](docs/NFCAPD_SETUP.md)** - NetFlow collector setup
- **[docs/SYSLOG_INTEGRATION.md](docs/SYSLOG_INTEGRATION.md)** - Firewall syslog integration
- **[docs/LOGGING_IMPROVEMENTS.md](docs/LOGGING_IMPROVEMENTS.md)** - Logging and monitoring improvements
- **[sample_data/README.md](sample_data/README.md)** - Data format documentation

For a complete list, see [docs/README.md](docs/README.md).

## 🎯 Performance Metrics

### File Sizes (Production)
- **CSS**: 113 KB → 79 KB (-30.5%)
- **JavaScript**: 122 KB → 68 KB (-44%)
- **Service Worker**: 4 KB → 2 KB (-52.4%)
- **Total Reduction**: 90 KB (-38%)

### Load Times
- **First Paint**: ~800ms
- **Time to Interactive**: ~1.2s
- **Full Load**: ~2.5s

### Accessibility Score
- **WCAG 2.1 Level AA Compliant**
- **24/24 Validation Tests Passed**
