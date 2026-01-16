# AGENTS.md - Guide for AI Coding Agents

This document helps AI agents (like Jules) understand the PROX_NFDUMP project structure, data flows, and conventions.

## 🏗️ Project Architecture

### Component Overview
```
PROX_NFDUMP/
├── app/                      # Flask backend (modular application)
├── frontend/
│   ├── static/               # Alpine.js frontend logic
│   └── templates/            # Single-page dashboard UI
├── threat-feeds.txt          # Multi-feed configuration
├── sample_data/              # Real data examples for reference
└── systemd/netflow-dashboard.service # Systemd service definition
```

### Technology Stack
- **Backend**: Flask (Python 3)
- **Frontend**: Alpine.js (reactive framework)
- **Data Source**: nfdump (NetFlow collector)
- **Styling**: Custom CSS with TrueNAS-style theme
- **Deployment**: Systemd service on Debian/Ubuntu LXC

## 📊 Data Flow

### 1. NetFlow Collection
```
Router/Switch → nfcapd (port 2055) → /var/cache/nfdump/
```

### 2. Query Processing
```
API Request → Flask Route → nfdump CLI → CSV Parser → JSON Response
```

### 3. Threat Intelligence
```
External Feeds → fetch_threat_feed() → /root/threat-ips.txt → Alert Detection
```

### 4. AI Assistant
```
Frontend Chat → /api/ollama/chat → Ollama Instance (DeepSeek Coder) → Streaming Response
```

### 5. Security Center
```
NetFlow/Syslog Data → Anomaly Detection Algorithms → /api/security/* → Risk Score & Alerts
```

### 6. Firewall
```
Investigator → /api/forensics/* → Advanced Search & Correlation → Attack Chains
```

## 🔍 Key Data Formats

### nfdump CSV Output
See `sample_data/nfdump_flows.csv` for real examples.

**Critical**: Column order can vary! Always use header detection:
```python
def parse_csv(output):
    lines = output.strip().split('\n')
    header = lines[0].lower()
    cols = [c.strip() for c in header.split(',')]
    src_ip_idx = cols.index('src ip addr')
```

### Threat Feed Format
One IP per line, comments start with #:
```
# Comment line
192.168.1.1
10.0.0.1
```

## 🎯 Critical Functions

### Backend (`app/api/routes.py`)

#### fetch_threat_feed()
- **Purpose**: Download and merge multiple threat feeds
- **Location**: Lines ~348-390
- **Key Feature**: Multi-feed support via `/root/threat-feeds.txt`
- **Critical**: Uses set() for deduplication, graceful error handling


#### resolve_hostname()
- **Purpose**: DNS resolution using configured DNS_SERVER
- **Implementation**: Uses dnspython for direct queries (not system resolver)
- **Configuration**: DNS_SERVER variable (default: 192.168.0.6)
- **Timeout**: 1 second for fast responses
- **Fallback**: Returns IP if DNS fails

#### parse_csv()
- **Purpose**: Parse nfdump CSV with dynamic column detection
- **Critical**: ALWAYS check for header row, column order varies
- **Common Mistake**: Hardcoding column indices breaks
- **Deduplication**: Skips duplicate headers and keys (nfdump can return duplicates)

#### get_common_nfdump_data()
- **Purpose**: Fetch and cache traffic statistics
- **Strategy**: Fetch 100 entries, sort by bytes, display top 10
- **Why**: nfdump's `-n` flag limits early in aggregation, misses data
- **Sorting**: Always sort by bytes descending for accurate top results

#### API Routes with Caching
- **Pattern**: All `/api/stats/*` endpoints use 60-second cache
- **Implementation**: threading.Lock for thread-safe cache
- **Key**: Cache keys aligned to 60s windows for better hit rates

#### Detection Algorithms
- **Location**: `run_all_detections` and `detect_*` functions
- **Purpose**: Analyze traffic for specific threat patterns (Scan, Exfil, Tunneling, etc.)
- **Output**: Generates alerts stored in `_alert_history`

## 🚨 Common Pitfalls

### 1. Column Index Assumptions
❌ Don't do: `src_ip = parts[3]` (hardcoded index)
✅ Do: `src_ip_idx = header.index('src ip addr')`

### 2. Threat Feed Handling
- Support multi-feed (not just single URL)
- Handle individual feed failures gracefully
- Use set() for deduplication across feeds

### 3. Cache Invalidation
- Cache keys must be deterministic
- Use time-based alignment (60s windows)
- Threading.Lock for concurrent access

### 4. Error Handling
- nfdump can return empty results (not an error)
- Threat feeds can timeout (continue with others)
- DNS lookups can fail (use IP fallback)

## 🔧 Development Guidelines

### Adding New Features

1. **Backend Changes**:
   - Add route to `app/api/routes.py`
   - Implement caching if query is expensive
   - Return consistent JSON format
   - Handle empty results gracefully

2. **Frontend Changes**:
   - Update Alpine.js state in app.js
   - Add API call in parallel fetch
   - Update template in index.html
   - Maintain TrueNAS-style theme in style.css

3. **Testing**:
   - Test with empty nfdump results
   - Test with missing threat feeds
   - Test with high concurrent load
   - Verify caching behavior

### Performance Considerations

- **nfdump calls are expensive**: Cache aggressively
- **Parallel processing**: Use ThreadPoolExecutor
- **Frontend**: Batch API calls with Promise.all() or `/api/stats/batch`
- **Batch API**: Consolidate multiple stats requests into a single HTTP call
- **Avoid**: N+1 queries, redundant nfdump calls

## 📝 Modification Checklist

When modifying code, verify:
- [ ] Column detection works (if touching CSV parsing)
- [ ] Multi-feed support preserved (threat intelligence)
- [ ] Caching logic maintained (API routes)
- [ ] Error handling for empty results
- [ ] No hardcoded IPs/paths
- [ ] Alpine.js reactivity preserved
- [ ] TrueNAS-style theme consistency

## 🧪 Testing with Sample Data

Use `sample_data/` directory:
- `nfdump_flows.csv` - 6,808 real NetFlow records
- `nfdump_stats_example.txt` - Statistical query examples
- `threat_feeds_example.txt` - Threat feed format
- `README.md` - Detailed format documentation

## 🔗 Key External Dependencies

- **nfdump**: CLI tool, output format can change between versions
- **dnspython**: DNS resolution library (apt install python3-dnspython)
- **MaxMind GeoIP**: Database location `/usr/share/GeoIP/*.mmdb`
- **Threat Feeds**: External URLs, may be temporarily unavailable
- **Flask**: Development mode only (use gunicorn for production)
- **Ollama**: Local AI Inference (optional, for Chat Assistant)

## 💡 Pro Tips for AI Agents

1. **Use sample_data/** - Reference real examples before modifying parsers
2. **Check nfdump version** - Output format varies slightly between versions
3. **Test feed failures** - Code should continue if one feed is down
4. **Monitor cache** - Log cache performance in development
5. **Preserve multi-feed** - This is a KEY feature, don't remove it
6. **Dynamic parsing** - Never hardcode CSV column positions
7. **Graceful degradation** - UI should work even if some APIs fail

## 🔥 SNMP Firewall Monitoring

### Overview
- Polls OPNsense firewall (192.168.0.1) via SNMP community "Phoboshomesnmp_3"
- Displays real-time firewall health metrics on dashboard
- 30-second cache with thread-safe locking
- Auto-formats uptime for readability

### Metrics Collected
| Metric | OID | Description |
|--------|-----|-------------|
| CPU Load 1min | `.1.3.6.1.4.1.2021.10.1.3.1` | 1-minute load average |
| CPU Load 5min | `.1.3.6.1.4.1.2021.10.1.3.2` | 5-minute load average |
| Memory Total | `.1.3.6.1.4.1.2021.4.5.0` | Total memory (KB) |
| Memory Available | `.1.3.6.1.4.1.2021.4.6.0` | Available memory (KB) |
| System Uptime | `.1.3.6.1.2.1.1.3.0` | System uptime timeticks |

### Dashboard Widgets
- **CPU Usage**: Shows percentage (derived from load average) + 1-min load
- **Memory**: Shows percentage + used/total in human-readable format
- **Uptime**: Formatted as "17h 44m" instead of raw "0:17:44:05.92"
- **5min Load**: Shows 5-minute load average for trend analysis

### API Endpoint
```
GET /api/stats/firewall?range={timerange}
```
Returns JSON with firewall health metrics including formatted uptime.

### Dependencies
```bash
apt-get install snmp python3-pysnmp4
```

## 🎨 UI/UX Guidelines

### TrueNAS-Style Theme
- Dark blue-grey backgrounds with TrueNAS blue accents (#00a2ff)
- Clean, professional interface design
- Monospace fonts for data tables
- Condensed tables (Top 10 items)
- Responsive bell icon for notifications

### Alpine.js Patterns
- Use `x-data` for component state
- `x-show` for conditional rendering
- `@click` for event handlers
- `:class` for dynamic styling
- Keep reactivity intact when modifying

### Mobile-First Responsive Design
- **Breakpoints**: 1024px (tablet), 768px (mobile), 480px (small mobile)
- **Mobile Bottom Nav**: Fixed 5-button navigation (Overview, Security, Pause, Refresh, Settings)
- **Mobile Stats Bar**: Horizontal scrollable quick stats (CPU, MEM, Threats, Flows, Status)
- **Collapsible Controls**: Filter toggle button hides/shows header controls
- **Touch Targets**: Minimum 44px for all interactive elements
- **Safe Areas**: Supports notched phones (iPhone X+) with `env(safe-area-inset-*)`
- **PWA Ready**: Meta tags for home screen install on iOS/Android

### Responsive Considerations
- Single column layouts on mobile
- Horizontal scrolling tables with swipe support
- Security Center full-width on mobile
- Activity feed compact layout
- Score widget centered and stacked
- `prefers-reduced-motion` accessibility support
- Print styles for report generation

## 📚 Architecture Decisions

### Why Multi-Feed?
- Broader threat coverage (~38K IPs vs ~500)
- Resilience to individual feed failures
- Different feeds have different specialties
- Easy to add/remove feeds via config file

### Why 60-Second Cache?
- Balance between freshness and performance
- Reduces CPU load significantly
- NetFlow data doesn't change that rapidly
- Window alignment improves cache hits

### Why Alpine.js?
- Lightweight (no build step required)
- Reactive like Vue but simpler
- Perfect for single-page dashboards
- Easy to understand and modify

## 🎛️ Widget Inventory

### Analytics Section (11 widgets)
- **Summary Stats** - Total traffic, flows, avg packet size
- **Bandwidth & Flow Rate** - Time-series chart
- **Firewall Health** - CPU, MEM, Uptime from SNMP
- **TCP Flags** - Flag distribution chart
- **Long Flows** - Enhanced with stats, hostnames, protocol, visual bars, and explanations
- **Packet Sizes** - Packet size distribution chart
- **Protocols** - Protocol breakdown table
- **Traffic Insights** - Dynamic insights about network behavior
- **Flow Statistics** - Avg duration, avg size, bytes/packet, duration distribution
- **Protocol Mix** - Pie chart visualization of protocol traffic
- **Network Health** - Health score (0-100) with indicators (resets, SYN-only, ICMP, tiny flows)

### Top Stats Section (8 widgets)
- **Top Sources** - IP tables with geo, sparklines
- **Top Destinations** - IP tables with geo, sparklines
- **Top Ports** - Port traffic with service names
- **Top ASNs** - Autonomous System traffic bars
- **Top Countries** - Geographic traffic distribution (pie chart)
- **Top Talkers** - Source→Destination IP pairs with highest traffic
- **Top Services** - Traffic by service name (aggregated from ports)
- **Traffic by Hour** - 24-hour traffic distribution chart with peak hour

### Security Center (13 widgets)

- **Security Score** - 0-100 gauge with grade + trend indicator (↑/↓)
- **Alert History (24h)** - Recent alerts with severity/type filtering
- **Threats by Country** - Geo breakdown of threats
- **Threat Detections** - Active threat IP table with block button
- **Feed Health** - Compact 2-column feed status list
- **Top Malicious Ports** - Suspicious port activity
- **Blocklist Match Rate** - Time-series chart
- **Threat Velocity** - Threats/hr with trend
- **Top Threat IPs** - Ranked threat IPs with hits
- **Network Risk Index** - Risk meter with factors
- **Attack Timeline** - 24h stacked bar chart by severity
- **MITRE ATT&CK Heatmap** - Technique coverage visualization
- **Protocol Anomalies** - Protocol deviation detection

### Advanced Detection Algorithms

- **Port Scan Detection** - Detects IPs scanning multiple ports
- **Brute Force Detection** - Monitors auth port connection attempts
- **Data Exfiltration** - Large outbound transfer detection
- **DNS Tunneling** - Abnormal DNS query patterns
- **Lateral Movement** - Internal-to-internal traffic spikes
- **Protocol Anomaly** - Unusual protocol distributions
- **Off-Hours Activity** - After-hours traffic alerts
- **New External Connections** - First-seen country/ASN tracking

## 🔐 Security Considerations

- Threat intelligence updates every 15 minutes
- SMTP credentials in separate config file
- No authentication on dashboard (LXC internal only)
- Threat feeds validated before use
- DNS lookups timeout to prevent hanging
- World map uses `load_threatlist()` to mark threat IPs geographically

## 🔥 Firewall Syslog Integration (NEW)

### Overview
The dashboard can receive and parse OPNsense firewall logs via syslog UDP, providing visibility into blocked connections.

### Architecture
```
OPNsense (192.168.0.1) → UDP 514 → Dashboard (192.168.0.74) → SQLite (firewall.db)
```

### Key Components
- **Syslog Receiver**: `start_syslog_thread()` - UDP server on port 514
- **Log Parser**: `_parse_filterlog()` - Parses OPNsense filterlog format
- **Database**: `/root/firewall.db` - SQLite with 7-day retention
- **APIs**: `/api/firewall/logs/*` - Stats, blocked IPs, timeline, recent logs

### Configuration (Environment Variables)
| Variable | Default | Description |
|----------|---------|-------------|
| `FIREWALL_DB_PATH` | `/root/firewall.db` | SQLite database path |
| `SYSLOG_PORT` | `514` | UDP port for syslog receiver |
| `SYSLOG_BIND` | `0.0.0.0` | Interface to bind |
| `FIREWALL_IP` | `192.168.0.1` | Only accept logs from this IP |

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/firewall/logs/stats` | Block counts, top ports, top countries |
| `/api/firewall/logs/blocked` | Top blocked IPs with enrichment |
| `/api/firewall/logs/timeline` | Hourly blocks/passes chart data |
| `/api/firewall/logs/recent` | Recent log entries |
| `/api/stats/malicious_ports` | Blocked ports + threat traffic (syslog+NetFlow) |

### Enhanced APIs (Syslog-aware)

| Endpoint | Syslog Enhancement |
|----------|-------------------|
| `/api/security/score` | +5 pts for active blocking, `fw_blocks_1h`, `fw_threats_blocked` |
| `/api/stats/threats` | `blocked` status and `block_count` per threat IP |
| `/api/stats/firewall` | `blocks_1h`, `unique_blocked_ips`, `syslog_active` |
| `/api/stats/net_health` | "Firewall Active" and "Threats Blocked" indicators |

### OPNsense Setup
1. Go to **System → Settings → Logging / Targets**
2. Add target: UDP to 192.168.0.74:514
3. Select **Applications**: `filter` (filterlog)
4. Enable logging on firewall rules

### Database Schema
- `fw_logs`: Raw log entries with GeoIP enrichment
- `fw_stats_hourly`: Pre-aggregated hourly stats
- Automatic cleanup of logs > 7 days

### For AI Agents
- See `SYSLOG_INTEGRATION.md` for full design doc
- Log parser regex: `FILTERLOG_PATTERN` in `app/services/syslog.py`
- Test with: `logger -n 192.168.0.74 -P 514 "test"`

---

**Last Updated**: January 11, 2026 (v3.0 - Full Syslog Integration & AI Assistant)
**Maintained By**: Human + AI Collaboration (Warp/Jules/Claude)  
**For AI Agents**: Read sample_data/README.md for detailed format docs
