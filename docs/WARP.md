# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

PHOBOS-NET - A real-time network traffic monitoring system designed for Proxmox LXC environments. This is a Flask-based web application that analyzes NetFlow data using nfdump, provides threat intelligence via multi-feed aggregation, and displays cyberpunk-themed analytics with Alpine.js.

**Target Environment**: LXC Container 122 on Proxmox (Debian/Ubuntu-based)  
**Production IP**: 192.168.0.74  
**Default Port**: 8080

## Commands

### Development & Testing

```bash
# Run development server (on MacOS for local testing)
python3 netflow-dashboard.py

# The app falls back to sample data if nfdump is not available
# Sample data: sample_data/nfdump_flows.csv (6,808 real NetFlow records)
```

### Production Deployment

```bash
# Install on LXC container
systemctl start systemd/netflow-dashboard.service
systemctl stop systemd/netflow-dashboard.service
systemctl restart systemd/netflow-dashboard.service
systemctl status systemd/netflow-dashboard.service

# View logs
journalctl -u systemd/netflow-dashboard.service -f

# Manual run for debugging
cd /root && python3 netflow-dashboard.py
```

### Asset Management

```bash
# Minify CSS/JS for production
python3 minify.py

# This creates .min.css and .min.js versions
# Reduces total size by ~38% (-90KB)
```

### Testing

```bash
# Validate HTML/WCAG compliance
python3 test_html_validation.py

# Verify map functionality
python3 verify_map.py

# The project has no pytest/unittest suite
# Testing is primarily manual via browser + sample data
```

### Threat Feed Management

```bash
# Force threat feed refresh (via API)
curl -X POST http://192.168.0.74:8080/api/refresh_feed

# Edit threat feeds configuration
nano /root/threat-feeds.txt

# Check feed status
curl http://192.168.0.74:8080/api/stats/feed_health
```

### Database Management

```bash
# Firewall syslog database (SQLite)
sqlite3 /root/firewall.db

# NetFlow trends database
sqlite3 netflow-trends.sqlite

# Both have automatic cleanup (7-day retention for firewall, rolling for trends)
```

## Architecture

### Backend (Flask + Python)

**Core Components**:
- `netflow-dashboard.py` - Single monolithic Flask application (~3700 lines)
- `run_nfdump()` - Wrapper for nfdump CLI, falls back to mock data from sample_data/
- `parse_csv()` - **Dynamic column detection** - NEVER hardcode indices, always parse header
- `fetch_threat_feed()` - Multi-feed aggregator with per-feed error handling
- `detect_*()` functions - 8 advanced detection algorithms (port scan, brute force, exfil, etc.)

**Critical Design Patterns**:

1. **Mock Data Fallback**: If nfdump is unavailable, uses sample_data/nfdump_flows.csv
   - Enables local MacOS development without NetFlow infrastructure
   - Mock aggregation logic in `mock_nfdump()` must match real nfdump CSV output

2. **Dynamic CSV Parsing**: nfdump column order varies by query type
   ```python
   # ALWAYS detect columns dynamically
   header = lines[0].lower()
   cols = [c.strip() for c in header.split(',')]
   src_ip_idx = cols.index('sa') if 'sa' in cols else cols.index('val')
   ```

3. **Granular Caching**: Each API endpoint has dedicated lock + cache
   - 60s TTL for most stats (aligned to 60s windows for better hit rates)
   - 30s for SNMP firewall data
   - 15 min (900s) for threat feeds
   - Cache keys include time window: `f"{query_type}:{range}:{int(time.time()//60)}"`

4. **Fetch 100, Display 10**: nfdump's `-n` flag limits during aggregation (early cutoff)
   - Solution: Fetch 100 items, sort by bytes DESC in Python, display top 10
   - Function: `get_common_nfdump_data()` centralizes this pattern

5. **Multi-Feed Threat Intelligence**: `/root/threat-feeds.txt` format
   ```
   URL|CATEGORY|NAME
   https://feed.url/list.txt|C2|FeedName
   ```
   - Set-based deduplication across ~38K IPs from multiple sources
   - Individual feed failures don't block others
   - Per-feed health tracking in `_feed_status` dict

### Frontend (Alpine.js)

**Single-Page Architecture**:
- `templates/index.html` - Monolithic template with all widgets (~3500 lines)
- `static/app.js` - Alpine.js component with reactive state (~2700 lines)
- `static/style.css` - Cyberpunk glassmorphism theme

**Key UI Patterns**:
- **Lazy Loading**: Intersection Observer for on-demand widget data fetching
- **Mobile-First**: Responsive breakpoints at 1024px (tablet), 768px (mobile)
- **PWA Support**: Service worker with offline-first caching strategy
- **Accessibility**: WCAG 2.1 Level AA compliant (24/24 validation tests passed)

**Widget System**:
- 30+ widgets across 3 tabs (Overview, Security, Network)
- User preferences stored in localStorage (minimized/hidden widgets)
- Each widget has dedicated API endpoint with caching

### Data Flow

```
Router/Firewall → nfcapd (port 2055) → /var/cache/nfdump/*.nfcapd → nfdump CLI → parse_csv() → JSON API → Alpine.js
                                      ↓
                  OPNsense Syslog (port 514) → SQLite (firewall.db) → Firewall APIs → Security Score
```

### Firewall Integration (Dual-Mode)

**SNMP Monitoring** (OPNsense health metrics):
- Polls 192.168.0.1 via SNMP community "Phoboshomesnmp_3"
- Metrics: CPU, Memory, Uptime, Load averages
- Endpoint: `/api/stats/firewall`

**Syslog Integration** (OPNsense filterlog):
- UDP receiver on port 514
- Parses OPNsense filterlog format (enhanced security score)
- SQLite storage: `/root/firewall.db` with 7-day retention
- Enriches threats with block status (active vs. passive detection)

### Thread Architecture

**Background Threads** (daemon, auto-started):
1. `ThreatFeedThread` - Fetches threat feeds every 15 min
2. `TrendsThread` - Rolls up NetFlow stats every 5 min (SQLite storage)
3. `SyslogReceiverThread` - UDP server for firewall logs (port 514)
4. `AggregationThread` - Pre-computes hourly stats for firewall logs

All threads respect `_shutdown_event` for graceful termination.

## Configuration

### Environment Variables

```bash
# DNS & SNMP
DNS_SERVER=192.168.0.6          # For PTR lookups
SNMP_HOST=192.168.0.1           # Firewall IP
SNMP_COMMUNITY=Phoboshomesnmp_3 # SNMP community string

# Threat Intelligence APIs (optional)
VIRUSTOTAL_API_KEY=c480490e31bfbacf2ff9adc040312c254097c38d0037ccf4676200cbb2860632
ABUSEIPDB_API_KEY=6bec8cdb5f6e384445ad212a77d920c96f43a2c84f8060b76f6d358f04dc007eaf733e509f87da76

# Paths
SMTP_CFG_PATH=/root/netflow-smtp.json
NOTIFY_CFG_PATH=/root/netflow-notify.json
THRESHOLDS_CFG_PATH=/root/netflow-thresholds.json
FIREWALL_DB_PATH=/root/firewall.db

# Syslog
SYSLOG_PORT=514                 # UDP port for firewall logs
SYSLOG_BIND=0.0.0.0             # Bind address
FIREWALL_IP=192.168.0.1         # Only accept logs from this IP
```

### File Locations (Production)

```
/root/
├── netflow-dashboard.py        # Main application
├── threat-feeds.txt            # Multi-feed URLs
├── threat-ips.txt              # Aggregated blocklist (~38K IPs)
├── threat-whitelist.txt        # False positive exclusions
├── watchlist.txt               # User-defined IPs to monitor
├── netflow-smtp.json           # Email alert config
├── netflow-notify.json         # Notification preferences
├── netflow-thresholds.json     # Alert thresholds
├── firewall.db                 # Syslog SQLite database
├── static/                     # CSS, JS, minified assets
└── templates/                  # Jinja2 templates

/var/cache/nfdump/              # NetFlow capture files (*.nfcapd)
/usr/share/GeoIP/               # MaxMind GeoIP databases
```

## Critical Coding Guidelines

### Working with NetFlow Data

1. **Never hardcode CSV column indices** - always use dynamic detection:
   ```python
   # BAD
   src_ip = parts[3]
   
   # GOOD
   header = lines[0].lower().split(',')
   src_ip_idx = header.index('sa') if 'sa' in header else header.index('val')
   src_ip = parts[src_ip_idx]
   ```

2. **Fetch large, display small** - avoid nfdump's `-n` aggregation bug:
   ```python
   # Fetch 100, sort in Python, return top 10
   data = parse_csv(run_nfdump(["-s", "srcip/bytes", "-n", "100"], tf))
   data.sort(key=lambda x: x['bytes'], reverse=True)
   return data[:10]
   ```

3. **Cache with time windows** - align to 60s boundaries:
   ```python
   win = int(time.time() // 60)
   cache_key = f"{endpoint}:{range_key}:{win}"
   ```

### Multi-Feed Threat Intelligence

- **Support multi-feed** - this is a KEY feature, don't remove it
- **Graceful degradation** - continue if individual feeds fail
- **Set-based deduplication** - use `set()` for IP merging
- **Per-feed metadata** - track category, feed name, latency

Format in threat-feeds.txt:
```
URL|CATEGORY|NAME
```

### Security Considerations

- **Input validation**: Use `validate_ip()` and `validate_filter()` for nfdump arguments
- **No command injection**: All nfdump args are array-based, not shell strings
- **SNMP community**: Stored in env var, not committed to git
- **Rate limiting**: `@throttle()` decorator on all API endpoints

### UI Development

- **Alpine.js reactivity**: Use `x-data`, `x-show`, `:class` patterns
- **Cyberpunk theme**: Dark backgrounds, neon accents (#0ff, #f0f, #ff0)
- **Mobile-first**: Test at 768px and 480px breakpoints
- **Accessibility**: Always include ARIA labels, roles, and keyboard navigation

## Common Tasks

### Adding a New Threat Feed

1. Edit `/root/threat-feeds.txt`
2. Add line: `https://feed.url/list.txt|CATEGORY|FeedName`
3. Restart service or wait for next auto-refresh (15 min)

### Adding a New Widget

1. **Backend**: Add API endpoint in `netflow-dashboard.py`
   - Create dedicated lock and cache dict
   - Use 60s TTL with window alignment
   - Return consistent JSON format

2. **Frontend**: 
   - Add state to `static/app.js` Alpine component
   - Add HTML in `templates/index.html`
   - Update `friendlyLabels` dict for widget manager

3. **Styling**: Maintain cyberpunk theme in `static/style.css`

### Modifying CSV Parsing

- **Always test with real nfdump output AND mock data**
- Update both `parse_csv()` and `mock_nfdump()` to match
- Check `sample_data/nfdump_flows.csv` for reference format
- Verify with: `nfdump -R /var/cache/nfdump -o csv -s srcip/bytes -n 10`

## Performance Considerations

- **nfdump calls are expensive**: Cache aggressively (60s TTL)
- **Parallel processing**: Use `ThreadPoolExecutor` for concurrent operations
- **Frontend batching**: `Promise.all()` for parallel API calls
- **Asset minification**: Run `python3 minify.py` before deployment
- **DNS caching**: Background resolution with 300s TTL to avoid blocking

## Known Limitations

- **No database ORM** - Raw SQLite queries for firewall logs
- **No authentication** - Designed for internal LXC network only
- **Single-threaded Flask** - Use systemd for production (not gunicorn in current setup)
- **No WebSocket** - Polling-based refresh (not real-time push)
- **GeoIP requires manual download** - Not auto-updated

## Documentation References

- **AGENTS.md** - Comprehensive architecture guide for AI agents
- **PERFORMANCE.md** - Optimization strategies and benchmarks
- **SYSLOG_INTEGRATION.md** - Firewall log integration design
- **sample_data/README.md** - Data format documentation with real examples
- **DEPLOYMENT.md** - Production deployment checklist
- **OPNSENSE_NETFLOW.md** - OPNsense NetFlow configuration guide

## Troubleshooting

**No data displayed**:
- Check nfdump availability: `which nfdump`
- Verify NetFlow files: `ls -lh /var/cache/nfdump/`
- Test manual query: `nfdump -R /var/cache/nfdump -o csv -s srcip/bytes -n 10`
- Falls back to sample data on MacOS

**Threat feed errors**:
- Check internet connectivity from LXC container
- Verify `/root/threat-feeds.txt` format
- Check feed health: `curl http://localhost:8080/api/stats/feed_health`

**High CPU usage**:
- Check cache hit rates: `/api/stats/metrics`
- Reduce refresh interval (default 30s)
- Enable Low Power mode in UI

**Firewall logs not appearing**:
- Verify syslog receiver: `netstat -ulnp | grep 514`
- Check OPNsense: System → Settings → Logging / Targets
- Test with: `logger -n 192.168.0.74 -P 514 "test"`
- Verify FIREWALL_IP env var matches OPNsense IP

## Version History

- **v2.8** (Jan 2026) - Firewall syslog integration
- **v2.6** (Jan 2026) - Analytics expansion (11 widgets)
- **v2.5** (Jan 2026) - Top Stats expansion (8 widgets)
- **v2.4** (Jan 2026) - Security Center enhancements (13 widgets, 8 detection algorithms)
- **v2.0** (Jan 2026) - Major rewrite with Alpine.js, multi-feed support, cyberpunk theme
