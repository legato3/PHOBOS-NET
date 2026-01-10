# OPNsense Firewall Syslog Integration

## Overview

This document describes how to integrate OPNsense firewall logs into the NetFlow Dashboard via syslog, enabling real-time visibility into blocked connections, firewall rule hits, and security events.

## Architecture

```
┌─────────────────┐     UDP 514      ┌──────────────────┐
│   OPNsense      │ ───────────────► │  LXC 122         │
│   Firewall      │                  │  (Dashboard)     │
│   192.168.0.1   │                  │  192.168.0.74    │
└─────────────────┘                  └────────┬─────────┘
                                              │
                                              ▼
                                     ┌──────────────────┐
                                     │  Python Syslog   │
                                     │  Receiver        │
                                     │  (UDP 514)       │
                                     └────────┬─────────┘
                                              │
                                              ▼
                                     ┌──────────────────┐
                                     │  SQLite DB       │
                                     │  firewall.db     │
                                     │  (7-day retention)│
                                     └────────┬─────────┘
                                              │
                                              ▼
                                     ┌──────────────────┐
                                     │  Dashboard API   │
                                     │  /api/firewall/* │
                                     └──────────────────┘
```

## Storage Design

### Why SQLite?
- Already proven in this project (netflow-trends.sqlite)
- Simple deployment (no additional services)
- Good performance with proper indexing for 7-day retention
- Easy backup and maintenance

### Database Schema

```sql
-- Main firewall log table
CREATE TABLE IF NOT EXISTS fw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,           -- Unix timestamp
    timestamp_iso TEXT,                -- ISO format for display
    action TEXT NOT NULL,              -- 'pass', 'block', 'reject'
    direction TEXT,                    -- 'in', 'out'
    interface TEXT,                    -- 'wan', 'lan', 'opt1', etc.
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    proto TEXT,                        -- 'tcp', 'udp', 'icmp'
    rule_id TEXT,                      -- OPNsense rule ID
    rule_desc TEXT,                    -- Rule description (if available)
    reason TEXT,                       -- Block reason
    length INTEGER,                    -- Packet length
    country_iso TEXT,                  -- GeoIP country (enriched)
    is_threat INTEGER DEFAULT 0,       -- Matched threat feed
    raw_log TEXT                       -- Original syslog message
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_fw_timestamp ON fw_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_fw_action ON fw_logs(action);
CREATE INDEX IF NOT EXISTS idx_fw_src_ip ON fw_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_fw_dst_ip ON fw_logs(dst_ip);
CREATE INDEX IF NOT EXISTS idx_fw_dst_port ON fw_logs(dst_port);
CREATE INDEX IF NOT EXISTS idx_fw_action_ts ON fw_logs(action, timestamp);

-- Aggregated stats (updated every minute)
CREATE TABLE IF NOT EXISTS fw_stats_hourly (
    hour_ts INTEGER PRIMARY KEY,       -- Hour timestamp (Unix)
    blocks INTEGER DEFAULT 0,
    passes INTEGER DEFAULT 0,
    unique_blocked_ips INTEGER DEFAULT 0,
    top_blocked_port INTEGER,
    top_blocked_country TEXT
);
```

### Retention Policy
- **Raw logs**: 7 days (168 hours)
- **Hourly aggregates**: 30 days
- **Cleanup**: Automatic via background thread every hour

### Estimated Storage
- ~10,000 logs/day (typical home network) = 70,000 logs/week
- ~200 bytes/row average = ~14 MB/week raw data
- With indexes: ~25-30 MB total
- Very manageable for SQLite

## OPNsense Configuration

### Step 1: Enable Remote Syslog

1. Go to **System → Settings → Logging / Targets**
2. Click **+ Add**
3. Configure:
   - **Enabled**: ✅
   - **Transport**: UDP
   - **Applications**: filter (firewall logs)
   - **Hostname**: 192.168.0.74
   - **Port**: 514
   - **Facility**: Local0
   - **Level**: Informational
   - **Description**: NetFlow Dashboard

4. Click **Save** and **Apply**

### Step 2: Configure Log Format (Optional)

For richer data, enable RFC 5424 format:
1. Go to **System → Settings → Logging**
2. Set **Log Message Format**: syslog (RFC 5424)

### Step 3: Firewall Rule Logging

Ensure key rules have logging enabled:
1. Go to **Firewall → Rules → [Interface]**
2. Edit rules you want to monitor
3. Enable **Log packets that are handled by this rule**
4. Consider logging:
   - All block rules (default)
   - WAN inbound pass rules
   - Suspicious port rules

## Log Format Parsing

### OPNsense filterlog Format

```
<134>1 2026-01-10T18:30:45+01:00 OPNsense.localdomain filterlog 12345 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,185.220.101.45,192.168.0.1,443,54321,0,S,1234567890,,65535,,
```

**Field breakdown** (comma-separated after filterlog):
1. Rule number
2. Sub-rule
3. Anchor
4. Tracker ID
5. Interface (e.g., igb0, igb1)
6. Reason (match, default)
7. Action (pass, block, reject)
8. Direction (in, out)
9. IP version (4, 6)
10. TOS
11. ECN
12. TTL
13. ID
14. Offset
15. Flags
16. Protocol number
17. Protocol name
18. Length
19. Source IP
20. Destination IP
21. Source port
22. Destination port
23. (TCP fields if applicable)

### Parser Implementation

```python
import re
from datetime import datetime

FILTERLOG_PATTERN = re.compile(
    r'filterlog.*?:\s*'
    r'(?P<rule>\d+)?,'        # Rule number
    r'(?P<subrule>.*?),'      # Sub-rule
    r'(?P<anchor>.*?),'       # Anchor
    r'(?P<tracker>.*?),'      # Tracker ID
    r'(?P<iface>\w+),'        # Interface
    r'(?P<reason>\w+),'       # Reason
    r'(?P<action>\w+),'       # Action
    r'(?P<dir>\w+),'          # Direction
    r'(?P<ipver>\d),'         # IP version
    r'.*?,'                   # TOS
    r'.*?,'                   # ECN
    r'(?P<ttl>\d+)?,'         # TTL
    r'.*?,'                   # ID
    r'.*?,'                   # Offset
    r'.*?,'                   # Flags
    r'(?P<proto_num>\d+)?,'   # Protocol number
    r'(?P<proto>\w+)?,'       # Protocol name
    r'(?P<length>\d+)?,'      # Packet length
    r'(?P<src_ip>[\d\.]+),'   # Source IP
    r'(?P<dst_ip>[\d\.]+),'   # Destination IP
    r'(?P<src_port>\d+)?,'    # Source port
    r'(?P<dst_port>\d+)?'     # Destination port
)

def parse_filterlog(line: str) -> dict | None:
    """Parse OPNsense filterlog syslog message."""
    match = FILTERLOG_PATTERN.search(line)
    if not match:
        return None
    
    return {
        'rule_id': match.group('rule'),
        'interface': match.group('iface'),
        'action': match.group('action'),
        'direction': match.group('dir'),
        'proto': match.group('proto'),
        'length': int(match.group('length') or 0),
        'src_ip': match.group('src_ip'),
        'dst_ip': match.group('dst_ip'),
        'src_port': int(match.group('src_port') or 0),
        'dst_port': int(match.group('dst_port') or 0),
    }
```

## New API Endpoints

### Firewall Statistics
```
GET /api/firewall/stats?range=1h
```
Response:
```json
{
  "blocks_total": 1234,
  "blocks_per_hour": 51.4,
  "passes_total": 45678,
  "unique_blocked_ips": 89,
  "top_blocked_ports": [
    {"port": 22, "count": 456, "service": "SSH"},
    {"port": 23, "count": 234, "service": "Telnet"},
    {"port": 445, "count": 123, "service": "SMB"}
  ],
  "top_blocked_countries": [
    {"iso": "CN", "name": "China", "count": 345},
    {"iso": "RU", "name": "Russia", "count": 234}
  ]
}
```

### Blocked IPs
```
GET /api/firewall/blocked?range=1h&limit=20
```
Response:
```json
{
  "blocked_ips": [
    {
      "ip": "185.220.101.45",
      "count": 156,
      "last_seen": "2026-01-10T18:30:45Z",
      "ports_targeted": [22, 443, 8080],
      "country": "Germany",
      "country_iso": "DE",
      "is_threat": true,
      "threat_feed": "Tor Exit Nodes"
    }
  ]
}
```

### Attack Timeline
```
GET /api/firewall/timeline?range=24h
```
Response:
```json
{
  "timeline": [
    {"hour": "2026-01-10T00:00:00Z", "blocks": 45, "passes": 1234},
    {"hour": "2026-01-10T01:00:00Z", "blocks": 67, "passes": 1456}
  ]
}
```

### Live Feed (WebSocket future enhancement)
```
WS /api/firewall/live
```

## New Dashboard Widgets

### 1. Blocked Connections Card
```
┌─────────────────────────────────────┐
│ 🛡️ Blocked Connections (24h)        │
├─────────────────────────────────────┤
│                                     │
│     1,234 blocked                   │
│     ↑ 23% vs yesterday              │
│                                     │
│  89 unique IPs  │  12 countries     │
│                                     │
└─────────────────────────────────────┘
```

### 2. Top Blocked IPs Table
```
┌─────────────────────────────────────────────────────┐
│ 🚫 Top Blocked IPs                                  │
├─────────────────────────────────────────────────────┤
│ IP              │ Hits │ Country │ Ports      │ ⚠️  │
├─────────────────┼──────┼─────────┼────────────┼─────┤
│ 185.220.101.45  │  156 │ 🇩🇪 DE   │ 22,443     │ TOR │
│ 45.155.205.233  │  134 │ 🇷🇺 RU   │ 22,23      │ 🔴  │
│ 92.118.160.18   │   89 │ 🇨🇳 CN   │ 445        │ 🔴  │
└─────────────────────────────────────────────────────┘
```

### 3. Firewall Rules Hit Count
```
┌─────────────────────────────────────────────────────┐
│ 📋 Firewall Rules Activity                          │
├─────────────────────────────────────────────────────┤
│ Rule                          │ Hits  │ Action      │
├───────────────────────────────┼───────┼─────────────┤
│ Block bogon networks          │ 2,345 │ 🔴 block    │
│ Block private networks        │ 1,234 │ 🔴 block    │
│ Allow LAN to any              │ 45.6K │ 🟢 pass     │
│ Allow established/related     │ 23.4K │ 🟢 pass     │
└─────────────────────────────────────────────────────┘
```

### 4. Countries Blocked Map/List
```
┌─────────────────────────────────────┐
│ 🌍 Blocked by Country (24h)         │
├─────────────────────────────────────┤
│ 🇨🇳 China        ████████████ 345   │
│ 🇷🇺 Russia       ████████░░░░ 234   │
│ 🇩🇪 Germany      ██████░░░░░░ 189   │
│ 🇺🇸 USA          ████░░░░░░░░ 123   │
│ 🇳🇱 Netherlands  ███░░░░░░░░░  89   │
└─────────────────────────────────────┘
```

### 5. Attack Timeline (Enhanced)
```
┌─────────────────────────────────────────────────────┐
│ 📊 Attack Timeline (24h)                            │
├─────────────────────────────────────────────────────┤
│  ▓                                                  │
│  ▓ ▓                          ▓                     │
│  ▓ ▓     ▓                    ▓ ▓                   │
│ ▓▓▓▓▓   ▓▓▓    ▓ ▓           ▓▓▓▓▓                  │
│▓▓▓▓▓▓▓ ▓▓▓▓▓ ▓▓▓▓▓ ▓ ▓ ▓ ▓ ▓▓▓▓▓▓▓ ▓               │
├─────────────────────────────────────────────────────┤
│ 00  03  06  09  12  15  18  21  now                 │
│ ■ Blocks  ■ Port Scans  ■ Brute Force               │
└─────────────────────────────────────────────────────┘
```

### 6. Security Score Enhancement

Add these factors to the security score calculation:
- Blocks/hour rate
- Known threat IPs blocked (positive factor!)
- Port scan attempts detected
- Brute force attempts detected

## Implementation Checklist

### Phase 1: Backend Infrastructure
- [ ] Create SQLite database schema
- [ ] Implement syslog UDP receiver (port 514)
- [ ] Implement filterlog parser
- [ ] Add GeoIP enrichment for blocked IPs
- [ ] Add threat feed matching for blocked IPs
- [ ] Implement 7-day retention cleanup
- [ ] Add hourly aggregation background task

### Phase 2: API Endpoints
- [ ] `/api/firewall/stats` - Summary statistics
- [ ] `/api/firewall/blocked` - Blocked IPs list
- [ ] `/api/firewall/timeline` - Hourly timeline
- [ ] `/api/firewall/rules` - Rule hit counts
- [ ] `/api/firewall/countries` - Country breakdown

### Phase 3: Dashboard Widgets
- [ ] Blocked Connections card
- [ ] Top Blocked IPs table
- [ ] Firewall Rules Activity
- [ ] Countries Blocked visualization
- [ ] Enhanced Attack Timeline
- [ ] Update Security Score calculation

### Phase 4: Testing & Deployment
- [ ] Test syslog receiver with OPNsense
- [ ] Verify log parsing accuracy
- [ ] Load test with high log volume
- [ ] Deploy to production LXC
- [ ] Configure OPNsense syslog target
- [ ] Monitor for 24h, adjust as needed

## Deployment Commands

### On LXC 122 (Dashboard Server)

```bash
# Allow UDP 514 in firewall (if ufw enabled)
ufw allow 514/udp

# Or via iptables
iptables -A INPUT -p udp --dport 514 -s 192.168.0.1 -j ACCEPT

# Restart dashboard service after code update
systemctl restart netflow-dashboard

# Monitor incoming syslog (for testing)
tcpdump -i eth0 -n port 514 -A
```

### Verify Connection

```bash
# From OPNsense (or any Linux box)
logger -n 192.168.0.74 -P 514 "Test message from OPNsense"

# Check dashboard logs
journalctl -u netflow-dashboard -f | grep -i syslog
```

## Security Considerations

1. **Only accept from firewall IP**: Bind syslog receiver to accept only from 192.168.0.1
2. **No authentication on UDP syslog**: This is a LAN-only deployment
3. **Rate limiting**: Implement if log volume is unexpectedly high
4. **Disk monitoring**: Alert if database grows beyond expected size

## Future Enhancements

1. **WebSocket live feed**: Real-time blocked connections display
2. **IDS/IPS integration**: Parse Suricata alerts if enabled
3. **Automatic blocklist**: Feed confirmed attackers back to OPNsense
4. **Alert thresholds**: Email/webhook when blocks exceed threshold
5. **Geo-blocking recommendations**: Suggest countries to block based on attack patterns

---

**Last Updated**: January 10, 2026  
**Author**: Claude Opus + Human Collaboration
