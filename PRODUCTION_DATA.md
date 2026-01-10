# Production Dashboard Data & Metrics

Generated: 2026-01-10

## 1. System Environment

### Network Configuration
- **Firewall**: OPNsense at 192.168.0.1
- **Collector**: LXC 122 at 192.168.0.74:8080
- **Internal Network**: 192.168.0.0/24
- **Key Servers**:
  - Proxmox Host: 192.168.0.80 (PHOBOS-PROX-2)
  - TrueNAS: 192.168.0.100 (PHOBOS-TRUENAS)
  - Backup: 192.168.0.71 (PROX-PBS)
  - Dashboard: 192.168.0.74 (LXC 122)

### NetFlow Collection
- **Version**: NetFlow v9
- **Rotation**: 1 minute (60 files/hour, 1,440 files/day)
- **Compression**: LZ4 (67% space savings)
- **Retention**: 7 days
- **Storage**: ~689 MB current
- **Files**: ~10,080 files total
- **Port**: UDP 2055
- **Buffer**: 8MB socket buffer

## 2. Performance Metrics

### Data Collection
- **Files/hour**: 60
- **Avg file size**: 80-90 KB (compressed)
- **UDP drops**: 0
- **Sequence failures**: 0
- **Compression ratio**: 67% (549KB → 182KB per file)

### System Resources (Dashboard Service)
- **Memory**: 110-260 MB (varies with query load)
- **CPU**: 5-10% baseline, spikes during heavy queries
- **Concurrent tasks**: 10-70 (nfdump query processes)
- **Storage available**: 6.5 GB free

## 3. API Endpoints & Sample Responses

### Key Endpoints
- `/api/stats/summary` - Overall traffic stats
- `/api/stats/sources` - Top source IPs
- `/api/stats/destinations` - Top destination IPs
- `/api/stats/ports` - Top ports
- `/api/stats/protocols` - Protocol breakdown
- `/api/stats/firewall` - SNMP firewall metrics
- `/api/stats/worldmap` - Geographic data
- `/api/stats/countries` - Country aggregation
- `/api/stats/threats` - Security threats
- `/api/bandwidth` - Bandwidth over time
- `/api/conversations` - Top conversations

### To Collect Sample Responses
```bash
cd /tmp
curl -s http://192.168.0.74:8080/api/stats/summary?range=1h > sample-summary.json
curl -s http://192.168.0.74:8080/api/stats/sources?range=1h > sample-sources.json
curl -s http://192.168.0.74:8080/api/stats/firewall > sample-firewall.json
```

## 4. Known Issues & Fixes

### Issue 1: World Map _threat_ips Undefined
- **Status**: FIXED (commit 57ccb8a)
- **Problem**: NameError on line 2117, variable never defined
- **Impact**: World map couldn't render any data
- **Solution**: Temporary - initialize as empty set
- **Needs**: Proper threat_ips implementation

### Issue 2: Browser Cache
- **Status**: MANAGED
- **Solution**: CSS version parameters (?v=11)
- **Method**: Increment version on each deployment

### Issue 3: Locale Warnings
- **Status**: Cosmetic, non-critical
- **Message**: "cannot change locale (en_US.UTF-8)"
- **Impact**: None on functionality

## 5. Usage Patterns (To Be Collected)

### Time Ranges
Commonly used:
- 1 hour (real-time monitoring)
- 6 hours (trend analysis)
- 24 hours (daily patterns)

**Need user feedback on**:
- Which range is used most?
- Any ranges missing?

### Widgets
**Need user feedback on**:
- Most useful widgets?
- Least useful widgets?
- Any to add/remove?
- Any layout issues?

## 6. Network Environment Details

### Internal IP Ranges (Exclude from "External" traffic)
- 192.168.0.0/24 (internal network)

### Key Ports to Monitor
- **443** - HTTPS (primary traffic)
- **53** - DNS queries
- **22** - SSH admin
- **2055** - NetFlow collection
- **80** - HTTP
- **3389** - RDP (if applicable)

### Protocols of Interest
- TCP (web traffic, services)
- UDP (DNS, NetFlow)
- ICMP (network diagnostics)

## 7. GeoIP Integration

### Databases Installed
Location: `/var/lib/GeoIP/` (symlinked to `/root/`)
- **GeoLite2-Country.mmdb** - 9.2 MB
- **GeoLite2-City.mmdb** - 61 MB
- **GeoLite2-ASN.mmdb** - 11 MB

### Test Results
```bash
8.8.8.8 → United States, AS15169 GOOGLE
```

### Status
✅ Working - enriches dashboard with geographic data

## 8. Threat Intelligence

### Feeds Configured
See `threat-feeds.txt` (11 sources configured)

### Status
⚠️ Integration ongoing - needs review after _threat_ips fix

## 9. Feature Requests (To Be Collected)

**Need user input**:
- What's missing?
- Desired features?
- Workflow improvements?
- Integration requests?

## 10. Error Logs

### Recent Errors Found
1. ✅ **FIXED**: _threat_ips NameError (commit 57ccb8a)
2. ⚠️ **Cosmetic**: Locale warnings (non-critical)

### How to Monitor
```bash
# Real-time errors
pct exec 122 -- journalctl -u netflow-dashboard -f | grep -i error

# Last 100 lines
pct exec 122 -- journalctl -u netflow-dashboard -n 100 --no-pager

# Specific error search
pct exec 122 -- journalctl -u netflow-dashboard --since "1 hour ago" | grep -i "error\|exception"
```

## 11. Performance Testing Commands

### API Response Time Tests
```bash
# Test key endpoints
time curl -s http://192.168.0.74:8080/api/stats/summary?range=1h > /dev/null
time curl -s http://192.168.0.74:8080/api/stats/sources?range=1h > /dev/null
time curl -s http://192.168.0.74:8080/api/stats/worldmap?range=1h > /dev/null
time curl -s http://192.168.0.74:8080/api/stats/firewall > /dev/null
```

### Page Load Time
Open browser DevTools → Network tab → Reload page
Record:
- Total page load time
- Largest assets
- Slowest API calls

## 12. Screenshots Needed

Please provide:
1. **Main dashboard** with populated widgets
2. **World map view** with geographic data
3. **Security Center** section
4. **Firewall monitoring** widgets
5. **Any visual issues**: overlapping, layout problems
6. **Mobile view** (if applicable)

## 13. Browser Console

Check for:
- JavaScript errors
- Network failures
- Warning messages
- Performance issues

## 14. Data Collection Checklist

- [ ] API response samples collected
- [ ] Performance timing results gathered
- [ ] Screenshots with real data taken
- [ ] Browser console errors noted
- [ ] Most/least useful widgets identified
- [ ] Feature requests documented
- [ ] Workflow issues noted
- [ ] Network environment details confirmed

## 15. How to Share Data

Create sample files:
```bash
# On the Proxmox host
cd /tmp
curl -s http://192.168.0.74:8080/api/stats/summary?range=1h | jq '.' > sample-summary.json
curl -s http://192.168.0.74:8080/api/stats/sources?range=1h | jq '.sources | .[:5]' > sample-sources.json
curl -s http://192.168.0.74:8080/api/stats/firewall | jq '.' > sample-firewall.json
```

Share via GitHub issue or provide to Claude Opus for analysis.
