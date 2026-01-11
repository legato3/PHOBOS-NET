# Logging & Monitoring Environment Improvements

## Current Setup Analysis

### System Resources
- **Container**: LXC 122 on Proxmox (192.168.0.70)
- **Memory**: 1GB total, ~200MB used by dashboard
- **Disk**: 20GB total, 1.7GB used (9% - healthy)
- **CPU**: 4 cores

### Current Logging Infrastructure

#### NetFlow Collection
- **Collector**: nfcapd (receives on UDP 2055)
- **Storage**: `/var/cache/nfdump/` (721MB currently)
- **Retention**: Not explicitly configured (depends on disk space)
- **Format**: nfcapd files (rotated every 5 minutes)

#### Syslog Collection
- **Receiver**: Custom UDP server on port 514
- **Source**: OPNsense firewall (192.168.0.1)
- **Storage**: SQLite database `/root/firewall.db`
- **Retention**: 7 days (configurable via FIREWALL_RETENTION_DAYS)
- **Maintenance**: Hourly cleanup thread

#### SNMP Monitoring
- **Target**: OPNsense firewall (192.168.0.1)
- **Community**: Phoboshomesnmp_3
- **Polling**: Real-time on API requests (cached)
- **Metrics**: CPU, memory, uptime, interface stats

---

## Recommended Improvements

### 1. NetFlow Collection Optimization

#### A. Implement nfcapd Rotation Policy
**Current Issue**: No explicit retention policy - relies on disk space

**Recommendation**: Configure nfcapd rotation with automatic cleanup

```bash
# Add to nfcapd startup script or systemd service
nfcapd -w -D -l /var/cache/nfdump -p 2055 -P /var/run/nfcapd.pid \
    -t 300 -s 0 -S 1 -x '/usr/bin/nfexpire -t 7d' \
    -x '/usr/bin/nfexpire -v -t 7d'
```

**Benefits**:
- Automatic cleanup of files older than 7 days
- Prevents disk space exhaustion
- Configurable retention period
- Verbose logging for troubleshooting

**Implementation**:
```bash
# Check current nfcapd process
pct exec 122 -- systemctl status nfcapd 2>/dev/null || pct exec 122 -- ps aux | grep nfcapd

# If running via systemd, update service file
# If running manually, update startup command
```

#### B. Add NetFlow Data Compression
**Recommendation**: Enable nfdump compression for older data

```bash
# Compress files older than 1 day
find /var/cache/nfdump -name "nfcapd.*" -mtime +1 -exec gzip {} \;

# Update nfdump queries to handle .gz files
# nfdump automatically handles .gz files
```

**Benefits**:
- 70-80% disk space savings
- Faster queries (compressed I/O is often faster for large files)
- Extended retention with same disk space

#### C. Implement NetFlow Data Aggregation
**Current**: Raw flow data only

**Recommendation**: Pre-aggregate data for longer retention

```bash
# Daily aggregation script
/usr/local/bin/nfdump-aggregate.sh:
#!/bin/bash
DATE=$(date -d "yesterday" +%Y%m%d)
nfcapd -R /var/cache/nfdump -M -q -A srcip,dstip,proto,dstport \
    -w /var/cache/nfdump/daily/nfcapd.daily.${DATE}
```

**Benefits**:
- Reduced storage for historical analysis
- Faster queries for long time ranges
- Better for trending and reporting

---

### 2. Syslog Collection Improvements

#### A. Add Syslog Rate Limiting
**Current**: No rate limiting - could overwhelm on high traffic

**Recommendation**: Add rate limiting to UDP receiver

```python
# In netflow-dashboard.py syslog receiver
from collections import deque
import time

_syslog_rate_limit = {}  # {source_ip: deque of timestamps}
MAX_LOGS_PER_SECOND = 100

def check_rate_limit(src_ip):
    now = time.time()
    if src_ip not in _syslog_rate_limit:
        _syslog_rate_limit[src_ip] = deque(maxlen=MAX_LOGS_PER_SECOND)
    
    recent = _syslog_rate_limit[src_ip]
    # Remove logs older than 1 second
    while recent and (now - recent[0]) > 1.0:
        recent.popleft()
    
    if len(recent) >= MAX_LOGS_PER_SECOND:
        return False  # Rate limit exceeded
    recent.append(now)
    return True
```

**Benefits**:
- Prevents DoS from log floods
- Protects database from excessive writes
- Maintains performance under high load

#### B. Implement Batch Inserts
**Current**: Individual INSERT per log entry

**Recommendation**: Batch inserts for better performance

```python
# Buffer logs and insert in batches
_syslog_buffer = []
_buffer_lock = threading.Lock()
BUFFER_SIZE = 100
BUFFER_TIMEOUT = 5  # seconds

def flush_syslog_buffer():
    with _buffer_lock:
        if not _syslog_buffer:
            return
        logs_to_insert = _syslog_buffer[:]
        _syslog_buffer.clear()
    
    # Batch INSERT with executemany
    conn.execute('BEGIN TRANSACTION')
    conn.executemany('INSERT INTO fw_logs (...) VALUES (...)', logs_to_insert)
    conn.commit()
```

**Benefits**:
- 10-50x faster inserts
- Reduced database lock contention
- Better handling of burst traffic

#### C. Add Syslog Indexing
**Current**: Full table scans for queries

**Recommendation**: Add indexes to firewall.db

```sql
-- Add indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_fw_logs_timestamp ON fw_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_fw_logs_src_ip ON fw_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_fw_logs_dst_ip ON fw_logs(dst_ip);
CREATE INDEX IF NOT EXISTS idx_fw_logs_action ON fw_logs(action);
CREATE INDEX IF NOT EXISTS idx_fw_logs_composite ON fw_logs(timestamp, action, src_ip);
```

**Benefits**:
- 10-100x faster queries
- Better performance for dashboard APIs
- Reduced CPU usage

---

### 3. SNMP Monitoring Enhancements

#### A. Implement Background Polling
**Current**: Polls on-demand (cached)

**Recommendation**: Background polling thread for near real-time data

```python
# Already partially implemented, but optimize interval
SNMP_POLL_INTERVAL = 2.0  # seconds (current)
# Consider: 5 seconds for production (reduces load)
```

**Benefits**:
- Consistent data freshness
- Reduced response time for dashboard
- Better for alerting

#### B. Add SNMP Error Handling & Retry Logic
**Current**: Basic error handling

**Recommendation**: Exponential backoff for failures

```python
# Already implemented with exponential backoff
# Consider: Add SNMP timeout configuration
SNMP_TIMEOUT = 2.0  # seconds
SNMP_RETRIES = 3
```

---

### 4. Database Optimization

#### A. Enable WAL Mode for SQLite
**Current**: Default journal mode (slower writes)

**Recommendation**: Enable Write-Ahead Logging

```python
# In _firewall_db_init()
conn.execute('PRAGMA journal_mode=WAL;')
conn.execute('PRAGMA synchronous=NORMAL;')  # Balanced performance/reliability
conn.execute('PRAGMA cache_size=-64000;')  # 64MB cache
conn.execute('PRAGMA temp_store=memory;')
```

**Benefits**:
- 2-3x faster writes
- Better concurrency (readers don't block writers)
- Improved performance for syslog insertion

#### B. Implement Database Vacuum Scheduling
**Recommendation**: Weekly VACUUM to reclaim space

```python
# Add to maintenance thread
def _db_vacuum():
    if datetime.now().weekday() == 0 and datetime.now().hour == 2:  # Monday 2 AM
        conn.execute('VACUUM;')
        conn.execute('ANALYZE;')  # Update statistics
```

**Benefits**:
- Reclaims disk space from deleted records
- Improves query performance
- Maintains database health

---

### 5. Monitoring & Alerting

#### A. Add Disk Space Monitoring
**Recommendation**: Alert when disk usage exceeds thresholds

```python
# Add to monitoring
import shutil

def check_disk_space():
    total, used, free = shutil.disk_usage('/var/cache/nfdump')
    percent_used = (used / total) * 100
    
    if percent_used > 90:
        # Send alert
        send_alert('CRITICAL', f'NetFlow storage {percent_used:.1f}% full')
    elif percent_used > 75:
        send_alert('WARNING', f'NetFlow storage {percent_used:.1f}% full')
```

#### B. Add Log Collection Health Checks
**Recommendation**: Monitor syslog/netflow collection rates

```python
# Track metrics
_syslog_health = {
    'received_1h': 0,
    'parsed_1h': 0,
    'errors_1h': 0,
    'last_received': None
}

# Alert if no logs received in 5 minutes
if (time.time() - _syslog_health['last_received']) > 300:
    send_alert('WARNING', 'No syslog received in 5 minutes')
```

---

### 6. Performance Optimizations

#### A. Optimize NetFlow Queries
**Recommendation**: Use time-based filtering more aggressively

```python
# In run_nfdump, ensure time filters are always used
# Current implementation looks good, but verify:
# - Always provide time range
# - Use -n limit for aggregation queries
# - Consider pre-aggregated data for long ranges
```

#### B. Add Query Result Caching
**Current**: 60-second cache for stats

**Recommendation**: Extend cache for longer time ranges

```python
# Longer cache for historical data
if range_key in ['24h', '7d']:
    CACHE_TTL = 300  # 5 minutes
elif range_key in ['1h']:
    CACHE_TTL = 60  # 1 minute
```

---

### 7. Security Enhancements

#### A. Harden Syslog Receiver
**Current**: Accepts from any source (filtered by firewall IP in code)

**Recommendation**: Bind to specific interface or use firewall rules

```python
# In syslog receiver
SYSLOG_BIND = os.getenv("SYSLOG_BIND", "192.168.0.74")  # Container IP only
```

#### B. Add Input Validation
**Recommendation**: Validate syslog messages before processing

```python
# Sanitize syslog input
def sanitize_syslog_message(msg):
    # Limit message length
    if len(msg) > 4096:
        return None
    # Remove null bytes
    msg = msg.replace('\x00', '')
    # Validate encoding
    try:
        msg.encode('utf-8')
        return msg
    except UnicodeEncodeError:
        return None
```

---

### 8. Operational Improvements

#### A. Add Log Rotation for Application Logs
**Recommendation**: Configure logrotate for Flask/Gunicorn logs

```bash
# /etc/logrotate.d/netflow-dashboard
/var/log/netflow-dashboard/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
```

#### B. Add Health Check Endpoint
**Recommendation**: Add comprehensive health check

```python
@app.route('/health')
def health_check():
    checks = {
        'database': check_database(),
        'disk_space': check_disk_space(),
        'syslog_active': _syslog_stats['received'] > 0,
        'memory_usage': get_memory_usage(),
        'nfdump_available': _has_nfdump
    }
    status = 'healthy' if all(checks.values()) else 'degraded'
    return jsonify({'status': status, 'checks': checks}), 200 if status == 'healthy' else 503
```

---

## Implementation Priority

### High Priority (Do First)
1. ✅ NetFlow retention policy (prevent disk fill)
2. ✅ Syslog batch inserts (performance)
3. ✅ Database indexes (query performance)
4. ✅ WAL mode for SQLite (write performance)

### Medium Priority (Do Soon)
5. Disk space monitoring (operational)
6. NetFlow compression (storage efficiency)
7. Syslog rate limiting (stability)
8. Health check endpoint (monitoring)

### Low Priority (Nice to Have)
9. NetFlow aggregation (advanced analytics)
10. Log rotation (operational)
11. Extended caching (performance)

---

## Quick Wins (Easy to Implement)

1. **Enable SQLite WAL mode** - 5 minutes, significant performance gain
2. **Add database indexes** - 10 minutes, major query improvement
3. **Configure nfcapd rotation** - 15 minutes, prevents disk issues
4. **Add disk space monitoring** - 30 minutes, operational safety

---

## Monitoring Recommendations

### Key Metrics to Track
- NetFlow storage usage (disk space)
- Syslog insertion rate (logs/second)
- Database size and growth rate
- Query response times
- Memory usage trends
- nfdump query frequency

### Alert Thresholds
- Disk usage > 75% (warning)
- Disk usage > 90% (critical)
- No syslog for 5 minutes (warning)
- Database > 500MB (consider retention policy)
- Memory usage > 80% (warning)

---

## Estimated Impact

### Storage Savings
- NetFlow compression: ~500MB → ~150MB (70% reduction)
- Aggregation: Additional 50% for historical data
- **Total potential savings: ~600MB**

### Performance Improvements
- WAL mode: 2-3x faster database writes
- Indexes: 10-100x faster queries
- Batch inserts: 10-50x faster syslog processing
- **Overall: 5-10x improvement in high-load scenarios**

### Operational Benefits
- Automatic cleanup prevents disk issues
- Better monitoring and alerting
- Extended retention with same resources
- Improved reliability and stability

---

## Next Steps

1. Review recommendations and prioritize
2. Test changes in development/staging first
3. Implement high-priority items
4. Monitor impact and adjust
5. Document configuration changes
