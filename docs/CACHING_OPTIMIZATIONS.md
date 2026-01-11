# Caching & Performance Optimizations

This document outlines caching and performance optimizations implemented and available.

## Implemented Optimizations

1. ✅ **Common data cache reuse** - Summary, protocols, and ASNs endpoints now reuse cached data
2. ✅ **Cache memory management** - Automatic LRU cleanup for common data cache
3. ✅ **HTTP cache headers** - 60s cache-control headers for API endpoints
4. ✅ **Service worker caching** - Client-side caching with network-first strategy
5. ✅ **Parallelized network/security fetches** - Network and security sections now fetch in parallel using Promise.allSettled()
6. ✅ **Batch API endpoint** - `/api/stats/batch` endpoint available for batch requests (optional, can be used for further optimization)
7. ✅ **Compression optimization** - Flask-Compress configured with optimal settings (level 6, min size 500 bytes)

## Additional Optimization Suggestions

### 1. Batch API Endpoint (High Impact)

**Problem**: Initial page load makes 10-15+ separate API requests, even with parallel fetching.

**Solution**: Create `/api/stats/batch` endpoint that accepts multiple endpoint requests and returns them in a single response.

**Benefits**:
- Reduces HTTP overhead (headers, connection setup)
- Single round-trip instead of multiple
- Can leverage shared cached data more efficiently
- Better compression ratio (single larger response)

**Implementation**:
```python
@app.route("/api/stats/batch", methods=['POST'])
def api_stats_batch():
    """Batch endpoint: accepts list of endpoint paths, returns combined response"""
    requests = request.json.get('requests', [])
    range_key = request.args.get('range', '1h')
    
    results = {}
    for req in requests:
        endpoint = req.get('endpoint')
        params = req.get('params', {})
        # Route to appropriate handler and cache results
        # ...
    
    return jsonify(results)
```

**Frontend usage**:
```javascript
// Initial load: batch common endpoints
const batchResponse = await fetch('/api/stats/batch', {
    method: 'POST',
    body: JSON.stringify({
        requests: [
            { endpoint: 'summary' },
            { endpoint: 'sources', params: { limit: 10 } },
            { endpoint: 'destinations', params: { limit: 10 } },
            { endpoint: 'ports', params: { limit: 10 } },
            { endpoint: 'protocols' },
            { endpoint: 'threats' },
            { endpoint: 'bandwidth' }
        ]
    })
});
```

**Estimated Impact**: 30-50% reduction in initial load time (fewer HTTP requests, better compression)

---

### 2. SQLite Database Optimizations (Medium Impact)

**Problem**: SQLite queries on `firewall.db` and `netflow-trends.sqlite` may not be optimized.

**Solutions**:

#### A. Enable WAL Mode
Enables concurrent reads without blocking:
```python
def _firewall_db_connect():
    conn = sqlite3.connect(FIREWALL_DB_PATH, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL;')  # Write-Ahead Logging
    conn.execute('PRAGMA synchronous=NORMAL;')  # Faster writes
    conn.execute('PRAGMA cache_size=-64000;')   # 64MB cache
    return conn
```

#### B. Add Indexes
For frequently queried columns:
```sql
CREATE INDEX IF NOT EXISTS idx_firewall_ts ON firewall_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_firewall_src_ip ON firewall_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_firewall_dst_ip ON firewall_logs(dst_ip);
CREATE INDEX IF NOT EXISTS idx_firewall_action ON firewall_logs(action);

-- For trends DB
CREATE INDEX IF NOT EXISTS idx_trends_bucket_end ON traffic_rollups(bucket_end);
```

**Estimated Impact**: 20-40% faster SQLite queries, especially for filtered searches

---

### 3. Parallelize Network Section Fetches (Medium Impact)

**Problem**: Network section loads 10+ endpoints sequentially when visible.

**Current code** (in `loadAll()`):
```javascript
this.fetchFlags();
this.fetchDurations();
this.fetchPacketSizes();
this.fetchProtocols();  // ... etc, all sequential
```

**Solution**: Wrap in `Promise.allSettled()`:
```javascript
if (this.isSectionVisible('section-network') && ...) {
    await Promise.allSettled([
        this.fetchFlags(),
        this.fetchDurations(),
        this.fetchPacketSizes(),
        this.fetchProtocols(),
        this.fetchFlowStats(),
        this.fetchProtoMix(),
        this.fetchNetHealth(),
        this.fetchASNs(),
        this.fetchCountries(),
        this.fetchTalkers(),
        this.fetchServices(),
        this.fetchHourlyTraffic()
    ]);
    this.lastFetch.network = now;
}
```

**Estimated Impact**: 50-70% faster network section load (parallel vs sequential)

---

### 4. Pre-warm Cache Background Thread (Low-Medium Impact)

**Problem**: First request after cache expiry hits nfdump directly.

**Solution**: Background thread pre-computes common queries 5-10 seconds before cache expiry.

```python
def _cache_prewarm_thread():
    """Pre-warm cache before expiry to reduce user-facing latency"""
    while not _shutdown_event.is_set():
        # Check which caches expire in next 10 seconds
        # Pre-compute them in background
        time.sleep(5)
```

**Estimated Impact**: Near-zero latency for cache hits (data ready before request)

**Trade-off**: Increased background CPU usage

---

### 5. Response Compression Optimization (Low Impact)

**Current**: Flask-Compress is enabled, but verify settings.

**Enhancement**: Ensure optimal compression levels:
```python
Compress(app)
app.config['COMPRESS_MIMETYPES'] = [
    'text/html', 'text/css', 'text/javascript',
    'application/json', 'application/javascript'
]
app.config['COMPRESS_LEVEL'] = 6  # Balance speed vs size
app.config['COMPRESS_MIN_SIZE'] = 500  # Only compress >500 bytes
```

**Estimated Impact**: 5-10% smaller responses (already compressed, but can optimize)

---

### 6. Connection Pooling for SQLite (Low Impact)

**Problem**: Creating new SQLite connections for each query has overhead.

**Solution**: Reuse connection objects with thread-local storage:
```python
import threading
_local = threading.local()

def get_db_connection():
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(FIREWALL_DB_PATH, check_same_thread=False)
        _local.conn.execute('PRAGMA journal_mode=WAL;')
    return _local.conn
```

**Note**: SQLite handles this reasonably well, but connection reuse helps.

**Estimated Impact**: 5-10% faster database queries

---

## Priority Ranking

1. **Batch API Endpoint** - Highest impact, moderate complexity
2. **SQLite WAL Mode + Indexes** - High impact, low complexity (quick win)
3. **Parallelize Network Fetches** - Medium impact, very low complexity (easy win)
4. **Pre-warm Cache Thread** - Medium impact, medium complexity
5. **Connection Pooling** - Low impact, low complexity
6. **Compression Tuning** - Low impact, very low complexity

## Implementation Notes

- Start with #2 (SQLite optimizations) - easiest and immediate benefit
- Then #3 (parallel fetches) - simple code change
- Consider #1 (batch endpoint) for significant performance gains if load times are still an issue
- Monitor cache hit rates and query times before/after optimizations

## Monitoring

Track these metrics to measure improvements:
- Initial page load time (First Contentful Paint, Time to Interactive)
- Number of HTTP requests on page load
- Cache hit rates (`/api/performance/metrics`)
- SQLite query times (add timing logs)
- Total nfdump calls per page load
