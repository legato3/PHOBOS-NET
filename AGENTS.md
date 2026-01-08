# AGENTS.md - Guide for AI Coding Agents

This document helps AI agents (like Jules) understand the PROX_NFDUMP project structure, data flows, and conventions.

## 🏗️ Project Architecture

### Component Overview
```
PROX_NFDUMP/
├── netflow-dashboard.py      # Flask backend (main application)
├── static/
│   ├── app.js                # Alpine.js frontend logic
│   └── style.css             # Cyberpunk theme styles
├── templates/
│   └── index.html            # Single-page dashboard UI
├── threat-feeds.txt          # Multi-feed configuration
├── sample_data/              # Real data examples for reference
└── netflow-dashboard.service # Systemd service definition
```

### Technology Stack
- **Backend**: Flask (Python 3)
- **Frontend**: Alpine.js (reactive framework)
- **Data Source**: nfdump (NetFlow collector)
- **Styling**: Custom CSS with Cyberpunk Glassmorphism theme
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

### Backend (netflow-dashboard.py)

#### fetch_threat_feed()
- **Purpose**: Download and merge multiple threat feeds
- **Location**: Lines ~348-390
- **Key Feature**: Multi-feed support via `/root/threat-feeds.txt`
- **Critical**: Uses set() for deduplication, graceful error handling

#### parse_csv()
- **Purpose**: Parse nfdump CSV with dynamic column detection
- **Critical**: ALWAYS check for header row, column order varies
- **Common Mistake**: Hardcoding column indices breaks

#### API Routes with Caching
- **Pattern**: All `/api/stats/*` endpoints use 60-second cache
- **Implementation**: threading.Lock for thread-safe cache
- **Key**: Cache keys aligned to 60s windows for better hit rates

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
   - Add route to netflow-dashboard.py
   - Implement caching if query is expensive
   - Return consistent JSON format
   - Handle empty results gracefully

2. **Frontend Changes**:
   - Update Alpine.js state in app.js
   - Add API call in parallel fetch
   - Update template in index.html
   - Maintain Cyberpunk theme in style.css

3. **Testing**:
   - Test with empty nfdump results
   - Test with missing threat feeds
   - Test with high concurrent load
   - Verify caching behavior

### Performance Considerations

- **nfdump calls are expensive**: Cache aggressively
- **Parallel processing**: Use ThreadPoolExecutor
- **Frontend**: Batch API calls with Promise.all()
- **Avoid**: N+1 queries, redundant nfdump calls

## 📝 Modification Checklist

When modifying code, verify:
- [ ] Column detection works (if touching CSV parsing)
- [ ] Multi-feed support preserved (threat intelligence)
- [ ] Caching logic maintained (API routes)
- [ ] Error handling for empty results
- [ ] No hardcoded IPs/paths
- [ ] Alpine.js reactivity preserved
- [ ] Cyberpunk theme consistency

## 🧪 Testing with Sample Data

Use `sample_data/` directory:
- `nfdump_flows.csv` - 6,808 real NetFlow records
- `nfdump_stats_example.txt` - Statistical query examples
- `threat_feeds_example.txt` - Threat feed format
- `README.md` - Detailed format documentation

## 🔗 Key External Dependencies

- **nfdump**: CLI tool, output format can change between versions
- **MaxMind GeoIP**: Database location `/usr/share/GeoIP/*.mmdb`
- **Threat Feeds**: External URLs, may be temporarily unavailable
- **Flask**: Development mode only (use gunicorn for production)

## 💡 Pro Tips for AI Agents

1. **Use sample_data/** - Reference real examples before modifying parsers
2. **Check nfdump version** - Output format varies slightly between versions
3. **Test feed failures** - Code should continue if one feed is down
4. **Monitor cache** - Log cache performance in development
5. **Preserve multi-feed** - This is a KEY feature, don't remove it
6. **Dynamic parsing** - Never hardcode CSV column positions
7. **Graceful degradation** - UI should work even if some APIs fail

## 🎨 UI/UX Guidelines

### Cyberpunk Theme
- Dark backgrounds with neon accents (#0ff, #f0f, #ff0)
- Glassmorphism effects (backdrop-filter: blur)
- Monospace fonts for data tables
- Condensed tables (Top 10 items)
- Responsive bell icon for notifications

### Alpine.js Patterns
- Use `x-data` for component state
- `x-show` for conditional rendering
- `@click` for event handlers
- `:class` for dynamic styling
- Keep reactivity intact when modifying

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

## 🔐 Security Considerations

- Threat intelligence updates every 15 minutes
- SMTP credentials in separate config file
- No authentication on dashboard (LXC internal only)
- Threat feeds validated before use
- DNS lookups timeout to prevent hanging

---

**Last Updated**: January 2026 (v2.0)  
**Maintained By**: Human + AI Collaboration (Warp/Jules)  
**For AI Agents**: Read sample_data/README.md for detailed format docs
