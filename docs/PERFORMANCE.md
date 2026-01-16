# Performance Optimization Guide

## Asset Minification

The dashboard uses minified assets in production for optimal performance:

- **CSS**: `style.min.css` - 30.5% smaller than original
- **JavaScript**: `app.min.js` - 44% smaller than original  
- **Service Worker**: `sw.min.js` - 52.4% smaller than original

### Building Minified Assets

To regenerate minified assets after making changes:

```bash
cd /root/PROX_NFDUMP
PYTHONPATH=/usr/local/lib/python3.*/site-packages python3 minify.py
```

Or install dependencies first:

```bash
pip3 install csscompressor rjsmin
python3 minify.py
```

## Performance Features

### 1. Resource Optimization

- **Preconnect Headers**: DNS prefetch and preconnect for external CDN resources (Leaflet)
- **Deferred Scripts**: All JavaScript loads with `defer` attribute
- **Minified Libraries**: Chart.js, Alpine.js, and all vendor libraries use `.min` versions
- **Cache Busting**: Version query parameters on CSS/JS (`?v=2.6.1`)

### 2. Caching Strategy

#### Server-Side Caching
- **60-second API cache**: All `/api/stats/*` endpoints (aligned to 60s windows)
- **Common data cache**: Shared cache for sources, destinations, ports, and protocols
  - Reduces redundant nfdump queries by reusing cached data across endpoints
  - Summary, protocols, and ASNs endpoints now use shared cache instead of separate queries
  - Automatic cleanup prevents memory growth (max 100 entries, LRU eviction)
- **Granular bandwidth cache**: 5-minute historical data buckets
- **Thread-safe caching**: `threading.Lock` prevents race conditions
- **Cache reuse optimization**: Multiple endpoints share the same underlying data to minimize nfdump calls

#### Client-Side Caching (Service Worker)
- **Static Assets**: Cache-first strategy for CSS, JS, images
- **API Responses**: Network-first with 60s cache fallback
- **Offline Support**: Graceful degradation when network unavailable

### 3. Frontend Optimizations

#### Lazy Loading
- **Intersection Observer API**: Sections load data only when visible
- **Smart Polling**: Heavy widgets (World Map, Analytics) refresh every 60s
- **Stale-While-Revalidate**: Show cached data immediately, update in background

#### JavaScript Optimizations
- **Debounced Scroll**: Scroll spy updates throttled to 50ms
- **Chart Reuse**: Chart.js instances reused rather than recreated
- **Sparkline Cache**: 2-minute TTL reduces redundant trend API calls

### 4. Network Optimizations

#### Parallel Fetching
```javascript
Promise.all([
    fetch('/api/stats/summary'),
    fetch('/api/stats/sources'),
    fetch('/api/stats/threats')
])
```

#### Request Coalescing
- Timestamp-aligned cache keys prevent thundering herd
- Multiple widgets share same API response

### 5. CSS Optimizations

#### Mobile-First Responsive Design
- Base styles for mobile, progressively enhanced for desktop
- 3 main breakpoints: 480px, 768px, 1024px
- Touch-friendly targets (min 44px) on mobile

#### CSS Architecture
- CSS Custom Properties (variables) for theming
- Flexbox and Grid for layouts (IE11+ compatible)
- `contain: layout style paint` for World Map isolation

## Performance Monitoring

### Metrics Tracked
- **API Latency**: Average of last 10 requests displayed in status bar
- **Data Freshness**: Shows age of last update with color coding
- **Cache Hit Rate**: Monitor via browser DevTools Network tab

### Browser DevTools
1. **Network Tab**: Check 200 (cache) vs 200 responses
2. **Performance Tab**: Record page load, check for long tasks
3. **Lighthouse**: Run audit for PWA, performance, accessibility scores

## Optimization Checklist

### Before Deployment
- [ ] Run `python3 minify.py` to regenerate minified assets
- [ ] Verify `index.html` references `.min.css` and `.min.js`
- [ ] Test service worker registration in console
- [ ] Check cache headers in Network tab
- [ ] Validate mobile responsiveness

### Production Server
- [ ] Enable gzip/brotli compression in Flask/nginx
- [ ] Set appropriate cache-control headers:
  ```
  static/ -> Cache-Control: public, max-age=31536000, immutable
  api/ -> Cache-Control: public, max-age=60
  ```
- [ ] Use HTTP/2 for multiplexing
- [ ] Consider CDN for static assets

## Troubleshooting

### High Memory Usage
- Lower `heavyTTL` (default 60s) to reduce client-side cache
- Enable "Low Power Mode" in dashboard settings
- Reduce refresh interval from 30s to 60s

### Slow API Responses
- Check nfdump cache on server (60s TTL)
- Verify nfcapd isn't writing during queries
- Monitor server CPU/disk I/O
- Check cache hit rates: Summary, protocols, and ASNs endpoints now reuse common data cache
- Review `/api/performance/metrics` endpoint for cache statistics

### Service Worker Issues
```javascript
// Clear cache manually in browser console
navigator.serviceWorker.ready.then(reg => {
    reg.active.postMessage('clearCache');
});

// Force service worker update
navigator.serviceWorker.ready.then(reg => reg.update());
```

## Future Optimizations

### Potential Improvements
1. **Webpack/Rollup**: Bundle and tree-shake JavaScript
2. **WebP Images**: Use next-gen formats with fallbacks
3. **Critical CSS**: Inline above-the-fold CSS
4. **Code Splitting**: Load firewall/security tabs on-demand
5. **Virtual Scrolling**: For tables with 100+ rows
6. **Web Workers**: Offload heavy computations (sparklines, charts)

### Database Optimization
1. **SQLite WAL Mode**: For concurrent firewall.db reads
2. **Indexed Columns**: Add indexes on timestamp, src_ip, dst_ip
3. **Partitioning**: Separate hot (24h) and cold (7d) data

## Benchmarks

### File Sizes
```
Original:
- style.css:  112 KB
- app.js:     122 KB
- sw.js:        4 KB
Total:        238 KB

Minified:
- style.min.css:  78 KB (-30.5%)
- app.min.js:     68 KB (-44%)
- sw.min.js:       2 KB (-52.4%)
Total:           148 KB (-38%)

With gzip:
- style.min.css:  ~18 KB
- app.min.js:     ~20 KB
- sw.min.js:      ~0.8 KB
Total:            ~39 KB (-84% from original)
```

### Load Times (Typical)
- **First Paint**: ~800ms
- **Interactive**: ~1.2s
- **Full Load**: ~2.5s (including Leaflet)

### API Response Times
- **Summary**: ~50ms (cached)
- **Top Sources**: ~80ms (cached)
- **World Map**: ~200ms (heavy, cached 60s)
- **Bandwidth Chart**: ~120ms (5min buckets)
