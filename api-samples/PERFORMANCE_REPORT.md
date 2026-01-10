# API Performance & Sample Data Report

**Generated**: 2026-01-10 18:29 CET
**Dashboard**: http://192.168.0.74:8080
**Test Range**: 1 hour

## Performance Results

### Response Times (average of 3 runs)

| Endpoint | Avg Response | Min | Max | Size |
|----------|-------------|-----|-----|------|
| /api/stats/summary | **0.786ms** | 0.667ms | 0.991ms | 313 bytes |
| /api/stats/sources | **0.756ms** | 0.726ms | 0.775ms | 3.1 KB |
| /api/stats/destinations | **0.780ms** | 0.757ms | 0.794ms | 3.2 KB |
| /api/stats/ports | **0.675ms** | 0.657ms | 0.705ms | 1.2 KB |
| /api/stats/protocols | **0.668ms** | 0.620ms | 0.743ms | 501 bytes |
| /api/stats/firewall | **0.743ms** | 0.731ms | 0.766ms | 1.6 KB |
| /api/stats/worldmap | **2.351ms** | 0.816ms | 5.312ms | 11 KB |
| /api/stats/countries | **1.095ms** | 0.757ms | 1.753ms | 1.2 KB |
| /api/bandwidth | **1.053ms** | 0.691ms | 1.678ms | 310 bytes |
| /api/stats/threats | **4.830ms** | 1.954ms | 10.388ms | 198 bytes |

### Performance Analysis

**Fastest APIs** (< 1ms):
- ✅ `/api/stats/summary` - 0.786ms
- ✅ `/api/stats/protocols` - 0.668ms
- ✅ `/api/stats/ports` - 0.675ms
- ✅ `/api/stats/firewall` - 0.743ms (SNMP data)
- ✅ `/api/stats/sources` - 0.756ms
- ✅ `/api/stats/destinations` - 0.780ms

**Moderate Performance** (1-3ms):
- ⚠️ `/api/bandwidth` - 1.053ms
- ⚠️ `/api/stats/countries` - 1.095ms
- ⚠️ `/api/stats/worldmap` - 2.351ms

**Needs Optimization** (> 3ms):
- 🔴 `/api/stats/threats` - 4.830ms (slowest)

### Observations

1. **Excellent baseline performance**: Most APIs respond in < 1ms
2. **Cached data**: Response times are consistent, indicating good caching
3. **World map performance**: ~2.3ms average, acceptable for geographic processing
4. **Threats endpoint**: Slowest at ~4.8ms, likely due to threat feed processing
5. **Data size**: Largest response is worldmap at 11 KB (still very reasonable)

## Sample Data Summary

### Data Collected

| File | Size | Records/Items |
|------|------|---------------|
| summary.json | 313 B | Overview stats |
| sources.json | 3.1 KB | Top source IPs |
| destinations.json | 3.2 KB | Top destination IPs |
| ports.json | 1.2 KB | Top ports |
| protocols.json | 501 B | Protocol breakdown |
| firewall.json | 1.6 KB | SNMP firewall metrics |
| worldmap.json | 11 KB | Geographic data |
| countries.json | 1.2 KB | Country aggregation |
| bandwidth.json | 310 B | Bandwidth time series |
| threats.json | 198 B | Security threats |

**Total Sample Data**: ~22 KB

## System Context

### Environment
- **Container**: LXC 122 on Proxmox
- **NetFlow Source**: OPNsense firewall (192.168.0.1)
- **Collection Rate**: 1-minute intervals
- **Compression**: LZ4 (67% reduction)
- **GeoIP**: Active (Country, City, ASN databases)

### Load Conditions
- Multiple concurrent nfdump queries
- Real-time data collection active
- SNMP polling every 2 seconds
- SQLite trend database active

## Recommendations

### Performance
1. ✅ **Overall performance excellent** - No optimization needed for most endpoints
2. ⚠️ **Consider caching threats data** - 4.8ms is acceptable but could be improved
3. ✅ **GeoIP integration working well** - Minimal impact on performance
4. ✅ **SNMP data very responsive** - 0.743ms for firewall metrics

### Data Quality
- All endpoints returning valid JSON
- GeoIP enrichment working (worldmap has 11KB of geographic data)
- Threat detection active (198 bytes of threat data)
- Real-time metrics available

## Notes for Claude Opus

- Sample JSON files are anonymized (external IPs preserved, internal details sanitized)
- Performance tests run during normal operations (realistic conditions)
- Dashboard is actively used with real traffic monitoring
- All optimizations (compression, caching, GeoIP) are operational
