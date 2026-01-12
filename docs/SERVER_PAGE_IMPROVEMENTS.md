# Server Page Improvements & Suggestions

## Current Issues Fixed
1. ✅ CPU calculation - Now uses psutil for accurate real-time CPU percentage
2. ✅ Database path - Fixed to use FIREWALL_DB_PATH instead of hardcoded path
3. ✅ Auto-refresh - Added 1-second refresh interval when server tab is active
4. ✅ Font styling - Updated to use monospace font for consistency

---

## Additional Data & Widget Suggestions

### 1. CPU Widget Enhancements
**Current:** Shows CPU percent, load averages (1m, 5m, 15m)

**Suggestions:**
- **Per-Core CPU Usage**: Show individual core utilization (if multi-core)
- **CPU Frequency**: Display current CPU frequency (if available)
- **CPU Temperature**: Add temperature monitoring (requires sensors/lm-sensors)
- **Process Count**: Show number of running processes
- **CPU History Graph**: Small sparkline showing CPU usage over last 5 minutes
- **Top Processes**: List top 5 CPU-consuming processes

### 2. Memory Widget Enhancements
**Current:** Shows total, used, available, process memory

**Suggestions:**
- **Swap Usage**: Add swap space statistics (total, used, free)
- **Memory Breakdown**: Show breakdown by buffers, cache, used, free
- **Memory History**: Sparkline graph of memory usage trend
- **Memory Pressure**: Indicator for memory pressure (low/normal/high)
- **Top Memory Consumers**: List processes using most memory

### 3. Disk Widget Enhancements
**Current:** Shows root and NetFlow data directory usage

**Suggestions:**
- **I/O Statistics**: Disk read/write rates (IOPS, MB/s)
- **Disk Temperature**: HDD/SSD temperature (if available)
- **Disk Health**: SMART status indicators
- **Mount Points**: List all mount points with usage
- **Disk History**: Trend graph for disk usage over time
- **Cleanup Suggestions**: Show largest directories/files for cleanup

### 4. Network Statistics Widget (New)
**Add a new widget for network interface statistics:**
- Interface status (up/down)
- Bytes in/out (total and per second)
- Packets in/out
- Interface errors/discards
- Interface speed/duplex
- Network utilization percentage

### 5. Database Widget Enhancements
**Current:** Shows connection status, log count, size, path

**Suggestions:**
- **Database Performance**: Query execution time, slow queries
- **Database Operations**: Reads/writes per second
- **Database Growth Rate**: MB/day or MB/hour growth
- **Table Statistics**: Row counts per table, largest tables
- **Index Statistics**: Index usage and efficiency
- **Backup Status**: Last backup time, backup size
- **Vacuum Status**: Last vacuum time, fragmentation

### 6. System Widget Enhancements
**Current:** Shows uptime, process threads, process name

**Suggestions:**
- **System Load**: Current system load (1m, 5m, 15m) as separate metrics
- **Boot Time**: When system last booted
- **Kernel Version**: OS and kernel information
- **Hostname**: System hostname
- **Time Synchronization**: NTP sync status
- **Logged-in Users**: Current user sessions
- **System Services**: Status of critical services (systemd)

### 7. Process/Application Metrics (New)
**New widget for application-specific metrics:**
- Python process memory (already shown, but enhance)
- Gunicorn worker count and status
- Thread pool utilization
- Request queue depth
- Active connections
- Request rate (requests/second)
- Average response time
- Error rate

### 8. Cache Statistics Widget (New)
**New widget showing cache performance:**
- DNS cache size and hit rate
- GeoIP cache size and hit rate
- API response cache hit rates
- Cache memory usage
- Cache eviction statistics

### 9. Resource Alerts Widget (New)
**New widget for resource warnings:**
- Disk space warnings (when >80%, >90%)
- Memory pressure alerts
- CPU high usage alerts
- Database growth rate warnings
- Service status alerts

### 10. Performance Metrics Widget (New)
**New widget for application performance:**
- API response times (p50, p95, p99)
- Database query times
- nfdump execution times
- Cache effectiveness
- Request throughput

---

## Layout & Design Suggestions

### Current Layout
- Grid layout with auto-fit columns (min 300px)
- Each metric in a card

### Suggested Improvements

**Option 1: Categorized Sections**
Group related metrics into sections:
- **System Resources**: CPU, Memory, Disk
- **Application Health**: Process, Database, Cache
- **Network & Data**: NetFlow, Syslog, Network Interfaces
- **Performance**: Response times, throughput, cache stats

**Option 2: Dashboard-Style Cards**
- Larger primary cards for critical metrics (CPU, Memory, Disk)
- Smaller secondary cards for supporting metrics
- Use visual indicators (progress bars, gauges) for percentages

**Option 3: Tabbed View**
- **Overview**: Critical metrics (CPU, Memory, Disk, Database)
- **Performance**: Detailed performance metrics
- **Network**: Network interfaces and statistics
- **System**: System-level information (uptime, services, etc.)

### Visual Enhancements

1. **Progress Bars**: Add visual progress bars for percentages (CPU, Memory, Disk)
2. **Gauges**: Circular gauges for CPU and Memory usage
3. **Trend Indicators**: Small arrows showing if metrics are increasing/decreasing
4. **Color Coding**: 
   - Green: Healthy/normal
   - Yellow: Warning (70-90%)
   - Red: Critical (>90%)
5. **Sparklines**: Mini trend graphs for CPU, Memory, Disk usage
6. **Status Icons**: Visual icons for status (connected/disconnected, active/inactive)

---

## Implementation Priority

### High Priority (Core Functionality)
1. ✅ Fix CPU calculation accuracy
2. ✅ Fix database connection status
3. ✅ Add 1-second auto-refresh
4. ✅ Fix font styling consistency
5. Add swap memory statistics
6. Add disk I/O statistics
7. Add network interface statistics

### Medium Priority (Enhanced Information)
8. Add CPU temperature (if sensors available)
9. Add per-core CPU usage
10. Add memory breakdown (buffers, cache)
11. Add database performance metrics
12. Add process/application metrics widget
13. Add visual progress bars/gauges

### Low Priority (Nice to Have)
14. Add cache statistics widget
15. Add resource alerts widget
16. Add performance metrics widget
17. Add sparkline trend graphs
18. Add top processes list
19. Add system services status

---

## Technical Considerations

### Dependencies
- **psutil**: Already used for CPU (should add to requirements.txt if not present)
- **sensors/lm-sensors**: For temperature monitoring (optional)
- **smartmontools**: For disk health (optional)

### Performance
- 1-second refresh rate is appropriate for server monitoring
- Cache expensive operations (disk I/O, process enumeration)
- Use async/background updates where possible

### Error Handling
- Gracefully handle missing sensors/tools
- Show fallback data when psutil unavailable
- Display clear error messages for failed metrics

---

## Example Enhanced Widget Structure

```html
<!-- Enhanced CPU Widget -->
<div class="server-stat-card">
    <div class="server-stat-header">
        <span>⚡ CPU</span>
        <span class="server-stat-badge">...</span>
    </div>
    <div class="server-stat-value">...</div>
    <!-- Add progress bar -->
    <div class="server-stat-progress">
        <div class="progress-bar" :style="'width: ' + cpuPercent + '%'"></div>
    </div>
    <!-- Add sparkline -->
    <canvas class="server-stat-sparkline" id="cpu-sparkline"></canvas>
    <div class="server-stat-details">
        <!-- Existing details -->
        <!-- Add per-core if available -->
        <div x-show="cpu.cores">
            <span>Cores:</span>
            <span x-text="cpu.cores"></span>
        </div>
        <!-- Add temperature if available -->
        <div x-show="cpu.temperature">
            <span>Temperature:</span>
            <span x-text="cpu.temperature + '°C'"></span>
        </div>
    </div>
</div>
```
