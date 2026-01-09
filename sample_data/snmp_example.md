# SNMP Firewall Monitoring - Sample Data

This document provides sample SNMP data collected from OPNsense firewall for the NetFlow Analytics Dashboard.

## Configuration

```python
SNMP_CONFIG = {
    "host": "192.168.0.1",
    "community": "Phoboshomesnmp_3",
    "port": 161,
    "timeout": 2
}
```

## SNMP OIDs Used

| Metric | OID | Type | Description |
|--------|-----|------|-------------|
| CPU Load 1min | `.1.3.6.1.4.1.2021.10.1.3.1` | FLOAT | 1-minute load average |
| CPU Load 5min | `.1.3.6.1.4.1.2021.10.1.3.2` | FLOAT | 5-minute load average |
| Memory Total | `.1.3.6.1.4.1.2021.4.5.0` | INTEGER | Total memory in KB |
| Memory Available | `.1.3.6.1.4.1.2021.4.6.0` | INTEGER | Available memory in KB |
| System Uptime | `.1.3.6.1.2.1.1.3.0` | TIMETICKS | System uptime in timeticks |

## Sample SNMP Walk Output

```bash
$ snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.4.1.2021.10.1.3

UCD-SNMP-MIB::laLoad.1 = STRING: 0.51
UCD-SNMP-MIB::laLoad.2 = STRING: 0.60
UCD-SNMP-MIB::laLoad.3 = STRING: 0.65
```

```bash
$ snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.4.1.2021.4

UCD-SNMP-MIB::memTotalReal.0 = INTEGER: 12182676 KB
UCD-SNMP-MIB::memAvailReal.0 = INTEGER: 735092 KB
UCD-SNMP-MIB::memBuffer.0 = INTEGER: 0 KB
UCD-SNMP-MIB::memCached.0 = INTEGER: 6475320 KB
```

```bash
$ snmpget -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.1.3.0

DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (64657991) 7 days, 11:36:19.91
```

## API Response Format

### Endpoint
```
GET /api/stats/firewall?range=1h
```

### Sample Response
```json
{
    "firewall": {
        "cpu_load_1min": 0.51,
        "cpu_load_5min": 0.60,
        "cpu_percent": 12.8,
        "mem_avail": 735092,
        "mem_percent": 94.0,
        "mem_total": 12182676,
        "mem_used": 11447584,
        "sys_uptime": "0:17:56:19.91",
        "sys_uptime_formatted": "17h 56m"
    }
}
```

## Field Descriptions

| Field | Type | Unit | Description |
|-------|------|------|-------------|
| `cpu_load_1min` | float | - | 1-minute load average |
| `cpu_load_5min` | float | - | 5-minute load average |
| `cpu_percent` | float | % | Derived CPU percentage (load_1min * 25) |
| `mem_total` | integer | KB | Total system memory |
| `mem_avail` | integer | KB | Available memory |
| `mem_used` | integer | KB | Used memory (total - available) |
| `mem_percent` | float | % | Memory usage percentage |
| `sys_uptime` | string | - | Raw uptime format "D:HH:MM:SS.ms" |
| `sys_uptime_formatted` | string | - | Human-readable uptime "17h 56m" |

## Uptime Format Conversion

### Raw Format
```
0:17:56:19.91
```
Interpretation: `days:hours:minutes:seconds.milliseconds`

### Formatted Output
```
17h 56m
```

### Python Conversion Function
```python
def format_uptime(uptime_str):
    """Convert '0:17:42:05.92' to '17h 42m'"""
    parts = uptime_str.split(':')
    if len(parts) >= 3:
        hours = int(parts[1])
        minutes = int(parts[2].split('.')[0])
        return f"{hours}h {minutes}m"
    return uptime_str
```

## Caching Strategy

- **Cache Duration**: 30 seconds
- **Thread Safety**: Threading.Lock used for concurrent requests
- **Cache Key**: Time-window based (current_time // cache_duration)
- **Invalidation**: Automatic after 30 seconds

```python
firewall_cache = {
    "timestamp": 0,
    "data": {}
}
firewall_cache_lock = threading.Lock()
FIREWALL_CACHE_SECONDS = 30
```

## Error Handling

### Failed SNMP Query
If SNMP query fails, returns empty dict:
```json
{
    "firewall": {}
}
```

### Frontend Display
Dashboard shows `--` for missing values:
```javascript
x-text="firewall.cpu_percent ? firewall.cpu_percent + '%' : '--'"
```

## Dashboard Widget Display

### CPU Usage Widget
```
🔥 CPU Usage
   12.8%
   Load: 0.51
```

### Memory Widget
```
💾 Memory
   94.0%
   10.9 GB / 11.6 GB
```

### Uptime Widget
```
⏱️ Uptime
   17h 56m
   192.168.0.1
```

### 5min Load Widget
```
📊 5min Load
   0.60
   OPNsense
```

## Dependencies

### System Packages
```bash
apt-get install snmp python3-pysnmp4
```

### Python Imports
```python
from pysnmp.hlapi import *
import threading
```

## Testing SNMP Connectivity

### Test with snmpget
```bash
snmpget -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.1.3.0
```

### Test with Python
```python
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpEngine(),
           CommunityData('Phoboshomesnmp_3'),
           UdpTransportTarget(('192.168.0.1', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('.1.3.6.1.2.1.1.3.0')))
)

if errorIndication:
    print(f"Error: {errorIndication}")
else:
    for varBind in varBinds:
        print(f"{varBind[0]} = {varBind[1]}")
```

## Notes

- OPNsense runs on FreeBSD, uses Net-SNMP daemon
- Load average on 2-core system: ~0.5 = 25% CPU usage
- Memory calculation: `mem_used = mem_total - mem_avail`
- Dashboard updates every 30 seconds via auto-refresh
