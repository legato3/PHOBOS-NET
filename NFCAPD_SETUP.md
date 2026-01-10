# NetFlow Collection Setup (nfcapd/nfdump)

## Overview
NetFlow data collection setup for PROX_NFDUMP dashboard in LXC container 122 on PHOBOS-PROX-2.

## System Information
- **Container**: LXC 122 (PROX-NFDUMP)
- **Host**: PHOBOS-PROX-2  
- **IP**: 192.168.0.74
- **Data Dir**: `/var/cache/nfdump`
- **Config**: `/etc/nfdump/default.conf`

## Configuration

### nfcapd Optimized Settings

```bash
# /etc/nfdump/default.conf
cache_directory=/var/cache/nfdump
user=root
group=root

# Optimized options:
# -l /var/cache/nfdump : Base directory
# -p 2055              : NetFlow port
# -y                   : LZ4 compression (67% space savings)
# -B 8388608           : 8MB socket buffer
# -e                   : Auto-expire old data
# -t 300               : 5-minute file rotation
options='-l /var/cache/nfdump -p 2055 -y -B 8388608 -e -t 300'
```

### Optimizations

1. **LZ4 Compression** (`-y`): 67% storage reduction (549KB → 182KB per file)
2. **8MB Buffer** (`-B`): Better burst handling
3. **Auto-Expire** (`-e`): Automatic cleanup
4. **5-Min Rotation** (`-t 300`): 288 files/day

## Data Retention

### 7-Day Retention
Automated cleanup via `/etc/cron.daily/nfdump-cleanup`:

```bash
#!/bin/bash
NFDUMP_DIR="/var/cache/nfdump"
DAYS_TO_KEEP=7
find "$NFDUMP_DIR" -name 'nfcapd.*' -type f -mtime +$DAYS_TO_KEEP -delete
logger -t nfdump-cleanup "Cleaned up NetFlow files older than $DAYS_TO_KEEP days"
```

### Storage Stats
- **Uncompressed**: ~688 MB
- **Compressed**: ~227 MB (67% reduction)
- **Files**: ~2,100 (7 days)
- **Available**: 6.5 GB free

### Retention Scaling
- **7 days**: ~227 MB
- **14 days**: ~454 MB
- **30 days**: ~974 MB

## Service Management

```bash
# Restart
/etc/init.d/nfdump restart

# Status
systemctl status nfdump

# Verify
ps aux | grep nfcapd
```

## NetFlow Sources

OPNsense firewall (192.168.0.1) exports to:
- **IP**: 192.168.0.74
- **Port**: 2055
- **Protocol**: UDP

## Troubleshooting

```bash
# Check process
ps aux | grep nfcapd

# Check port
netstat -unlp | grep 2055

# Check logs
journalctl -u nfdump -n 50

# Verify compression
ps aux | grep nfcapd | grep -- '-y'
```

## Change Log

### 2026-01-10 - Optimization
- LZ4 compression enabled
- 8MB socket buffer
- Auto-expire enabled
- 5-minute rotation
- 7-day retention script
- 67% storage reduction achieved

### 2026-01-03 - Initial Setup
- Basic nfcapd configuration
- Port 2055 collection
