# OPNsense NetFlow Configuration Guide

## Overview
This guide documents the recommended NetFlow configuration for OPNsense firewall to export flow data to the PHOBOS-NET dashboard.

## Current Setup
- **Firewall**: OPNsense at 192.168.0.1
- **Collector**: LXC 122 at 192.168.0.74:2055
- **Protocol**: NetFlow v9
- **Export Interval**: Real-time

## OPNsense Configuration

### Step 1: Enable NetFlow
1. Navigate to **Reporting → NetFlow**
2. Enable the NetFlow exporter
3. Configure the following settings:

### Basic Settings
| Setting | Value |
|---------|-------|
| Enable | ✅ Checked |
| Interfaces | WAN, LAN (select all monitored interfaces) |
| Version | NetFlow v9 (recommended) or IPFIX |
| Destination | 192.168.0.74 |
| Port | 2055 |

### Recommended Template Fields
Enable these additional fields for richer analytics:

#### Essential Fields (Already Enabled)
- ✅ Source IP Address
- ✅ Destination IP Address
- ✅ Source Port
- ✅ Destination Port
- ✅ Protocol
- ✅ Bytes
- ✅ Packets
- ✅ TCP Flags
- ✅ ToS (Type of Service)

#### Recommended Additional Fields
- ⬜ **Input Interface** - See which interface traffic enters
- ⬜ **Output Interface** - See which interface traffic exits
- ⬜ **Source AS Number** - Origin network identification
- ⬜ **Destination AS Number** - Destination network identification
- ⬜ **VLAN ID** - If using VLANs
- ⬜ **Next Hop IP** - Routing path visibility
- ⬜ **BGP Next Hop** - If using BGP
- ⬜ **Source MAC** - Layer 2 identification
- ⬜ **Destination MAC** - Layer 2 identification

### Export Settings
| Setting | Recommended Value |
|---------|-------------------|
| Active Timeout | 60 seconds |
| Inactive Timeout | 15 seconds |
| Template Refresh | 300 packets |
| Cache Size | 65535 (default) |

## Verification

### On OPNsense
Check NetFlow status in **Reporting → NetFlow → Diagnostics**

### On Collector (LXC 122)
```bash
# Check if flows are being received
ls -lt /var/cache/nfdump/ | head -5

# View recent flow stats
nfdump -R /var/cache/nfdump -t "last 5 minutes" -I

# Check for specific fields
nfdump -R /var/cache/nfdump -t "last 5 minutes" -o extended | head -10
```

## Upgrading to IPFIX (Optional)

IPFIX provides more flexibility than NetFlow v9:

### Benefits of IPFIX
- Variable-length fields
- Better enterprise field support
- More efficient encoding
- Bi-directional flow support

### Configuration
1. Change Version to **IPFIX** in OPNsense
2. Port remains **2055** (or use 4739 for IPFIX standard)
3. nfcapd automatically supports IPFIX

## Troubleshooting

### No Data Received
```bash
# Check if nfcapd is listening
netstat -unlp | grep 2055

# Check firewall rules
# Ensure UDP 2055 is allowed from 192.168.0.1

# Verify OPNsense is exporting
# Check Reporting → NetFlow → Diagnostics on OPNsense
```

### Missing Fields
If certain fields show as 0 or empty:
1. Verify the field is enabled in OPNsense NetFlow template
2. Check if the interface supports the field type
3. Some fields require specific traffic types (e.g., VLAN needs tagged traffic)

### High Sequence Failures
If `nfdump -I` shows high sequence failures:
1. Increase collector buffer: `-B 16777216` (16MB)
2. Check network congestion between firewall and collector
3. Consider reducing export rate on OPNsense

## Performance Tuning

### For High-Traffic Networks
```bash
# /etc/nfdump/default.conf
options='-l /var/cache/nfdump -p 2055 -y -B 16777216 -e -t 60'
```

### For Multiple NetFlow Sources
```bash
# Add multiple sources with different idents
options='-n opnsense,192.168.0.1,/var/cache/nfdump/opnsense -n switch,192.168.0.2,/var/cache/nfdump/switch -p 2055 -y -B 8388608 -e -t 60'
```

## Related Documentation
- [NFCAPD_SETUP.md](NFCAPD_SETUP.md) - Collector configuration
- [AGENTS.md](AGENTS.md) - Dashboard implementation
- [README.md](README.md) - Project overview
