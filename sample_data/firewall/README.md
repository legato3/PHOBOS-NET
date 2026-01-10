# Firewall Sample Data

Sample OPNsense firewall logs collected via syslog integration.

## Files

### firewall_sample.json
Real production firewall log samples including:
- **50 blocked connection attempts** - Port scans, bogon networks, threat IPs
- **20 passed connections** - Normal traffic (DNS, HTTPS, etc.)

## Data Structure

```json
{
  "description": "Sample OPNsense firewall logs from syslog integration",
  "blocked_logs": [
    {
      "timestamp": 1768072647.895146,
      "timestamp_iso": "2026-01-10T20:17:27.895146",
      "action": "block",
      "direction": "in",
      "interface": "igc0",
      "src_ip": "192.168.0.1",
      "src_port": 53824,
      "dst_ip": "239.255.255.250",
      "dst_port": 1900,
      "proto": "udp",
      "country_iso": null,
      "is_threat": 0
    }
  ],
  "pass_logs": [...],
  "total_blocked": 50,
  "total_pass": 20
}
```

## Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | float | Unix timestamp (seconds since epoch) |
| `timestamp_iso` | string | ISO 8601 formatted timestamp |
| `action` | string | Firewall action: `block`, `pass`, `reject` |
| `direction` | string | Traffic direction: `in`, `out` |
| `interface` | string | Network interface: `igc0` (WAN), `igc1` (LAN), etc. |
| `src_ip` | string | Source IP address |
| `src_port` | int | Source port number |
| `dst_ip` | string | Destination IP address |
| `dst_port` | int | Destination port number |
| `proto` | string | Protocol: `tcp`, `udp`, `icmp` |
| `country_iso` | string | ISO country code from GeoIP (null if private/unknown) |
| `is_threat` | int | 1 if IP is in threat feed, 0 otherwise |

## Common Blocked Traffic Patterns

### Port Scans
```json
{
  "src_ip": "34.13.170.63",
  "dst_port": 4639,
  "proto": "udp",
  "country_iso": "NL"
}
```

### UPnP Discovery (Port 1900)
```json
{
  "src_ip": "192.168.0.1",
  "dst_ip": "239.255.255.250",
  "dst_port": 1900,
  "proto": "udp"
}
```

### Threat Feed Matches
```json
{
  "src_ip": "147.185.133.42",
  "dst_port": 9763,
  "country_iso": "US",
  "is_threat": 1
}
```

## Data Source

Data collected from OPNsense firewall via syslog (UDP port 514) integration:
- RFC 5424 syslog format
- Parsed from `filterlog` messages
- Enriched with GeoIP country data
- Matched against threat intelligence feeds

## Privacy Note

All IP addresses in this dataset are real production IPs from:
- Public internet sources (attackers, scanners)
- Local network devices (router, internal systems)
- Multicast/broadcast addresses

Internal private IPs have been preserved for context. No sensitive data is exposed.

## Use Cases

- Testing dashboard firewall widgets
- Understanding OPNsense log format
- Validating syslog parsing logic
- Training machine learning models for threat detection
- Example data for documentation

## Related Documentation

- [SYSLOG_INTEGRATION.md](../../SYSLOG_INTEGRATION.md) - Full syslog setup guide
- [AGENTS.md](../../AGENTS.md) - API documentation
- [DEPLOYMENT.md](../../DEPLOYMENT.md) - Deployment instructions
