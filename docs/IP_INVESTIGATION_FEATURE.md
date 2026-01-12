# IP Investigation Feature

## Overview

The IP Investigation feature provides comprehensive forensic analysis of any IP address that appears in your network traffic or firewall logs. It aggregates data from multiple sources to give you a complete picture of an IP's activity, threat status, and network behavior.

## What It Does

When you investigate an IP address, the system:

1. **Analyzes Network Traffic Patterns** (via nfdump):
   - **Traffic Direction**: Calculates upload/download volumes to determine if the IP is primarily sending or receiving data
   - **Source Ports**: Identifies destination ports the IP connects to (when IP is source)
   - **Destination Ports**: Identifies source ports the IP receives from (when IP is destination)
   - **Protocols**: Analyzes which network protocols (TCP, UDP, ICMP, etc.) the IP uses

2. **Enriches with Geographic Data** (via MaxMind GeoIP):
   - Country and region information
   - ASN (Autonomous System Number) and organization
   - City-level location data (if available)

3. **Resolves Hostname** (via DNS):
   - Performs reverse DNS lookup to get hostname/domain name

4. **Checks Threat Status**:
   - Cross-references against threat intelligence feeds
   - Identifies if the IP is known malicious

5. **Classifies Network Type**:
   - Determines if IP is internal (private network) or external (public internet)

## How to Use

### From Firewall Logs
1. Click on any IP address (source or destination) in the firewall logs table
2. The IP Investigation modal opens automatically
3. Investigation starts immediately with the clicked IP pre-filled

### From Alert Correlation Widget
1. Click on an IP address in an attack chain
2. Or click the "🔍 Investigate IP" button
3. Modal opens and investigation begins automatically

### Manual Investigation
1. Go to the Forensics tab
2. Find the "IP Deep Dive" search bar (at the top of the page)
3. Enter an IP address
4. Click "Investigate" button

## Data Displayed

The investigation results show:

- **Basic Information**:
  - IP Address
  - Hostname (if resolved)
  - Classification (Internal/External)
  - Threat Status (Threat/Clean)

- **Geographic Information**:
  - Country and flag
  - Region/City
  - ASN and organization

- **Traffic Analysis**:
  - Total traffic volume (upload + download)
  - Top destination ports (when IP is source)
  - Top source ports (when IP is destination)
  - Protocols used
  - Active port counts

- **Network Activity Summary**:
  - Total flow count
  - Protocol distribution
  - Port activity breakdown

## Technical Details

### API Endpoint
- **URL**: `/api/ip_detail/<ip>`
- **Method**: GET
- **Parameters**:
  - `range` (optional): Time range for analysis (15m, 30m, 1h, 6h, 24h, 7d). Default: 1h
- **Rate Limit**: 5 requests per 10 seconds per IP

### Data Sources
- **NetFlow Data**: nfdump queries for traffic patterns
- **GeoIP Database**: MaxMind GeoLite2 for location data
- **DNS**: System DNS resolver for hostname lookup
- **Threat Feeds**: In-memory threat intelligence lists

### Time Range Support
The investigation respects the global time range selector, allowing you to analyze:
- Last 15 minutes (for recent incidents)
- Last hour (default, good balance)
- Last 6 hours (daily patterns)
- Last 24 hours (full day analysis)
- Last 7 days (weekly patterns)

## Error Handling

The feature includes robust error handling:

- **Timeout Protection**: Requests timeout after 30 seconds to prevent hanging
- **Graceful Degradation**: If nfdump queries fail, partial data is returned
- **Error Display**: Clear error messages shown in the modal with retry option
- **URL Encoding**: IP addresses are properly encoded for API calls

## Export Options

You can export investigation results:
- **JSON**: Complete raw data for further analysis
- **CSV**: Formatted spreadsheet-friendly data

## Use Cases

1. **Incident Response**: Quickly investigate suspicious IPs from firewall blocks
2. **Threat Hunting**: Analyze IPs from attack chains to understand attacker behavior
3. **Network Forensics**: Deep dive into specific IP activity patterns
4. **Traffic Analysis**: Understand communication patterns and protocols used
5. **Geographic Analysis**: Identify origin countries and organizations

## Limitations

- **Data Availability**: Depends on NetFlow data availability for the selected time range
- **GeoIP Accuracy**: Location data accuracy depends on GeoIP database quality
- **DNS Resolution**: Hostname resolution depends on DNS server configuration
- **Performance**: Large time ranges (7d) may be slower due to more data processing

## Future Enhancements

Potential improvements:
- Timeline visualization of IP activity over time
- Related IPs discovery (IPs that communicate with the same targets)
- Threat intelligence integration (VirusTotal, AbuseIPDB, etc.)
- Historical comparison (compare current vs. previous time periods)
- Traffic pattern anomaly detection
- Automated alert generation for suspicious patterns
