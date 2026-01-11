# Forensics Tab Improvements - Suggestions

## Current State
- Firewall logs are displayed at the bottom of Forensics tab
- Logs are fetched on tab load but not auto-refreshed
- No real-time streaming of new logs
- No filtering/search capabilities

## Proposed Improvements

### 1. Live Firewall Logs (Priority: High)
**Move to top of tab** and add real-time updates:
- Move firewall logs section to the very top of Forensics tab
- Add auto-refresh (polling every 5-10 seconds when tab is active)
- Add "Live" indicator showing when logs are being updated
- Show timestamp of last log received
- Auto-scroll to new logs option (toggle)

### 2. Log Filtering & Search (Priority: High)
- Filter by action (Block/Pass/Reject)
- Filter by threat status (Threats only / All)
- Search by IP address (source or destination)
- Filter by port number
- Filter by protocol (TCP/UDP/ICMP)
- Filter by time range (Last 15m, 1h, 6h, 24h)
- Clear filters button

### 3. Real-Time Log Streaming (Priority: Medium)
- Server-Sent Events endpoint for live log streaming
- Only stream when Forensics tab is active
- Buffer new logs and append to top of table
- Mark new logs with visual indicator (flash/animation)

### 4. Log Statistics Dashboard (Priority: Medium)
Add a summary widget showing:
- Logs per minute/hour
- Top blocked IPs (with counts)
- Top targeted ports
- Geographic distribution of blocked IPs
- Threat vs normal traffic ratio

### 5. Enhanced Log Details (Priority: Low)
- Expandable row details (click to expand)
- Show full raw log message
- Show GeoIP information (country, ASN)
- Link to IP investigation tool
- Export filtered logs (CSV/JSON)

### 6. Log Timeline Visualization (Priority: Low)
- Mini timeline chart showing log volume over time
- Highlight threat events
- Interactive zoom/pan

### 7. Additional Forensics Features
- **Connection Flow Visualization**: Graph showing connection chains
- **Port Scan Detection**: Identify and highlight port scan patterns in logs
- **Brute Force Detection**: Detect and highlight repeated connection attempts
- **Geographic Threat Map**: Visualize blocked IPs on a map
- **Threat Intelligence Enrichment**: Show threat feed matches inline
- **Log Correlation**: Group related logs by IP/port/pattern
- **Export Investigation**: Export all data for a specific investigation
