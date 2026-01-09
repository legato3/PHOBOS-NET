# Sample Data

This directory contains sample data to help understand the dashboard's data formats, including NetFlow flows, nfdump statistics, threat feeds, and SNMP firewall metrics.

## Files

### nfdump_flows.csv
Sample NetFlow data in CSV format from nfdump output. Contains 30 flow records with fields:
- Timestamps (first, last)
- Duration
- Source/Destination IPs and ports
- Protocol (TCP/UDP/ICMP)
- TCP flags
- Packet and byte counts
- Type of Service (ToS)
- Input/Output interfaces

**Usage in dashboard:**
- API endpoints parse this format for bandwidth, top sources/destinations, protocols
- Used for traffic analysis and anomaly detection

### nfdump_stats_example.txt
Example output from nfdump statistical queries used by the dashboard:
- Top sources: `nfdump -R /path -s srcip/bytes -n 10`
- Top destinations: `nfdump -R /path -s dstip/bytes -n 10`
- Top protocols: `nfdump -R /path -s proto/bytes/flows -n 10`
- Top ports: `nfdump -R /path -s dstport/bytes/flows -n 20`

### threat_feeds_example.txt
Sample threat intelligence feed format:
- One IP address per line
- Comments start with #
- Used for matching against flow data to detect threats
### snmp_example.md
Comprehensive documentation for SNMP firewall monitoring:
- SNMP OIDs used for CPU, memory, and uptime metrics
- Sample SNMP walk/get outputs from OPNsense firewall
- API response format with field descriptions
- Uptime format conversion examples
- Caching strategy and error handling
- Testing commands for SNMP connectivity

**Usage in dashboard:**
- `/api/stats/firewall` endpoint returns firewall health metrics
- Dashboard displays CPU usage, memory, uptime, and load average widgets
- 30-second caching reduces SNMP polling overhead

### snmp_api_response.json
Real API response from `/api/stats/firewall` endpoint showing:
- CPU load averages (1min, 5min)
- Memory usage (total, available, used, percentage)
- System uptime (raw and formatted)
- All values collected via SNMP from OPNsense firewall at 192.168.0.1


## Data Flow

1. **nfdump** captures and stores NetFlow data
2. **Dashboard** queries nfdump with various filters and aggregations
3. **API endpoints** parse CSV/text output and return JSON
4. **Frontend** displays data in tables, charts, and alerts

## Notes for AI Agents

When making changes to data parsing:
- CSV format is consistent but column order may vary
- Always check for header row to detect column positions
- Handle empty results gracefully
- Threat feed IPs should be deduplicated and sorted
