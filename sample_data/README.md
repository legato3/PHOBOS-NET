# Sample Data

This directory contains sample data to help understand the dashboard's data formats.

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
