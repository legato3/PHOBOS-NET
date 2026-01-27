# PHOBOS-NET Data Coverage Map

This document outlines the data sources, ingestion methods, storage mechanisms, and visualization capabilities of the PHOBOS-NET dashboard.

## 1. NetFlow (v9 / IPFIX)

*   **Ingest:**
    *   `nfcapd` (nfdump toolsuite) listens on UDP port 2055.
    *   Captures raw NetFlow v5/v9 or IPFIX records from the firewall.
    *   **Fields:** Source IP, Destination IP, Source Port, Destination Port, Protocol, TCP Flags, Bytes, Packets, Timestamp, Duration.
*   **Store:**
    *   **Raw:** Binary flow files in `/var/cache/nfdump/nfcapd.YYYYMMDDHHMM` (rotated every 5 minutes).
    *   **Rollups:** SQLite (`traffic_rollups` table) stores aggregated bandwidth (bytes/flows) per 5-minute bucket.
    *   **Top Lists:** SQLite (`top_sources`, `top_dests` tables) stores top 100 talkers per 5-minute bucket.
    *   **Host Memory:** SQLite (`host_memory` table) persists "first seen" timestamps for hosts.
    *   **Flow History:** In-memory cache (`_flow_history`) stores recent flow details (src/dst/port/proto) for 30-60 minutes.
*   **Visualize:**
    *   **Bandwidth:** Timeseries graph of bits/second and flows/second.
    *   **Top Talkers:** Source IP, Destination IP, Bytes, Flows, Packets, Duration, Protocol, Service Name.
    *   **Geo/ASN:** Country flags, City, ASN Organization, World Map (Source/Dest/Threat locations).
    *   **Stats:** Distribution of Protocols, Ports, TCP Flags, Packet Sizes.
    *   **Analysis:** Long-lived flow detection, Beaconing candidates, Traffic anomalies.
*   **Not Shown:**
    *   IPv6 addresses are ingested but skipped in Duration Stats (`api_stats_durations`).
    *   Tiny flows (<64 bytes average packet size) are classified as "noise" in Noise Metrics but individual records are still available in raw flow views.
    *   `nfdump` summary headers and system messages are parsed out and discarded.

## 2. Filterlog (Firewall Logs)

*   **Ingest:**
    *   Syslog listener on UDP port 514.
    *   Parses lines containing `filterlog` (OPNsense/pf format).
    *   **Fields:** Rule ID, Tracker ID, Interface, Reason, Action (pass/block/reject), Direction, IP Version, Protocol, Length, Source IP, Destination IP, Source Port, Destination Port.
*   **Store:**
    *   **SQLite:** `fw_logs` table stores all parsed fields plus enriched GeoIP data and Threat status.
    *   **Memory:** `FirewallStore` ring buffer (last 10,000 events) for real-time streaming.
*   **Visualize:**
    *   **Real-time:** Live stream of firewall events (Block/Pass).
    *   **Stats:** Block vs Pass counts, Top Blocked IPs, Top Blocked Ports, Top Blocked Countries, Top Blocked Rules.
    *   **Alerts:** High-value port blocks (SSH, RDP, SMB) and Threat IP blocks generate visual alerts.
*   **Not Shown:**
    *   Packet payload (not captured by filterlog).
    *   Non-filterlog syslog messages on port 514 are discarded (handled by Port 515 listener).
    *   IPv6 extension headers (beyond basic proto/src/dst) are not deeply parsed.

## 3. Firewall Syslog (General)

*   **Ingest:**
    *   Syslog listener on UDP port 515 (configured on OPNsense as a remote target).
    *   Captures generic system messages (configd, lighttpd, unbound, dhcpd, etc.).
*   **Store:**
    *   **SQLite:** `syslog_events` table stores Timestamp, Program, Message, Facility, Severity, Hostname.
    *   **Memory:** Buffered for batch insertion.
*   **Visualize:**
    *   **Logs:** Searchable table of system logs.
    *   **Timeline:** Significant events (Service start/stop, Interface up/down, Errors) are promoted to the main Timeline view.
*   **Not Shown:**
    *   Filterlog messages (if sent to port 515, they would be stored as raw text but not parsed as firewall events).
    *   Duplicate listeners are prevented; only one thread binds to port 515.

## 4. SNMP (System Health)

*   **Ingest:**
    *   Active Polling (SNMP v2c) of the Firewall IP.
    *   **OIDs:** CPU Load, Memory Usage, Swap Usage, Uptime, Interface Traffic (In/Out Octets), Interface Errors/Discards, TCP/UDP Stats, Connection Table.
*   **Store:**
    *   **Memory:** Short-term cache (`_snmp_cache`) and baselines (`_baselines`) for trend analysis.
    *   **Persistence:** None (real-time only).
*   **Visualize:**
    *   **Hardware:** Firewall CPU %, Memory %, Swap %, Uptime, Temperature (if available).
    *   **Interfaces:** WAN/LAN/VPN throughput (Mbps), Packets/sec, Errors/sec, Discards/sec.
    *   **Network Stack:** Active TCP Connections, UDP Datagrams, ICMP Errors.
    *   **VPN:** WireGuard and Tailscale interface status and throughput (discovered dynamically).
*   **Not Shown:**
    *   Full process list (only total process count is collected).
    *   "No Such Object" or empty OID responses are gracefully skipped.

## 5. System (Dashboard Host)

*   **Ingest:**
    *   Local OS metrics via `/proc` filesystem (CPU, Load Avg, Uptime, Disk I/O).
    *   Internal Application Metrics (Dependency Health, Thread Status, HTTP Performance).
*   **Store:**
    *   **Memory:** `PulseStore` stores recent health events and heartbeats.
    *   **Memory:** `_server_health_cache` stores instantaneous system snapshot.
*   **Visualize:**
    *   **Resources:** Dashboard Server CPU, Memory, Disk Usage (`/` and NetFlow storage).
    *   **Health:** Status of background threads (Aggregator, Threat Intel, SNMP Poller).
    *   **Services:** Status of external dependencies (Database, NFcapd, DNS, SNMP, Threat Feeds, Syslog).
*   **Not Shown:**
    *   Detailed per-process resource usage (except for the dashboard application itself).
