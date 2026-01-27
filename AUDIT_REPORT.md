# PHOBOS-NET Dashboard Audit Report

## 1. ✅ Correct Widgets (Working as Intended)

**Overview Page**
*   **Active Alerts**: Fetches from `alertHistory.active_count`. Backend `/api/security/alerts/history` (Security).
*   **Active Flows**: Fetches from `networkStatsOverview.active_flows`. Backend `/api/network/stats/overview` (Traffic).
*   **External Connections**: Fetches from `networkStatsOverview.external_connections`. Backend `/api/network/stats/overview` (Traffic).
*   **Blocked Events**: Fetches from `firewallStatsOverview.blocked_events_24h`. Backend `/api/firewall/stats/overview` (Traffic).
*   **Network Anomalies**: Fetches from `networkStatsOverview.anomalies_count`. Backend `/api/network/stats/overview` (Traffic).
*   **Bandwidth Chart**: Uses `/api/bandwidth`. Backend verifies/simulates nfdump data.
*   **World Map**: Uses `/api/stats/worldmap`. Backend aggregates GeoIP data.

**Network Page**
*   **System Status**: Fetches from `/api/stats/net_health`. Verifies system components.
*   **Active Flows (Stat Box)**: Correctly mapped to `networkStatsOverview.active_flows`.
*   **External Connections (Stat Box)**: Correctly mapped.
*   **Top Sources/Destinations**: Uses `/api/stats/sources`, `/api/stats/destinations`.
*   **Top Ports**: Uses `/api/stats/ports`.
*   **Protocol Hierarchy**: Uses `/api/stats/protocol_hierarchy`.
*   **Traffic Matrix**: Uses `/api/hosts/list` scatter plot data.
*   **TCP Flags**: Uses `/api/stats/flags`.
*   **Packet Sizes**: Uses `/api/stats/packet_sizes`.
*   **Flow Statistics**: Uses `/api/stats/flow_stats`.
*   **Network Intelligence**: Uses `/api/network/intelligence`.
*   **Top Talkers**: Uses `/api/stats/talkers`.

**Security Page**
*   **Threats/Blocks/Matches/Alerts (Stat Boxes)**: Use `threatActivityTimeline` from `/api/security/attack-timeline`.
*   **Threat Activity Timeline (Chart)**: Uses `/api/security/attack-timeline`.
*   **Security Coverage**: Uses `/api/security/score`.
*   **Alert History**: Uses `/api/security/alerts/history`.
*   **Detections by Country**: Uses `/api/security/threats/by_country`.
*   **Feed Health**: Uses `/api/stats/feeds`.
*   **Top Malicious Ports**: Uses `/api/stats/malicious_ports`.
*   **Top Threat IPs**: Uses `/api/security/top_threat_ips`.
*   **MITRE Heatmap**: Uses `/api/security/mitre-heatmap`.
*   **Protocol Anomalies**: Uses `/api/security/protocol-anomalies`.

**Server Page**
*   **Host Strip**: Uses `/api/server/health`. Verified system metrics.
*   **Ingestion Cards (NetFlow, Syslog, Firewall)**: Use `/api/server/health` and `/api/server/ingestion`. Verified.
*   **HTTP Traffic**: Uses `/api/system/http-metrics`. Verified.
*   **Internals (Services, Process, I/O, Container)**: Use `/api/server/health`. Verified.
*   **Database Stats**: Uses `/api/server/database-stats`. Verified.
*   **Resource History**: Uses `/api/system/resource-history`. Verified.
*   **Server Logs**: Uses `/api/server/logs`. Verified.

**Forensics Page**
*   **Timeline Analysis**: Uses `/api/forensics/timeline`. Verified.
*   **Session Reconstruction**: Uses `/api/forensics/session`. Verified.
*   **Evidence Collection**: Uses `/api/forensics/evidence`. Verified.

**Firewall Page**
*   **Stats Boxes (Blocked, Unique, New, Reason)**: Use `/api/firewall/stats/overview`. Verified.
*   **Firewall Filter Logs**: Uses `/api/firewall/logs/recent`. Verified.
*   **Firewall App Logs**: Uses `/api/firewall/syslog/recent`. Verified.
*   **Active Flows (Widget)**: Uses `/api/flows`. Verified.

---

## 2. ⚠️ Suspicious Widgets (Likely Incorrect or Misleading)

**Overview Page - Health Widget**
*   **File**: `frontend/templates/tabs/overview.html` (Lines 9-13)
*   **Issue**: The "Healthy" status is hardcoded in HTML and does not reflect actual system state.
    ```html
    <div class="card" ...>
        <div ...>Healthy</div> <!-- Hardcoded -->
        <div ...>OVERALL HEALTH</div>
    </div>
    ```
*   **Recommendation**: Bind this to `netHealth.status_text` and `netHealth.status_icon` or `overallHealth.state` from `store/index.js`.

---

## 3. ❌ Broken Widgets (Data Missing or Wrong)

**Network Page - Network Anomalies Stat Box**
*   **File**: `frontend/templates/tabs/network.html` (Line 24)
*   **Issue**: Attempts to display `networkStatsOverview.anomalies_24h`.
    ```html
    <span x-text="... (networkStatsOverview.anomalies_24h || 0).toLocaleString()">...</span>
    ```
    The backend endpoint `api_network_stats_overview` (in `app/api/routes/traffic.py`) returns the key `anomalies_count`, **not** `anomalies_24h`. This causes the widget to always show "0" or fallback values.
*   **Fix**: Update template to use `networkStatsOverview.anomalies_count`.

**Global - Overall Health Modal**
*   **File**: `frontend/templates/index.html` (Line 1177)
*   **Issue**: Same as above. The modal attempts to display `networkStatsOverview.anomalies_24h`.
    ```html
    <div ... x-text="(networkStatsOverview.anomalies_24h || 0).toLocaleString()"></div>
    ```
*   **Fix**: Update template to use `networkStatsOverview.anomalies_count`.
