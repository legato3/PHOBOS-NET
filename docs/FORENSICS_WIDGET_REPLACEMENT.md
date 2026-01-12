# Forensics Page Widget Replacement Suggestions

**Date**: 2026-01-12  
**Status**: Recommendations

---

## Removed Widget

### Advanced Flow Search
**Reason for Removal**: Redundant functionality
- Filtering capabilities are already available in the Firewall Logs widget (action, IP, port, protocol, threat filters)
- IP Deep Dive Investigation modal provides comprehensive flow analysis
- The "Recent Conversations" widget already shows top flows
- Advanced search functionality overlaps with existing tools

---

## Suggested Replacement Widgets

### Option 1: **Threat Activity Timeline** (Recommended)
**Priority**: High

**Description**: Visual timeline showing threat activity patterns over time, helping identify attack waves, quiet periods, and escalation patterns.

**Features**:
- Time-series chart showing threat count over selected time range
- Interactive timeline with zoom/pan capabilities
- Color-coded by threat type or severity
- Click timeline points to view related alerts
- Filter by threat category, IP range, or country
- Export timeline data

**Benefits**:
- Provides temporal context for security events
- Helps identify attack patterns and timing
- Visual representation is easier to interpret than tables
- Complements Alert Correlation widget (shows "when" vs "what sequence")

**Data Sources**:
- `/api/security/threat_velocity` (already exists)
- Alert history timeline
- Threat feed hits over time

---

### Option 2: **Port Scanning Detection**
**Priority**: Medium

**Description**: Identifies and displays port scanning attempts, highlighting suspicious connection patterns to multiple ports from single IPs.

**Features**:
- List of IPs with port scanning behavior
- Number of unique ports scanned
- Time window of scanning activity
- Target ports visualization (heatmap or list)
- Click to investigate scanning IP
- Filter by port count threshold

**Benefits**:
- Detects reconnaissance activities early
- Helps identify potential attackers before full exploitation
- Complements firewall logs with pattern analysis
- Useful for identifying botnet activity

**Data Sources**:
- Firewall logs analysis (multiple ports from single IP)
- Flow data aggregation
- New API endpoint needed: `/api/forensics/port-scans`

---

### Option 3: **Traffic Anomaly Detection**
**Priority**: Medium

**Description**: Highlights unusual traffic patterns that deviate from normal baseline, helping identify potential security incidents.

**Features**:
- List of detected anomalies with severity scores
- Anomaly types: volume spikes, unusual protocols, off-hours activity, new destinations
- Baseline comparison (traffic vs historical average)
- Time of anomaly detection
- Click to investigate anomalous IPs/flows

**Benefits**:
- Proactive threat detection
- Identifies zero-day or unknown attack patterns
- Complements rule-based detection systems
- Helps identify data exfiltration attempts

**Data Sources**:
- Traffic statistics comparison
- Baseline calculations
- New API endpoint needed: `/api/forensics/anomalies`

---

### Option 4: **Incident Response Playbook**
**Priority**: Low

**Description**: Interactive guide with recommended actions for common security incidents, integrated with current alerts.

**Features**:
- Step-by-step response procedures
- Context-aware recommendations based on current alerts
- Quick action buttons (block IP, isolate system, escalate)
- Integration with investigation tools
- Checklist for incident response

**Benefits**:
- Standardizes incident response procedures
- Reduces response time
- Helps junior analysts follow best practices
- Provides documentation and audit trail

**Data Sources**:
- Static playbook content
- Alert correlation data
- Integration with existing blocking/investigation tools

---

## Recommendation

**Recommended**: **Threat Activity Timeline** (Option 1)

**Rationale**:
1. **High Value**: Provides unique temporal insights not available in other widgets
2. **Data Availability**: Can leverage existing threat velocity API endpoint
3. **User Experience**: Visual timeline is intuitive and complements table-based widgets
4. **Forensics Focus**: Timeline analysis is a core forensics activity
5. **Implementation**: Relatively straightforward to implement using existing Chart.js library

**Alternative**: If timeline implementation is complex, **Port Scanning Detection** (Option 2) would be a good second choice as it provides actionable intelligence for network security.

---

## Implementation Notes

### For Threat Activity Timeline:
- Use Chart.js (already in project) for timeline visualization
- Leverage `/api/security/threat_velocity` endpoint
- Add time range selector (1h, 6h, 24h, 7d)
- Integrate with Alert Correlation widget (click timeline to filter chains)
- Consider adding export functionality (PNG, CSV)

### Widget Placement:
- Position after Alert Correlation widget
- Keep IP Deep Dive Investigation search bar at top
- Maintain widget ordering: Search → Firewall Logs → Alert Correlation → New Widget → Conversations

---

**Note**: These suggestions are based on current codebase analysis and can be adjusted based on user needs and development priorities.
