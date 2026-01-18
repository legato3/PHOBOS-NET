import { API } from '../modules/api.js?v=3.0.3';
import { Charts } from '../modules/charts.js?v=3.0.3';
import { DashboardWidgets } from '../modules/widgets.js?v=3.0.3';
import * as DashboardUtils from '../modules/utils.js?v=3.0.3';

// Module-level storage for Chart.js instances to avoid Alpine.js reactivity recursion
const _chartInstances = {};

export const Store = () => ({
    initDone: false,
    activeTab: 'overview',
    mapStatus: '', // Debug status for map loading

    // Widget State
    widgetVisibility: { ...DashboardWidgets.defaultVisibility },
    minimizedWidgets: new Set(),

    // Server Widget Aliases (for macro compatibility)
    get server_cpu() { return { loading: this.serverHealth.loading }; },
    get server_memory() { return { loading: this.serverHealth.loading }; },
    get server_disk() { return { loading: this.serverHealth.loading }; },
    get server_netflow() { return { loading: this.serverHealth.loading }; },
    get server_syslog() { return { loading: this.serverHealth.loading }; },
    get server_database() { return { loading: this.serverHealth.loading }; },
    get server_system() { return { loading: this.serverHealth.loading }; },
    get server_process() { return { loading: this.serverHealth.loading }; },
    get server_network() { return { loading: this.serverHealth.loading }; },
    get server_cache() { return { loading: this.serverHealth.loading }; },

    firewall: { cpu_percent: null, mem_percent: null, sys_uptime: null, loading: false, blocks_1h: 0, blocks_per_hour: 0, unique_blocked_ips: 0, threats_blocked: 0, syslog_active: false },
    firewallStreamActive: false,
    firewallES: null,
    timeRange: '1h',
    refreshInterval: 30000,
    refreshTimer: null,
    paused: false,
    lastUpdate: '-',
    lastUpdateTs: 0,  // Unix timestamp for freshness calculation
    searchQuery: '',

    // Refresh countdown
    refreshCountdown: 30,
    countdownTimer: null,

    // Fetch cadence control
    lastFetch: {
        worldmap: 0,
        network: 0,
        security: 0,
        flows: 0,
        alertCorrelation: 0,
        threatActivityTimeline: 0
    },
    heavyTTL: 60000, // 60s for heavy widgets
    mediumTTL: 30000, // 30s for flows

    // Low Power mode
    lowPower: false,

    // Compact mode
    compactMode: false,

    // Sidebar collapse state
    sidebarCollapsed: true,

    // Server health auto-refresh
    serverHealthRefreshTimer: null,

    // Edit Mode (Layout)
    editMode: false,

    // Ollama chat state
    ollamaChat: {
        messages: [],
        inputMessage: '',
        loading: false,
        error: null,
        model: 'deepseek-coder-v2:16b',
        availableModels: ['deepseek-coder-v2:16b'], // Initialize with default model
        includeContext: true, // Include dashboard context in messages
        analysisType: 'general' // Analysis type: general, forensics, investigation, mitigation
    },

    // Forensics state
    forensics: {
        timeline: {
            targetIp: '',
            timeRange: '24h',
            loading: false,
            error: null,
            data: {
                summary: {
                    target_ip: 'N/A',
                    total_events: 0,
                    total_bytes: 0,
                    suspicious_events: 0,
                    time_range: '24h',
                    query_time: new Date().toISOString()
                },
                timeline: []
            }
        },
        session: {
            srcIp: '',
            dstIp: '',
            timeRange: '1h',
            loading: false,
            error: null,
            data: {
                summary: {
                    src_ip: 'N/A',
                    dst_ip: 'N/A',
                    session_duration_seconds: 0,
                    total_flows: 0,
                    total_bytes: 0,
                    time_range: '1h',
                    query_time: new Date().toISOString()
                },
                flows: []
            }
        },
        evidence: {
            incidentType: 'general',
            targetIps: [],
            timeRange: '24h',
            preserveData: true,
            loading: false,
            error: null,
            report: {
                incident_metadata: {
                    incident_type: 'N/A',
                    collection_timestamp: new Date().toISOString(),
                    target_ips: [],
                    severity: 'unknown'
                },
                chain_of_custody: {
                    collector: 'PHOBOS-NET',
                    collection_method: 'automated',
                    integrity_check: 'pending',
                    preservation_status: 'active'
                },
                evidence_items: [],
                recommendations: []
            }
        }
    },

    // Mobile UI state
    showMobileFilters: false,
    worldMapMobileVisible: false,

    // Sparkline cache
    sparkCache: {}, // { key: { ts, labels, bytes } }
    sparkTTL: 120000, // 2 minutes

    // Data Stores
    summary: { totals: { bytes_fmt: '...', flows: 0, avg_packet_size: 0 }, loading: true },
    sources: { sources: [], loading: true },
    destinations: { destinations: [], loading: true },
    ports: { ports: [], loading: true },
    protocols: { protocols: [], loading: true },
    maliciousPorts: { ports: [], loading: true, has_syslog: false },
    threats: { hits: [], loading: true, total_blocked: 0 },
    blocklist: { series: [], current_rate: null, total_matches: 0, total_blocked: 0, has_fw_data: false, loading: true },
    alerts: { alerts: [], loading: true },
    bandwidth: { labels: [], bandwidth: [], flows: [], loading: true },
    flows: { flows: [], loading: true, viewLimit: 15 },  // Default to 15 rows
    networkStatsOverview: { active_flows: 0, external_connections: 0, anomalies_24h: 0, trends: {}, loading: true },

    // New Features Stores
    flags: { flags: [], loading: true },
    asns: { asns: [], loading: true },
    countries: { labels: [], bytes: [], loading: true },
    durations: { durations: [], stats: {}, loading: true },
    packetSizes: { labels: [], data: [], loading: true },
    feedHealth: { feeds: [], summary: { total: 0, ok: 0, error: 0, total_ips: 0 }, loading: true },
    talkers: { talkers: [], loading: true },
    services: { services: [], maxBytes: 1, loading: true },
    hourlyTraffic: { labels: [], bytes: [], flows: [], peak_hour: 0, peak_bytes_fmt: '0 B', loading: true },
    flowStats: { total_flows: 0, avg_duration_fmt: '0s', avg_bytes_fmt: '0 B', duration_dist: {}, loading: true },
    protoMix: { labels: [], bytes: [], bytes_fmt: [], flows: [], percentages: [], colors: [], total_bytes: 0, total_bytes_fmt: '0 B', loading: true },
    protocolHierarchy: { data: null, loading: true },
    trafficScatter: { data: null, loading: true },

    netHealth: { indicators: [], health_score: 100, status: 'healthy', status_icon: '💚', loading: true, firewall_active: false, blocks_1h: 0 },
    serverHealth: { cpu: {}, memory: {}, disk: {}, syslog: {}, netflow: {}, database: {}, loading: true },
    ingestionRates: null,
    databaseStats: { databases: [], loading: true, error: null },
    serverLogs: { logs: [], count: 0, loading: true, source: 'none', container: '', lines: 100 },

    // Unified Insight System - reusable across Traffic, Firewall, Hosts
    insightPanels: {
        traffic: {
            insights: [],
            expanded: false,
            loading: true,
            history: [],
            config: {
                type: 'traffic',
                title: 'Traffic Insights',
                icon: '💡',
                minThreshold: 0.05, // 5% minimum for talkers/ports
                protocolThreshold: 0.10, // 10% minimum for protocols
                commonPorts: [80, 443, 53] // Exclude from notable ports
            }
        },
        firewall: {
            insights: [],
            expanded: false,
            loading: true,
            history: [],
            config: {
                type: 'firewall',
                title: 'Firewall Insights',
                icon: '🛡️',
                minThreshold: 0.05
            }
        },
        hosts: {
            insights: [],
            expanded: false,
            loading: true,
            history: [],
            config: {
                type: 'hosts',
                title: 'Host Insights',
                icon: '🖥️',
                minThreshold: 0.05
            }
        }
    },

    // Legacy alias for backward compatibility
    get trafficInsights() {
        return this.insightPanels.traffic;
    },
    hosts: {
        stats: { total_hosts: 0, active_hosts: 0, new_hosts: '—', anomalies: 0 },
        list: [],
        loading: true,
        viewMode: 'observed',
        discovery: {
            loading: false,
            results: null,
            subnets: [],
            target: '',
            error: null
        }
    },

    // Security Features
    securityObservability: {
        overall_state: 'UNKNOWN',
        contributing_factors: [],
        protection_signals: [],
        exposure_signals: [],
        data_quality_signals: [],
        loading: true,
        last_updated: null
    },
    alertHistory: { alerts: [], total: 0, by_severity: {}, loading: true },
    threatsByCountry: { countries: [], total_blocked: 0, has_fw_data: false, loading: true },
    watchlist: { watchlist: [], count: 0, loading: true },
    watchlistInput: '',
    alertHistoryOpen: false,
    watchlistModalOpen: false,
    ipInvestigationModalOpen: false,
    flowDetailsModalOpen: false,
    selectedFlow: null,
    eventDetailsModalOpen: false,
    selectedEvent: null,
    selectedEventType: null, // 'flow', 'firewall', 'threat'
    threatVelocity: { current: 0, trend: 0, total_24h: 0, peak: 0, loading: true },
    topThreatIPs: { ips: [], loading: true },

    // New Security Widgets
    attackTimeline: { timeline: [], peak_hour: null, peak_count: 0, total_24h: 0, fw_blocks_24h: 0, has_fw_data: false, loading: true },
    mitreHeatmap: { techniques: [], by_tactic: {}, total_techniques: 0, loading: true },
    protocolAnomalies: { protocols: [], anomaly_count: 0, loading: true },
    recentBlocks: { blocks: [], total_1h: 0, loading: true, stats: { total: 0, actions: {}, threats: 0, unique_src: 0, unique_dst: 0, blocks_last_hour: 0, passes_last_hour: 0 }, lastUpdate: null },
    recentBlocksView: 50,
    recentBlocksFilter: { action: 'all', searchIP: '', port: '', protocol: 'all', threatOnly: false },
    recentBlocksAutoRefresh: true,
    recentBlocksRefreshTimer: null,

    // Firewall Syslog (Port 515) widget state
    firewallSyslog: { blocks: [], total_1h: 0, loading: true, stats: { total: 0, actions: {}, threats: 0, unique_src: 0, unique_dst: 0, blocks_last_hour: 0, passes_last_hour: 0 }, lastUpdate: null },
    firewallSyslogView: 50,
    firewallSyslogFilter: { action: 'all', searchIP: '', port: '', protocol: 'all', threatOnly: false },
    firewallSyslogAutoRefresh: true,
    firewallSyslogRefreshTimer: null,
    firewallStatsOverview: { blocked_events_24h: 0, unique_blocked_sources: 0, new_blocked_ips: 0, top_block_reason: 'N/A', top_block_count: 0, trends: {}, loading: true },
    baselineSignals: { signals: [], signal_details: [], metrics: {}, baselines_available: {}, loading: true },
    appMetadata: { name: 'PHOBOS-NET', version: 'v1.1.0', version_display: 'v1.1' }, // Application metadata from backend
    overallHealthModalOpen: false, // Modal for detailed health information
    mobileControlsModalOpen: false, // Modal for mobile controls (search, time range, refresh, etc.)
    mobileMoreModalOpen: false, // Modal for expanded mobile navigation
    firewallSNMP: { cpu_percent: null, memory_percent: null, active_sessions: null, total_throughput_mbps: null, uptime_formatted: null, interfaces: [], last_poll: null, poll_success: true, traffic_correlation: null, loading: true, error: null },
    firewallSNMPRefreshTimer: null,
    _firewallSNMPFetching: false,

    // Firewall Investigation Tools
    ipInvestigation: { searchIP: '', result: null, loading: false, error: null, timeline: { labels: [], bytes: [], flows: [], loading: false, compareHistory: false } },
    flowSearch: { filters: { srcIP: '', dstIP: '', port: '', protocol: '', country: '' }, results: [], loading: false },
    alertCorrelation: { chains: [], loading: false, showExplanation: false },
    threatActivityTimeline: { timeline: [], peak_hour: null, peak_count: 0, total_24h: 0, loading: true, timeRange: '24h', showDescription: false },

    // Alert Filtering
    alertFilter: { severity: 'all', type: 'all' },
    alertTypes: ['all', 'threat_ip', 'port_scan', 'brute_force', 'data_exfil', 'dns_tunneling', 'lateral_movement', 'suspicious_port', 'large_transfer', 'watchlist', 'off_hours', 'new_country', 'protocol_anomaly', 'tcp_reset', 'syn_scan', 'icmp_anomaly', 'tiny_flows', 'traffic_anomaly'],

    // Settings / Status
    notify: { email: true, webhook: true, muted: false },
    threatStatus: { status: '', last_ok: 0 },
    dismissedAlerts: new Set(JSON.parse(localStorage.getItem('dismissedAlerts') || '[]')),

    // Widget Management
    widgetVisibility: {},
    minimizedWidgets: new Set(JSON.parse(localStorage.getItem('minimizedWidgets') || '[]')),
    widgetManagerOpen: false,

    // Intersection Observer State
    visibleSections: new Set(),
    observer: null,

    // UI Labels for Widgets - Using DashboardWidgets module
    get friendlyLabels() {
        return (typeof DashboardWidgets !== 'undefined' && DashboardWidgets.friendlyLabels) || {
            summary: 'Summary Stats',
            bandwidth: 'Bandwidth & Flow Rate',
            firewall: 'Firewall Health',
            analytics: 'Analytics Row',
            topstats: 'Top Stats Row',
            flags: 'TCP Flags',
            asns: 'Top ASNs',
            countries: 'Traffic by Country',
            durations: 'Long Flows',
            packetSizes: 'Packet Sizes',
            sources: 'Top Sources',
            destinations: 'Top Destinations',
            ports: 'Top Ports',
            protocols: 'Protocols',
            threats: 'Threat Detections',
            maliciousPorts: 'Top Malicious Ports',
            blocklist: 'Blocklist Match Rate',
            feedHealth: 'Feed Health',
            securityObservability: 'Security Observability',
            alertHistory: 'Alert History',
            threatsByCountry: 'Threats by Country',
            threatVelocity: 'Threat Trend (1h)',
            topThreatIPs: 'Top Threat IPs',
            conversations: 'Active Flows',
            alertCorrelation: 'Alert Correlation & Attack Chains',
            threatActivityTimeline: 'Threat Activity Timeline',
            talkers: 'Top Talkers',
            services: 'Top Services',
            hourlyTraffic: 'Traffic by Hour',
            flowStats: 'Flow Statistics',

            netHealth: 'Network Health',
            insights: 'Traffic Insights',
            mitreHeatmap: 'Detected Techniques',
            protocolAnomalies: 'Protocol Anomalies',
            attackTimeline: 'Attack Timeline',
            recentBlocks: 'Firewall Logs'
        };
    },

    // Thresholds (editable)
    thresholds: {
        util_warn: 70, util_crit: 90,
        resets_warn: 0.1, resets_crit: 1.0,
        ip_err_warn: 0.1, ip_err_crit: 1.0,
        icmp_err_warn: 0.1, icmp_err_crit: 1.0,
        if_err_warn: 0.1, if_err_crit: 1.0,
        tcp_fails_warn: 0.5, tcp_fails_crit: 2.0,
        tcp_retrans_warn: 1.0, tcp_retrans_crit: 5.0
    },
    thresholdsModalOpen: false,

    // Configuration Settings Modal
    configModalOpen: false,
    configLoading: false,
    configSaving: false,
    config: {
        dns_server: '',
        snmp_host: '',
        snmp_community: '',
        snmp_poll_interval: 2,
        internal_networks: '',
        // Analysis settings
        default_time_range: '1h',
        refresh_interval: 30000
    },

    // Firewall Detail Modal
    fwDetailOpen: false,
    fwDetailType: null,
    fwDetails: {
        cpu: {
            title: '🔥 CPU Usage',
            description: 'Shows the current CPU utilization of your OPNsense firewall. High CPU usage can indicate heavy traffic processing, active VPN connections, or IDS/IPS inspection.',
            fields: ['cpu_percent', 'cpu_load_1min', 'cpu_load_5min'],
            thresholds: { warning: 70, critical: 90 },
            tips: ['Consider enabling hardware offloading if consistently high', 'Check for runaway processes in OPNsense shell', 'Review IDS/IPS rules if Suricata is enabled']
        },
        memory: {
            title: '💾 Memory Usage',
            description: 'RAM utilization on the firewall. OPNsense uses memory for state tables, caching, and services like Unbound DNS or Suricata.',
            fields: ['mem_percent', 'mem_used', 'mem_total', 'swap_percent'],
            thresholds: { warning: 70, critical: 90 },
            tips: ['High memory with low swap is normal', 'Check state table size if memory is high', 'Consider adding RAM if swap usage is significant']
        },
        uptime: {
            title: '⏱️ System Uptime',
            description: 'How long the firewall has been running since last reboot. Longer uptimes indicate stability.',
            fields: ['sys_uptime_formatted'],
            tips: ['Schedule periodic maintenance reboots after updates', 'Unexpected reboots may indicate hardware issues']
        },
        interfaces: {
            title: '🔌 Interface Status',
            description: 'Shows whether WAN and LAN interfaces are up and operational. Down interfaces will appear red.',
            fields: ['if_wan_status', 'if_lan_status'],
            tips: ['Check cable connections if interface is down', 'Review interface assignments in OPNsense']
        },
        wan_traffic: {
            title: '🌐 WAN Traffic',
            description: 'Current throughput on your WAN (internet) interface in Megabits per second. Shows download (RX) and upload (TX) rates.',
            fields: ['wan_rx_mbps', 'wan_tx_mbps', 'wan_in', 'wan_out'],
            tips: ['Compare against your ISP plan speeds', 'Sustained high usage may need bandwidth management']
        },
        lan_traffic: {
            title: '🏠 LAN Traffic',
            description: 'Current throughput on your LAN interface. High LAN traffic with low WAN may indicate local file transfers.',
            fields: ['lan_rx_mbps', 'lan_tx_mbps'],
            tips: ['Gigabit LAN can handle ~125 MB/s', 'Check for broadcast storms if unusually high']
        },
        tcp_activity: {
            title: '🔗 TCP Activity',
            description: 'Active TCP connection opens and established connection resets. High resets may indicate connection issues or attacks.',
            fields: ['tcp_active_opens_s', 'tcp_estab_resets_s', 'tcp_conns'],
            thresholds: { warning: 5, critical: 20 },
            tips: ['Some resets are normal (timeouts, closed connections)', 'Sudden spikes may indicate port scanning', 'Check firewall logs for blocked connections']
        },
        tcp_reliability: {
            title: '📡 TCP Reliability',
            description: 'TCP connection failures and retransmissions. High values indicate network congestion or packet loss.',
            fields: ['tcp_fails_s', 'tcp_retrans_s'],
            thresholds: { warning: 1, critical: 5 },
            tips: ['Check for duplex mismatches on interfaces', 'High retrans may indicate congested links', 'Consider QoS if latency-sensitive apps are affected']
        },
        if_errors: {
            title: '⚠️ Interface Errors',
            description: 'Packet errors on WAN and LAN interfaces. Errors may indicate cable issues, duplex mismatches, or hardware problems.',
            fields: ['wan_in_err_s', 'wan_out_err_s', 'lan_in_err_s', 'lan_out_err_s'],
            thresholds: { warning: 0.1, critical: 1 },
            tips: ['Check cable quality and connections', 'Verify auto-negotiation settings', 'Consider replacing network cables']
        },
        ip_errors: {
            title: '🔢 IP/ICMP Errors',
            description: 'IP header errors, address errors, and ICMP errors. These may indicate misconfigured clients or routing issues.',
            fields: ['ip_in_hdr_errors_s', 'ip_in_addr_errors_s', 'ip_in_discards_s', 'icmp_in_errors_s'],
            thresholds: { warning: 0.1, critical: 1 },
            tips: ['Check for misconfigured DHCP clients', 'Review routing table for conflicts', 'ICMP errors often come from unreachable hosts']
        },
        disk_io: {
            title: '💿 Disk I/O',
            description: 'Disk read and write activity. High I/O may occur during logging, package updates, or if swap is being used.',
            fields: ['disk_read', 'disk_write'],
            tips: ['Consistent high I/O may indicate logging issues', 'Consider SSD if using HDD', 'Check for large log files']
        }
    },

    openFwDetail(type) {
        this.fwDetailType = type;
        this.fwDetailOpen = true;
    },

    closeFwDetail() {
        this.fwDetailOpen = false;
        this.fwDetailType = null;
    },

    getFwValue(field) {
        const val = this.firewall[field];
        if (val === null || val === undefined) return '--';
        if (field.includes('percent')) return val + '%';
        if (field.includes('_s') || field.includes('_mbps')) return val.toFixed(2);
        if (field === 'mem_used' || field === 'mem_total') return DashboardUtils.formatBytes(val * 1024);
        if (field === 'wan_in' || field === 'wan_out' || field === 'disk_read' || field === 'disk_write') return this.fmtBytes(val);
        if (field === 'if_wan_status' || field === 'if_lan_status') return val === '1' ? 'UP' : 'DOWN';
        return val;
    },

    // Modal
    modalOpen: false,
    selectedIP: null,
    ipDetails: null,
    ipLoading: false,

    // Expanded Data Modal
    expandedModalOpen: false,
    expandedTitle: '',
    expandedColumns: [],
    expandedData: [],
    expandedLoading: false,

    // Network Graph
    networkGraphOpen: false,

    // Conversation View (List/Sankey)
    sankeyChartInstance: null,

    // World Map
    worldMap: { loading: false, sources: [], destinations: [], threats: [], blocked: [], source_countries: [], dest_countries: [], threat_countries: [], blocked_countries: [], summary: null, lastUpdate: null },
    worldMapLayers: { sources: true, destinations: true, threats: true, blocked: false },
    worldMapMode: 'traffic', // 'exposure', 'attacks', 'traffic'
    worldMapSelectedCountry: null, // ISO code of selected country for highlighting
    worldMapHoveredPoint: null, // Currently hovered point for direction context
    insights: { loading: false }, // Dummy object for insights widget (uses data from other widgets)
    map: null,
    mapLayers: [],

    map: null,
    mapLayers: [],

    // Chart instances are now stored in _chartInstances
    // bwChartInstance: null,
    // flagsChartInstance: null,
    // pktSizeChartInstance: null,
    // hourlyChartInstance: null,
    // hourlyChart2Instance: null,

    trendModalOpen: false,
    trendIP: null,
    trendKind: 'source',
    trendChartInstance: null,

    // Fullscreen Chart Mode
    fullscreenChart: null, // { chartId, title, chartInstance }
    fullscreenChartInstance: null,

    // API Latency Tracking
    apiLatency: null,
    apiLatencyHistory: [],

    async fetchAppMetadata() {
        try {
            const res = await fetch('/api/app/metadata');
            if (res.ok) {
                const data = await res.json();
                this.appMetadata = {
                    name: data.name || 'PHOBOS-NET',
                    version: data.version || 'v1.1.0',
                    version_display: data.version_display || 'v1.1'
                };
            }
        } catch (e) {
            console.warn('Failed to fetch app metadata:', e);
            // Keep defaults
        }
    },

    // Hosts Tab
    async openHostDetail(ip, extraData = {}) {
        this.selectedIP = ip;
        this.ipLoading = true;
        this.ipDetails = { ...extraData, timeline: { labels: [], bytes: [], flows: [], loading: true } };
        this.modalOpen = true;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            // Fetch host details and timeline in parallel
            const [detailRes, timelineRes] = await Promise.all([
                safeFetchFn(`/api/hosts/${ip}/detail`),
                safeFetchFn(`/api/hosts/${ip}/timeline?range=24h`)
            ]);

            if (detailRes.ok) {
                const data = await detailRes.json();
                this.ipDetails = { ...data, ...extraData, timeline: this.ipDetails.timeline };
            }

            if (timelineRes.ok) {
                const timelineData = await timelineRes.json();
                this.ipDetails.timeline = {
                    labels: timelineData.labels || [],
                    bytes: timelineData.bytes || [],
                    flows: timelineData.flows || [],
                    loading: false
                };
                // Render timeline chart after DOM update
                this.$nextTick(() => {
                    this.renderHostTimelineChart();
                });
            } else {
                this.ipDetails.timeline.loading = false;
            }
        } catch (e) {
            console.error('Failed to load host detail:', e);
            this.ipDetails = { error: 'Failed to load details', ...extraData, timeline: { labels: [], bytes: [], flows: [], loading: false } };
        } finally {
            this.ipLoading = false;
        }
    },

    renderHostTimelineChart() {
        try {
            const canvas = document.getElementById('hostDetailTimelineChart');
            if (!canvas || !this.ipDetails?.timeline || !this.ipDetails.timeline.labels || this.ipDetails.timeline.labels.length === 0) {
                return;
            }

            if (typeof Chart === 'undefined') {
                setTimeout(() => this.renderHostTimelineChart(), 100);
                return;
            }

            const ctx = canvas.getContext('2d');
            if (_chartInstances['_hostDetailTimelineChart']) {
                _chartInstances['_hostDetailTimelineChart'].destroy();
            }

            const labels = this.ipDetails.timeline.labels;
            const bytes = this.ipDetails.timeline.bytes;
            const flows = this.ipDetails.timeline.flows;

            // Simple single-line chart showing bytes (most relevant for activity)
            _chartInstances['_hostDetailTimelineChart'] = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Activity',
                        data: bytes,
                        borderColor: this.getCssVar('--neon-cyan') || 'rgba(0, 243, 255, 0.6)',
                        backgroundColor: 'rgba(0, 243, 255, 0.05)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 3,
                        borderWidth: 1.5
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: this.getCssVar('--neon-cyan') || 'rgba(0, 243, 255, 1)',
                            borderWidth: 1,
                            callbacks: {
                                label: (context) => {
                                    const bytes = context.parsed.y;
                                    const flowIdx = context.dataIndex;
                                    const flowCount = flows[flowIdx] || 0;
                                    return [
                                        `Bytes: ${this.fmtBytes(bytes)}`,
                                        `Flows: ${flowCount.toLocaleString()}`
                                    ];
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            display: true,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.05)',
                                drawBorder: false
                            },
                            ticks: {
                                color: this.getCssVar('--text-secondary') || '#888',
                                maxRotation: 45,
                                minRotation: 45,
                                maxTicksLimit: 12,
                                callback: (value, index) => {
                                    // Show only hour (e.g., "12:00")
                                    const label = labels[index];
                                    if (!label) return '';
                                    return label.split(' ')[1] || label;
                                }
                            }
                        },
                        y: {
                            display: true,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.05)',
                                drawBorder: false
                            },
                            ticks: {
                                color: this.getCssVar('--text-secondary') || '#888',
                                callback: (value) => {
                                    return this.fmtBytes(value);
                                }
                            }
                        }
                    },
                    interaction: {
                        mode: 'index',
                        intersect: false
                    }
                }
            });
        } catch (e) {
            console.error('Host timeline chart render error:', e);
        }
    },

    closeHostDetail() {
        this.hostDetailOpen = false;
        this.selectedHost = null;
    },

    init() {
        // Polyfill requestIdleCallback for better browser support
        const idleCallback = window.requestIdleCallback || ((cb) => setTimeout(cb, 1));

        // Mark as initialized immediately for rendering
        this.initDone = true;

        // Fetch app metadata early (non-blocking)
        this.fetchAppMetadata();

        // Defer heavy initialization to avoid blocking initial render
        idleCallback(() => {
            this.loadWidgetPreferences();
            this.loadCompactMode();
            this.loadSidebarState();
            this.startIntersectionObserver();
            // Defer data loading slightly to allow initial paint
            setTimeout(() => {
                this.loadAll();
            }, 50);
            this.loadNotifyStatus();
            this.loadThresholds();
            // Initialize drag-and-drop after DOM paints
            this.$nextTick(() => this.setupDragAndDrop());
            this.startTimer();

            // Start real-time firewall stream (SSE) if supported
            this.startFirewallStream();

            // Keyboard shortcuts
            this.setupKeyboardShortcuts();

            // Start countdown timer
            this.startCountdown();
        }, { timeout: 100 });

        // Watchers
        this.$watch('timeRange', () => {
            // Reset all fetch timestamps to force refresh with new time range
            this.lastFetch = {
                summary: 0, network: 0, security: 0, server: 0,
                firewall: 0, hosts: 0, forensics: 0, worldmap: 0
            };
            this.loadAll();
        });
        this.$watch('activeTab', (val) => {
            this.$nextTick(() => {
                this.loadTab(val);
                // Resize charts if needed when tab becomes visible
                window.dispatchEvent(new Event('resize'));
                // Manage firewall logs auto-refresh based on active tab
                if (val === 'forensics') {
                    this.startRecentBlocksAutoRefresh();
                } else if (val === 'firewall') {
                    this.startRecentBlocksAutoRefresh();
                    this.startFirewallSyslogAutoRefresh();
                } else {
                    if (this.recentBlocksRefreshTimer) {
                        clearInterval(this.recentBlocksRefreshTimer);
                        this.recentBlocksRefreshTimer = null;
                    }
                    if (this.firewallSyslogRefreshTimer) {
                        clearInterval(this.firewallSyslogRefreshTimer);
                        this.firewallSyslogRefreshTimer = null;
                    }
                }
                // Manage server health auto-refresh
                if (val === 'server') {
                    this.startServerHealthAutoRefresh();
                } else {
                    if (this.serverHealthRefreshTimer) {
                        clearInterval(this.serverHealthRefreshTimer);
                        this.serverHealthRefreshTimer = null;
                    }
                }
            });
        });
        this.$watch('refreshInterval', () => {
            this.startTimer();
        });
        this.$watch('compactMode', (v) => {
            document.body.classList.toggle('compact-mode', v);
            localStorage.setItem('compactMode', v ? '1' : '0');
        });
        this.$watch('paused', (val) => {
            if (!val) {
                this.startServerHealthAutoRefresh();
            }
        });
        this.$watch('sidebarCollapsed', (v) => {
            document.body.classList.toggle('sidebar-collapsed', v);
            localStorage.setItem('sidebarCollapsed', v ? '1' : '0');
        });
        this.$watch('lowPower', (v) => {
            if (v) {
                this.heavyTTL = 120000; // 120s
                this.mediumTTL = 60000;  // 60s
                this.refreshInterval = Math.max(this.refreshInterval, 60000);
            } else {
                this.heavyTTL = 60000;
                this.mediumTTL = 30000;
                this.refreshInterval = Math.min(this.refreshInterval, 30000);
            }
            this.startTimer();
        });
        // Watch for layer toggle changes to re-render map
        this.$watch('worldMapLayers.sources', () => this.renderWorldMap());
        this.$watch('worldMapLayers.destinations', () => this.renderWorldMap());
        this.$watch('worldMapLayers.threats', () => this.renderWorldMap());
        this.$watch('worldMapMode', () => this.renderWorldMap());
        this.$watch('worldMapSelectedCountry', () => this.renderWorldMap());

        // Watch editMode to toggle draggable state
        this.$watch('editMode', (val) => {
            const grids = document.querySelectorAll('.grid[data-reorder="true"][data-grid-id]');
            grids.forEach(grid => {
                Array.from(grid.children).forEach(card => {
                    if (!card.classList.contains('wide-card')) {
                        card.setAttribute('draggable', val.toString());
                    }
                });
            });

            if (val) {
                // Show notification or visual cue
                document.body.classList.add('edit-mode-active');
            } else {
                document.body.classList.remove('edit-mode-active');
            }
        });

        // Don't initialize map here - let IntersectionObserver handle it when section becomes visible
        // This is more reliable than trying to guess when Alpine.js has rendered the tab
    },

    startIntersectionObserver() {
        const options = {
            root: null,
            rootMargin: '100px', // Preload 100px before appearing
            threshold: 0.1
        };

        this.observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                const sectionId = entry.target.id;
                if (entry.isIntersecting) {
                    this.visibleSections.add(sectionId);
                    // Trigger a fetch if we just became visible
                    this.fetchSectionData(sectionId);
                } else {
                    this.visibleSections.delete(sectionId);
                }
            });
        }, options);

        // Observe all main sections
        ['section-summary', 'section-worldmap', 'section-analytics', 'section-topstats', 'section-security', 'section-flows'].forEach(id => {
            const el = document.getElementById(id);
            if (el) this.observer.observe(el);
        });
    },

    isSectionVisible(id) {
        // If observer not ready or section explicitly visible set, assume true to be safe
        if (!this.observer) return true;
        return this.visibleSections.has(id);
    },

    // Helper to get CSS variable value - Using DashboardUtils module
    getCssVar(name) {
        return DashboardUtils.getCssVar(name);
    },

    // Helper to get color for security state (kept for backward compatibility)
    getStateColor(state) {
        const stateColors = {
            'STABLE': this.getCssVar('--signal-ok') || '#00ff88',
            'ELEVATED': this.getCssVar('--signal-warn') || '#ffb400',
            'DEGRADED': '#cc8400',
            'UNDER PRESSURE': this.getCssVar('--signal-crit') || '#ff1744',
            'UNKNOWN': this.getCssVar('--text-muted') || '#888'
        };
        return stateColors[state] || stateColors['UNKNOWN'];
    },

    // Helper to get coverage quality label
    getCoverageLabel(ok, total) {
        if (!total || total === 0) return 'Unknown';
        const ratio = ok / total;
        if (ratio >= 0.9) return 'Excellent';
        if (ratio >= 0.7) return 'Good';
        return 'Limited';
    },

    // Helper to get coverage quality CSS class
    getCoverageClass(ok, total) {
        if (!total || total === 0) return '';
        const ratio = ok / total;
        if (ratio >= 0.9) return 'excellent';
        if (ratio >= 0.7) return 'good';
        return 'limited';
    },

    // Helper to format value or show '—' for unavailable data
    // Distinguishes between: null/undefined (unavailable) vs 0 (true zero)
    formatOrDash(value, formatter = null) {
        if (value === null || value === undefined) return '—';
        if (formatter) return formatter(value);
        return value;
    },

    // Helper to format number or show '—' for unavailable
    formatNumOrDash(value) {
        if (value === null || value === undefined) return '—';
        return Number(value).toLocaleString();
    },

    // UI state for details toggle
    showObservabilityDetails: false,

    // Tools state
    tools: {
        dns: { query: '', type: 'A', loading: false, result: null, error: null },
        port: { host: '', ports: '', loading: false, result: null, error: null },
        ping: { host: '', mode: 'ping', loading: false, result: null, error: null },
        reputation: { ip: '', loading: false, result: null, error: null },
        whois: { query: '', loading: false, result: null, error: null },
        shell: { command: '', history: [], historyIndex: -1, output: '', loading: false, error: null }
    },

    // DNS Lookup
    async runDnsLookup() {
        this.tools.dns.loading = true;
        this.tools.dns.error = null;
        this.tools.dns.result = null;
        try {
            const response = await fetch(`/api/tools/dns?query=${encodeURIComponent(this.tools.dns.query)}&type=${this.tools.dns.type}`);
            const data = await response.json();
            if (data.error) {
                this.tools.dns.error = data.error;
            } else {
                this.tools.dns.result = data.result || JSON.stringify(data, null, 2);
            }
        } catch (e) {
            this.tools.dns.error = 'Failed to perform DNS lookup: ' + e.message;
        }
        this.tools.dns.loading = false;
    },

    // Port Check
    async runPortCheck() {
        this.tools.port.loading = true;
        this.tools.port.error = null;
        this.tools.port.result = null;
        try {
            const response = await fetch(`/api/tools/port-check?host=${encodeURIComponent(this.tools.port.host)}&ports=${encodeURIComponent(this.tools.port.ports)}`);
            const data = await response.json();
            if (data.error) {
                this.tools.port.error = data.error;
            } else {
                this.tools.port.result = data.results || [];
            }
        } catch (e) {
            this.tools.port.error = 'Failed to check ports: ' + e.message;
        }
        this.tools.port.loading = false;
    },

    // Ping / Traceroute
    async runPing() {
        this.tools.ping.loading = true;
        this.tools.ping.error = null;
        this.tools.ping.result = null;
        try {
            const response = await fetch(`/api/tools/ping?host=${encodeURIComponent(this.tools.ping.host)}&mode=${this.tools.ping.mode}`);
            const data = await response.json();
            if (data.error) {
                this.tools.ping.error = data.error;
            } else {
                this.tools.ping.result = data.result || '';
            }
        } catch (e) {
            this.tools.ping.error = 'Failed to run ' + this.tools.ping.mode + ': ' + e.message;
        }
        this.tools.ping.loading = false;
    },

    // IP Reputation Check
    async runReputationCheck() {
        this.tools.reputation.loading = true;
        this.tools.reputation.error = null;
        this.tools.reputation.result = null;
        try {
            const response = await fetch(`/api/tools/reputation?ip=${encodeURIComponent(this.tools.reputation.ip)}`);
            const data = await response.json();
            if (data.error) {
                this.tools.reputation.error = data.error;
            } else {
                this.tools.reputation.result = data;
            }
        } catch (e) {
            this.tools.reputation.error = 'Failed to check reputation: ' + e.message;
        }
        this.tools.reputation.loading = false;
    },

    // Whois / ASN Lookup
    async runWhoisLookup() {
        this.tools.whois.loading = true;
        this.tools.whois.error = null;
        this.tools.whois.result = null;
        try {
            const response = await fetch(`/api/tools/whois?query=${encodeURIComponent(this.tools.whois.query)}`);
            const data = await response.json();
            if (data.error) {
                this.tools.whois.error = data.error;
            } else {
                this.tools.whois.result = data;
            }
        } catch (e) {
            this.tools.whois.error = 'Failed to perform lookup: ' + e.message;
        }
        this.tools.whois.loading = false;
    },

    // Shell Terminal
    async runShellCommand() {
        const cmd = this.tools.shell.command.trim();
        if (!cmd) return;

        // Add to history
        this.tools.shell.history.push(cmd);
        if (this.tools.shell.history.length > 50) this.tools.shell.history.shift();
        this.tools.shell.historyIndex = -1; // Reset history navigation

        this.tools.shell.loading = true;
        this.tools.shell.error = null;

        // Append command to output immediately
        const timestamp = new Date().toLocaleTimeString();
        this.tools.shell.output = (this.tools.shell.output || '') + `\n[${timestamp}] $ ${cmd}\n`;

        try {
            const response = await fetch('/api/tools/shell', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: cmd })
            });
            const data = await response.json();

            if (response.ok) {
                this.tools.shell.output += data.output;
                if (data.error) {
                    this.tools.shell.output += `\nError: ${data.error}`;
                }
            } else {
                this.tools.shell.error = data.error || 'Command failed';
                this.tools.shell.output += `\nError: ${data.error || 'Command failed'}`;
            }
        } catch (e) {
            this.tools.shell.error = 'Execution error: ' + e.message;
            this.tools.shell.output += `\nExecution error: ${e.message}`;
        }

        this.tools.shell.output += '\n';
        this.tools.shell.command = ''; // Clear input
        this.tools.shell.loading = false;

        // Auto-scroll to bottom using x-ref
        this.$nextTick(() => {
            const terminal = this.$refs.terminalOutput;
            if (terminal) terminal.scrollTop = terminal.scrollHeight;
        });
    },

    shellHistoryUp() {
        const history = this.tools.shell.history;
        if (history.length === 0) return;

        if (this.tools.shell.historyIndex === -1) {
            this.tools.shell.historyIndex = history.length - 1;
        } else if (this.tools.shell.historyIndex > 0) {
            this.tools.shell.historyIndex--;
        }

        this.tools.shell.command = history[this.tools.shell.historyIndex];
    },

    shellHistoryDown() {
        const history = this.tools.shell.history;
        if (history.length === 0 || this.tools.shell.historyIndex === -1) return;

        if (this.tools.shell.historyIndex < history.length - 1) {
            this.tools.shell.historyIndex++;
            this.tools.shell.command = history[this.tools.shell.historyIndex];
        } else {
            this.tools.shell.historyIndex = -1;
            this.tools.shell.command = '';
        }
    },

    exportAlerts() {
        const alerts = this.alerts.alerts || [];
        const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `alerts-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
    },

    getFlagColor(index) {
        // Return color for flag at given index - matches chart colors
        const cyanColor = this.getCssVar('--accent-cyan') || this.getCssVar('--signal-primary') || '#00eaff';
        const purpleColor = this.getCssVar('--accent-magenta') || this.getCssVar('--signal-tertiary') || '#7b7bff';
        const greenColor = this.getCssVar('--signal-ok') || '#00ff88';
        const redColor = this.getCssVar('--signal-crit') || '#ff1744';
        const yellowColor = this.getCssVar('--signal-warn') || '#ffb400';
        const colors = [cyanColor, purpleColor, greenColor, redColor, yellowColor, '#ffffff'];
        return colors[index] || colors[0];
    },

    get activeAlerts() {
        if (!this.alerts.alerts) return [];
        return this.alerts.alerts.filter(a => !this.dismissedAlerts.has(a.msg));
    },

    get groupedAlerts() {
        const groups = {};
        const order = ['critical', 'high', 'medium', 'low', 'info'];

        // Sort active alerts by order then group
        const sorted = this.activeAlerts.sort((a, b) => {
            return order.indexOf(a.severity) - order.indexOf(b.severity);
        });

        sorted.forEach(a => {
            const s = a.severity.toUpperCase();
            if (!groups[s]) groups[s] = [];
            groups[s].push(a);
        });
        return groups;
    },

    // Overall Health: Deterministic, explainable health state
    // Unhealthy (red) reserved for: Active alerts OR multiple critical signals
    // Degraded (amber) for: High volume without alerts
    // Uses baseline-aware signals when available, falls back to static thresholds
    get overallHealth() {
        // Inputs: Active Alerts, Network Anomalies, Firewall Blocks, External Connections
        const activeAlerts = this.alertHistory.total || 0;
        const anomalies = this.networkStatsOverview.anomalies_24h || 0;
        const blockedEvents = this.firewallStatsOverview.blocked_events_24h || 0;
        const externalConnections = this.networkStatsOverview.external_connections || 0;
        const activeFlows = this.networkStatsOverview.active_flows || 0;

        // Use baseline-aware signals if available, otherwise use static thresholds
        const baselineSignals = this.baselineSignals.signals || [];
        const baselineDetails = this.baselineSignals.signal_details || [];
        const baselinesAvailable = this.baselineSignals.baselines_available || {};

        const signals = [];
        const signalDetails = [];

        // Signal 1: Active Alerts (critical - always elevates to Unhealthy if present)
        const hasAlerts = activeAlerts > 0;
        if (hasAlerts) {
            signals.push('alerts');
            signalDetails.push(`${activeAlerts} active alert${activeAlerts > 1 ? 's' : ''}`);
        }

        // Use baseline-aware signals if available
        if (baselineSignals.length > 0 && Object.values(baselinesAvailable).some(v => v === true)) {
            // Add baseline-aware signals (excluding anomalies_present which we handle separately)
            baselineSignals.forEach((signal, idx) => {
                if (signal !== 'anomalies_present' && !signals.includes(signal)) {
                    signals.push(signal);
                    if (baselineDetails[idx]) {
                        signalDetails.push(baselineDetails[idx]);
                    }
                }
            });

            // Handle anomalies separately (always include if present, even if not spiking)
            const hasAnomalies = anomalies > 0;
            if (hasAnomalies && !signals.includes('anomalies')) {
                signals.push('anomalies');
                signalDetails.push(`${anomalies} network anomal${anomalies > 1 ? 'ies' : 'y'}`);
            }
        } else {
            // Fallback to static thresholds when baselines not available
            // Signal 2: Network Anomalies (sustained high volume)
            const hasAnomalies = anomalies > 0;
            if (hasAnomalies) {
                signals.push('anomalies');
                signalDetails.push(`${anomalies} network anomal${anomalies > 1 ? 'ies' : 'y'}`);
            }

            // Signal 3: Firewall Blocks spike (threshold: > 1000 in 24h indicates high activity)
            const hasBlockSpike = blockedEvents > 1000;
            if (hasBlockSpike) {
                signals.push('blocks_spike');
                signalDetails.push(`${blockedEvents.toLocaleString()} firewall blocks`);
            }

            // Signal 4: External Connections deviation (if > 50% of active flows are external, may indicate unusual pattern)
            const externalRatio = activeFlows > 0 ? (externalConnections / activeFlows) : 0;
            const hasExternalDeviation = externalRatio > 0.5 && externalConnections > 50;
            if (hasExternalDeviation) {
                signals.push('external_deviation');
                signalDetails.push(`unusual external connections (${Math.round(externalRatio * 100)}%)`);
            }
        }

        // Health state determination
        // Unhealthy: Active alerts present OR multiple critical signals (2+ non-alert signals)
        // Degraded: High volume without alerts (1 signal, or sustained high volume)
        // Healthy: No signals
        let state = 'healthy';
        let explanation = 'All systems operating normally.';
        let shortExplanation = '';

        if (signals.length === 0) {
            state = 'healthy';
            explanation = 'All systems operating normally. Traffic within baseline.';
            shortExplanation = 'traffic within baseline';
        } else if (hasAlerts) {
            // Active alerts present: Unhealthy (critical)
            state = 'unhealthy';
            const otherSignals = signalDetails.filter(d => !d.includes('alert'));
            if (otherSignals.length > 0) {
                explanation = `${activeAlerts} active alert${activeAlerts > 1 ? 's' : ''} and ${otherSignals.join(', ')}. Immediate investigation required.`;
                shortExplanation = `${activeAlerts} active alert${activeAlerts > 1 ? 's' : ''} and ${otherSignals[0]}`;
            } else {
                explanation = `${activeAlerts} active alert${activeAlerts > 1 ? 's' : ''} detected. Review security status immediately.`;
                shortExplanation = `${activeAlerts} active alert${activeAlerts > 1 ? 's' : ''}`;
            }
        } else {
            // Count baseline-aware signals (spikes) vs static signals (sustained activity)
            const baselineDeviations = baselineSignals.filter(s => s !== 'anomalies_present' && s !== 'anomalies');
            const hasBaselineSpikes = baselineDeviations.length >= 2;
            const hasSingleBaselineSpike = baselineDeviations.length === 1;

            if (hasBaselineSpikes) {
                // Multiple baseline deviations without alerts: Unhealthy (multiple metrics spiking)
                state = 'unhealthy';
                const spikeDetails = baselineDetails.filter((d, idx) => baselineSignals[idx] && baselineDeviations.includes(baselineSignals[idx]));
                explanation = `Multiple metrics spiking: ${spikeDetails.slice(0, 2).join(', ')}. Investigation recommended.`;
                shortExplanation = `Multiple metrics spiking: ${spikeDetails[0]}`;
            } else if (signals.length >= 2 && !hasBaselineSpikes) {
                // Multiple static signals without baseline spikes: Degraded (sustained activity)
                state = 'degraded';
                explanation = `Elevated activity: ${signalDetails.slice(0, 2).join(', ')}. Monitor if sustained.`;
                shortExplanation = signalDetails[0];
            } else {
                // Single signal or sustained activity without spikes: Degraded (stable but elevated)
                state = 'degraded';
                if (signals.includes('anomalies')) {
                    // Check if anomalies are spiking vs baseline
                    const anomaliesSpiking = baselineSignals.includes('anomalies_rate') || baselineSignals.includes('anomalies_present');
                    if (anomaliesSpiking) {
                        explanation = `${anomalies} network anomal${anomalies > 1 ? 'ies' : 'y'} detected, above baseline. Review network activity.`;
                        shortExplanation = `${anomalies} anomal${anomalies > 1 ? 'ies' : 'y'} above baseline`;
                    } else {
                        explanation = `${anomalies} network anomal${anomalies > 1 ? 'ies' : 'y'} detected, within normal range. Monitor activity.`;
                        shortExplanation = `${anomalies} anomal${anomalies > 1 ? 'ies' : 'y'} (within baseline)`;
                    }
                } else if (hasSingleBaselineSpike) {
                    // Single baseline spike: Degraded (not critical enough for Unhealthy)
                    const spikeDetail = baselineDetails.find((d, idx) => baselineSignals[idx] && baselineDeviations.includes(baselineSignals[idx]));
                    explanation = `${spikeDetail || signalDetails[0]}. Monitor activity.`;
                    shortExplanation = spikeDetail || signalDetails[0];
                } else if (signals.includes('blocks_spike')) {
                    explanation = `Elevated firewall blocks (${blockedEvents.toLocaleString()} in 24h). Activity within baseline. Monitor if sustained.`;
                    shortExplanation = `Elevated firewall blocks`;
                } else if (signals.includes('external_deviation')) {
                    explanation = `Unusual external connection pattern (${Math.round(externalRatio * 100)}% of flows). Monitor if sustained.`;
                    shortExplanation = `Unusual external connections`;
                } else if (signalDetails.length > 0) {
                    // Sustained activity without baseline spikes: Degraded
                    explanation = `${signalDetails[0]}. Activity within baseline. Monitor if sustained.`;
                    shortExplanation = signalDetails[0];
                }
            }
        }

        return {
            state: state, // 'healthy', 'degraded', 'unhealthy'
            explanation: explanation,
            shortExplanation: shortExplanation,
            signals: signals,
            signalsCount: signals.length
        };
    },

    dismissAlert(msg) {
        this.dismissedAlerts.add(msg);
        localStorage.setItem('dismissedAlerts', JSON.stringify([...this.dismissedAlerts]));
    },

    startTimer() {
        if (this.refreshTimer) clearInterval(this.refreshTimer);
        this.refreshTimer = setInterval(() => {
            if (!this.paused) this.loadAll();
        }, this.refreshInterval);
        // Reset countdown when timer restarts
        this.refreshCountdown = this.refreshInterval / 1000;
        this.startCountdown();
    },

    startCountdown() {
        if (this.countdownTimer) clearInterval(this.countdownTimer);
        this.refreshCountdown = this.refreshInterval / 1000;
        this.countdownTimer = setInterval(() => {
            if (!this.paused && this.refreshCountdown > 0) {
                this.refreshCountdown--;
            }
            if (this.refreshCountdown <= 0) {
                this.refreshCountdown = this.refreshInterval / 1000;
            }
        }, 1000);
    },

    get countdownPercent() {
        const total = this.refreshInterval / 1000;
        return ((total - this.refreshCountdown) / total) * 100;
    },

    get dataFreshness() {
        if (!this.lastUpdateTs) return { text: 'Never', class: 'error' };
        const elapsed = Math.floor((Date.now() - this.lastUpdateTs) / 1000);
        if (elapsed < 30) return { text: `${elapsed}s ago`, class: '' };
        if (elapsed < 60) return { text: `${elapsed}s ago`, class: 'stale' };
        if (elapsed < 120) return { text: `${Math.floor(elapsed / 60)}m ago`, class: 'stale' };
        return { text: `${Math.floor(elapsed / 60)}m ago`, class: 'error' };
    },

    // Global time range context - single source of truth for time-based widgets
    get global_time_range() {
        return this.timeRange;
    },

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Don't trigger if typing in input
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

            switch (e.key.toLowerCase()) {
                case 'r':
                    if (!e.ctrlKey && !e.metaKey) {
                        e.preventDefault();
                        this.loadAll();
                        this.refreshCountdown = this.refreshInterval / 1000;
                    }
                    break;
                case 'p':
                    e.preventDefault();
                    this.togglePause();
                    break;
                case '1':
                    e.preventDefault();
                    this.timeRange = '15m';
                    break;
                case '2':
                    e.preventDefault();
                    this.timeRange = '30m';
                    break;
                case '3':
                    e.preventDefault();
                    this.timeRange = '1h';
                    break;
                case '4':
                    e.preventDefault();
                    this.timeRange = '6h';
                    break;
                case '5':
                    e.preventDefault();
                    this.timeRange = '24h';
                    break;
                case '6':
                    e.preventDefault();
                    this.timeRange = '7d';
                    break;
                case 'escape':
                    this.modalOpen = false;
                    this.trendModalOpen = false;
                    this.thresholdsModalOpen = false;
                    this.widgetManagerOpen = false;
                    this.expandedModalOpen = false;
                    this.networkGraphOpen = false;
                    this.ipInvestigationModalOpen = false;
                    this.closeFullscreenChart();
                    // Return focus to a safe element
                    document.activeElement?.blur();
                    break;
                case '?':
                    if (e.shiftKey) {
                        e.preventDefault();
                        alert('Keyboard Shortcuts:\n\nR - Refresh data\nP - Pause/Resume\n1-6 - Time range (15m to 7d)\nESC - Close modals\n? - Show this help');
                    }
                    break;
                case 'g':
                    if (e.shiftKey) {
                        e.preventDefault();
                        // Focus search box
                        const searchBox = document.querySelector('.search-box');
                        if (searchBox) searchBox.focus();
                    }
                    break;
                case 'o':
                    if (e.shiftKey) {
                        e.preventDefault();
                        this.activeTab = 'overview';
                    }
                    break;
                case 's':
                    if (e.shiftKey && !e.ctrlKey) {
                        e.preventDefault();
                        this.activeTab = 'security';
                    }
                    break;
                case 'n':
                    if (e.shiftKey && !e.ctrlKey) {
                        e.preventDefault();
                        this.activeTab = 'network';
                    }
                    break;
                case 'f':
                    if (e.shiftKey && !e.ctrlKey) {
                        e.preventDefault();
                        this.activeTab = 'forensics';
                    }
                    break;
                case 'a':
                    if (e.shiftKey && !e.ctrlKey) {
                        e.preventDefault();
                        this.activeTab = 'assistant';
                    }
                    break;
            }
        });
    },

    togglePause() {
        this.paused = !this.paused;
    },

    // Fullscreen Chart Methods
    openFullscreenChart(chartId, title) {
        const sourceChart = this.getChartInstance(chartId);
        if (!sourceChart) return;

        this.fullscreenChart = { chartId, title };

        // Clone chart to fullscreen modal after DOM updates
        this.$nextTick(() => {
            const canvas = document.getElementById('fullscreenChartCanvas');
            if (!canvas) return;

            // Destroy existing fullscreen chart if any
            if (_chartInstances['fullscreenChartInstance']) {
                _chartInstances['fullscreenChartInstance'].destroy();
            }

            // Clone the chart configuration
            const config = JSON.parse(JSON.stringify(sourceChart.config));
            config.options = config.options || {};
            config.options.responsive = true;
            config.options.maintainAspectRatio = false;

            _chartInstances['fullscreenChartInstance'] = new Chart(canvas, config);
        });
    },

    closeFullscreenChart() {
        if (_chartInstances['fullscreenChartInstance']) {
            _chartInstances['fullscreenChartInstance'].destroy();
            _chartInstances['fullscreenChartInstance'] = null;
        }
        this.fullscreenChart = null;
    },

    getChartInstance(chartId) {
        return _chartInstances[chartId];
    },

    // API Latency tracking helper with enhanced error handling
    async fetchWithLatency(url, options = {}) {
        const start = performance.now();
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(url, { ...options, timeout: options.timeout || 30000 });
            const latency = Math.round(performance.now() - start);
            this.apiLatency = latency;
            this.apiLatencyHistory.push(latency);
            if (this.apiLatencyHistory.length > 10) {
                this.apiLatencyHistory.shift();
            }
            return res;
        } catch (error) {
            const latency = Math.round(performance.now() - start);
            this.apiLatency = latency;
            this.apiLatencyHistory.push(latency);
            if (this.apiLatencyHistory.length > 10) {
                this.apiLatencyHistory.shift();
            }
            throw error;
        }
    },

    get avgLatency() {
        if (this.apiLatencyHistory.length === 0) return null;
        return Math.round(this.apiLatencyHistory.reduce((a, b) => a + b, 0) / this.apiLatencyHistory.length);
    },

    get latencyClass() {
        const avg = this.avgLatency;
        if (avg === null) return '';
        if (avg < 200) return 'good';
        if (avg < 500) return 'warning';
        return 'critical';
    },

    // Performance metrics tracking
    performanceMetrics: {
        loading: false,
        error: null,
        data: null
    },

    async fetchPerformanceMetrics() {
        this.performanceMetrics.loading = true;
        this.performanceMetrics.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn('/api/performance/metrics');
            const data = await res.json();
            this.performanceMetrics.data = data;
            this.performanceMetrics.error = null;
        } catch (e) {
            console.error('Failed to fetch performance metrics:', e);
            this.performanceMetrics.error = DashboardUtils?.getUserFriendlyError(e, 'load performance metrics') || 'Failed to load performance metrics';
        } finally {
            this.performanceMetrics.loading = false;
        }
    },

    openThresholds() { this.thresholdsModalOpen = true; },

    async loadThresholds() {
        try {
            const res = await fetch('/api/thresholds');
            if (res.ok) {
                const t = await res.json();
                this.thresholds = { ...this.thresholds, ...t };
            }
        } catch (e) { console.error(e); }
    },

    async saveThresholds() {
        try {
            const res = await fetch('/api/thresholds', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(this.thresholds)
            });
            if (res.ok) {
                const t = await res.json();
                this.thresholds = { ...this.thresholds, ...t };
                this.thresholdsModalOpen = false;
            }
        } catch (e) { console.error(e); }
    },

    // Configuration Settings
    async openConfig() {
        this.configModalOpen = true;
        this.configLoading = true;
        try {
            const res = await fetch('/api/config');
            if (res.ok) {
                const cfg = await res.json();
                this.config = { ...this.config, ...cfg };
                // Initialize analysis settings from current values if not in config
                if (!this.config.default_time_range) {
                    this.config.default_time_range = this.timeRange;
                }
                if (!this.config.refresh_interval) {
                    this.config.refresh_interval = this.refreshInterval;
                }
            }
            // Always fetch system resources data when opening config modal to ensure fresh status
            this.fetchServerHealth();
            this.fetchFeedHealth();
        } catch (e) { console.error('Failed to load config:', e); }
        this.configLoading = false;
    },

    async saveConfig() {
        this.configSaving = true;
        try {
            // Apply analysis settings immediately to current session
            if (this.config.default_time_range) {
                this.timeRange = this.config.default_time_range;
            }
            if (this.config.refresh_interval) {
                this.refreshInterval = this.config.refresh_interval;
                // Restart refresh timer with new interval
                if (this.refreshTimer) {
                    clearInterval(this.refreshTimer);
                }
                // Restart the refresh timer using the existing startTimer method
                if (!this.paused) {
                    this.startTimer();
                } else {
                    // If paused, just update the interval for when it resumes
                    this.refreshCountdown = this.refreshInterval / 1000;
                }
            }

            // Save to backend (excluding analysis settings - they're frontend-only)
            const configToSave = {
                dns_server: this.config.dns_server,
                snmp_host: this.config.snmp_host,
                snmp_community: this.config.snmp_community,
                snmp_poll_interval: this.config.snmp_poll_interval,
                internal_networks: this.config.internal_networks
            };

            const res = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(configToSave)
            });
            if (res.ok) {
                const result = await res.json();
                if (result.config) {
                    // Merge backend config with frontend analysis settings
                    this.config = { ...this.config, ...result.config, default_time_range: this.config.default_time_range, refresh_interval: this.config.refresh_interval };
                }
                this.configModalOpen = false;
                // Show success notification
                this.showToast('Configuration saved successfully', 'success');
            } else {
                this.showToast('Failed to save configuration', 'error');
            }
        } catch (e) {
            console.error('Failed to save config:', e);
            this.showToast('Error saving configuration', 'error');
        }
        this.configSaving = false;
    },

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;

        // Stack toasts
        const existingToasts = document.querySelectorAll('.toast');
        const offset = existingToasts.length * 50 + 60; // 60px base offset

        let bgColor = 'var(--neon-cyan)';
        if (type === 'success') bgColor = 'var(--neon-green)';
        if (type === 'error') bgColor = 'var(--neon-red)';
        if (type === 'warning') bgColor = 'var(--neon-yellow)';

        toast.style.cssText = `position:fixed;bottom:${offset}px;right:20px;padding:12px 20px;border-radius:6px;z-index:10000;animation:fadeIn 0.3s;background:${bgColor};color:#000;box-shadow:0 4px 10px rgba(0,0,0,0.5);font-weight:600;min-width:200px;`;
        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(20px)';
            toast.style.transition = 'all 0.3s';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    fetchSectionData(sectionId) {
        // Trigger specific data loads based on visibility
        const now = Date.now();

        if (sectionId === 'section-worldmap' && this.isVisible('worldmap')) {
            if (now - this.lastFetch.worldmap > this.heavyTTL) {
                this.fetchWorldMap();
                this.lastFetch.worldmap = now;
            }
            // Initialize map when section becomes visible
            if (!this.map) {
                const initMapWhenReady = () => {
                    const container = document.getElementById('world-map-svg');
                    if (!container) return;

                    // Use requestAnimationFrame multiple times to ensure browser has painted
                    requestAnimationFrame(() => {
                        requestAnimationFrame(() => {
                            const rect = container.getBoundingClientRect();
                            const parentRect = container.parentElement?.getBoundingClientRect();

                            // If container has dimensions, initialize
                            if (rect.width > 0 && rect.height > 0 && !this.map) {
                                this.renderWorldMap();
                            }
                            // If parent has dimensions but container doesn't, force container dimensions
                            else if (parentRect && parentRect.width > 0 && parentRect.height > 0) {
                                container.style.width = parentRect.width + 'px';
                                container.style.height = parentRect.height + 'px';
                                // Wait one more frame for style to apply
                                requestAnimationFrame(() => {
                                    if (!this.map) {
                                        this.renderWorldMap();
                                    }
                                });
                            }
                            // If still no dimensions, use ResizeObserver as fallback
                            else if (!this._mapResizeObserver) {
                                this._mapResizeObserver = new ResizeObserver((entries) => {
                                    for (const entry of entries) {
                                        const { width, height } = entry.contentRect;
                                        if (width > 0 && height > 0 && !this.map) {
                                            this._mapResizeObserver.disconnect();
                                            this._mapResizeObserver = null;
                                            this.renderWorldMap();
                                            break;
                                        }
                                    }
                                });
                                this._mapResizeObserver.observe(container);
                            }
                        });
                    });
                };

                this.$nextTick(() => {
                    setTimeout(initMapWhenReady, 50);
                });
            } else {
                // Map exists - invalidate size to update it
                this.$nextTick(() => {
                    setTimeout(() => {
                        if (this.map) {
                            this.map.invalidateSize();
                        }
                    }, 100);
                });
            }
        }
        if (sectionId === 'section-network') {
            if (now - this.lastFetch.network > this.heavyTTL) {
                if (this.isVisible('sources')) this.fetchSources();
                if (this.isVisible('destinations')) this.fetchDestinations();
                if (this.isVisible('ports')) this.fetchPorts();
                if (this.isVisible('asns')) this.fetchASNs();
                if (this.isVisible('countries')) this.fetchCountries();
                if (this.isVisible('talkers')) this.fetchTalkers();
                if (this.isVisible('services')) this.fetchServices();
                if (this.isVisible('hourlyTraffic')) this.fetchHourlyTraffic();
                if (this.isVisible('flags')) this.fetchFlags();
                if (this.isVisible('durations')) this.fetchDurations();
                if (this.isVisible('packetSizes')) this.fetchPacketSizes();
                if (this.isVisible('protocols')) this.fetchProtocols();
                if (this.isVisible('flowStats')) this.fetchFlowStats();
                if (this.isVisible('protocolHierarchy')) {
                    this.fetchProtocolHierarchy();
                }

                // Network Health is now always visible as a stat box
                this.fetchNetHealth();
                this.lastFetch.network = now;
            }

            // Always render charts when section is visible
            this.$nextTick(() => {
                setTimeout(() => {
                    if (this.protocolHierarchy.data) {
                        this.renderProtocolHierarchyChart();
                    }
                    if (this.hosts.list && this.hosts.list.length > 0) {
                        this.renderTrafficScatter();
                    }
                }, 100);
            });
        }
        if (sectionId === 'section-security') {
            if (now - this.lastFetch.security > this.heavyTTL) {
                this.fetchSecurityObservability();
                this.fetchAlertHistory();
                this.fetchThreatsByCountry();
                this.fetchThreatVelocity();
                this.fetchTopThreatIPs();
                // Removed: this.fetchRiskIndex(); // Replaced with predictiveRisk in securityObservability
                this.fetchMitreHeatmap();
                this.fetchProtocolAnomalies();
                this.fetchRecentBlocks();
                this.fetchFeedHealth();
                this.fetchWatchlist();
                this.fetchMaliciousPorts();
                this.fetchThreatActivityTimeline();
                this.lastFetch.security = now;
            }
        }
        if (sectionId === 'section-alert-correlation' && this.isVisible('alertCorrelation')) {
            if (now - (this.lastFetch.alertCorrelation || 0) > this.mediumTTL) {
                this.fetchAlertCorrelation();
                this.lastFetch.alertCorrelation = now;
            }
        }
        if (sectionId === 'section-threat-activity-timeline' && this.isVisible('threatActivityTimeline')) {
            if (now - (this.lastFetch.threatActivityTimeline || 0) > this.mediumTTL) {
                this.fetchThreatActivityTimeline();
                this.lastFetch.threatActivityTimeline = now;
            }
        }
        if (sectionId === 'section-flows' && this.isVisible('flows')) {
            if (now - this.lastFetch.flows > this.mediumTTL) {
                this.fetchFlows();
                this.lastFetch.flows = now;
            }
        }
    },

    async loadAll() {
        this.lastUpdate = new Date().toLocaleTimeString();
        this.lastUpdateTs = Date.now();
        const now = Date.now();

        // Staggered loading: Prioritize critical summary data
        // Fetch summary first (await safe because it has internal try/catch)
        await this.fetchSummary();

        // Fetch Overview page stat boxes early (needed for initial page load)
        await Promise.allSettled([
            this.fetchNetworkStatsOverview(),
            this.fetchFirewallStatsOverview(),
            this.fetchAlertHistory(),
            this.fetchBaselineSignals(),
            this.fetchIngestionRates()
        ]);

        // Then fetch key charts in parallel, resilient to failure
        await Promise.allSettled([
            this.fetchBandwidth(),
            this.fetchAlerts(),
            this.fetchBlocklistRate(),
            this.fetchThreats()
        ]);

        // Then fetch the rest of the core data
        // Note: computeTrafficInsights() is called after each fetch completes
        this.fetchSources(); // Top 10 sources
        this.fetchDestinations(); // Top 10 dests
        this.fetchPorts();

        // Fetch Overview Widgets (New)
        if (this.isVisible('talkers')) this.fetchTalkers();

        // Also fetch protocol hierarchy if visible
        if (this.isVisible('protocolHierarchy')) {
            this.fetchProtocolHierarchy();
        }

        // Network Health is now always visible as a stat box
        this.fetchNetHealth();

        if (!this.firewallStreamActive) this.fetchFirewall();

        // Smart Loading via Polling: Check if sections are visible AND stale

        if (this.isSectionVisible('section-worldmap') && (now - this.lastFetch.worldmap > this.heavyTTL)) {
            this.fetchWorldMap();
            this.lastFetch.worldmap = now;
        }

        if (this.isSectionVisible('section-network') && (now - this.lastFetch.network > this.heavyTTL)) {
            // Parallelize all network section fetches for better performance
            await Promise.allSettled([
                this.fetchFlags(),
                this.fetchDurations(),
                this.fetchPacketSizes(),
                this.fetchProtocols(),
                this.fetchFlowStats(),

                this.fetchNetHealth(),
                this.fetchASNs(),
                this.fetchCountries(),
                this.fetchTalkers(),
                this.fetchServices(),
                this.fetchHourlyTraffic(),
                this.fetchHosts(),
                this.fetchProtocolHierarchy()
            ]);
            this.lastFetch.network = now;
        }

        if (this.isSectionVisible('section-security') && (now - this.lastFetch.security > this.heavyTTL)) {
            // Parallelize security section fetches for better performance
            await Promise.allSettled([
                this.fetchSecurityScore(),
                this.fetchAlertHistory(),
                this.fetchThreatsByCountry(),
                this.fetchThreatVelocity(),
                this.fetchTopThreatIPs(),
                this.fetchMitreHeatmap(),
                this.fetchProtocolAnomalies(),
                this.fetchRecentBlocks(),
                this.fetchFeedHealth(),
                this.fetchWatchlist(),
                this.fetchMaliciousPorts()
            ]);
            this.lastFetch.security = now;
        }

        if (this.isSectionVisible('section-threat-activity-timeline') && (now - (this.lastFetch.threatActivityTimeline || 0) > this.heavyTTL)) {
            this.fetchThreatActivityTimeline();
            this.lastFetch.threatActivityTimeline = now;
        }

        if (this.isSectionVisible('section-flows') && (now - this.lastFetch.flows > this.mediumTTL)) {
            this.fetchFlows();
            this.lastFetch.flows = now;
        }

        // Render sparklines for top IPs (throttled via sparkTTL)
        this.renderSparklines('source');
        this.renderSparklines('dest');

        this.loadNotifyStatus();
    },

    get filteredSources() {
        let list = this.sources.sources || [];
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            list = list.filter(s => s.key.includes(q) || (s.hostname && s.hostname.includes(q)));
        }
        return list.slice(0, 5);
    },

    get filteredDestinations() {
        let list = this.destinations.destinations || [];
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            list = list.filter(s => s.key.includes(q) || (s.hostname && s.hostname.includes(q)));
        }
        return list.slice(0, 5);
    },

    async fetchSummary() {
        this.summary.loading = true;
        this.summary.error = null;
        try {
            const res = await this.fetchWithLatency(`/api/stats/summary?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                this.summary = { ...data, error: null };
                if (data.threat_status) this.threatStatus = data.threat_status;
                // Update insights after summary loads
                this.computeTrafficInsights();
            } else {
                const errorMsg = `Summary fetch failed: ${res.status}`;
                console.error(errorMsg);
                this.summary.error = DashboardUtils?.getUserFriendlyError(new Error(errorMsg), 'load summary') || errorMsg;
            }
        } catch (e) {
            console.error('Failed to fetch summary:', e);
            this.summary.error = DashboardUtils?.getUserFriendlyError(e, 'load summary') || 'Failed to load summary';
        } finally {
            this.summary.loading = false;
        }
    },

    // Generic stability filter - shared across all insight types
    // tier: 'baseline' (always shown) or 'notable' (requires stability check)
    applyStabilityFilter(panel, currentInsights, tier = 'notable') {
        // Baseline insights bypass stability check - always shown
        if (tier === 'baseline') {
            return currentInsights;
        }

        // Notable insights require stability check
        const now = Date.now();
        const historyEntry = {
            timestamp: now,
            insights: currentInsights.map(i => ({ id: i.id, key: i.key, pct: i.pct }))
        };

        // Maintain history (keep last 3 samples)
        panel.history.push(historyEntry);
        if (panel.history.length > 3) {
            panel.history.shift();
        }

        // Stability filter: only show insights that appear in at least 2 consecutive samples
        const stableInsights = [];
        if (panel.history.length >= 2) {
            const recent = panel.history.slice(-2);
            const insightCounts = {};

            // Count occurrences of each insight across last 2 samples
            recent.forEach(sample => {
                sample.insights.forEach(insight => {
                    const key = `${insight.id}:${insight.key}`;
                    insightCounts[key] = (insightCounts[key] || 0) + 1;
                });
            });

            // Only include insights that appear in both samples
            currentInsights.forEach(insight => {
                const key = `${insight.id}:${insight.key}`;
                if (insightCounts[key] >= 2) {
                    stableInsights.push(insight);
                }
            });
        } else {
            // First sample - show all (no stability check yet)
            stableInsights.push(...currentInsights);
        }

        // Sort by percentage (descending)
        stableInsights.sort((a, b) => (b.pct || 0) - (a.pct || 0));
        return stableInsights;
    },

    // Generic insight computation - configurable for different data sources
    computeInsights(panelType) {
        const panel = this.insightPanels[panelType];
        if (!panel) return;

        const config = panel.config;
        let baselineInsights = [];
        let notableInsights = [];

        if (config.type === 'traffic') {
            // Only compute if we have the necessary data (destinations is optional)
            if (this.summary.loading || this.sources.loading || this.ports.loading || this.protocols.loading) {
                return;
            }
            // Destinations is optional - don't block on it

            const totalBytes = this.summary.total_bytes || 0;

            // ============================================
            // BASELINE INSIGHTS (Always shown, no thresholds)
            // ============================================

            // 1. Top Talker (always shown if data exists)
            if (this.sources.sources && this.sources.sources.length > 0) {
                const topSource = this.sources.sources[0];
                const bytes = topSource.bytes || 0;
                const pct = totalBytes > 0 ? (bytes / totalBytes) : 0;
                baselineInsights.push({
                    id: 'talker',
                    type: 'talker',
                    tier: 'baseline',
                    label: 'Top Talker',
                    key: topSource.key,
                    absolute: topSource.bytes_fmt || this.fmtBytes(bytes),
                    relative: totalBytes > 0 ? `${(pct * 100).toFixed(1)}% of total traffic` : 'No traffic',
                    bytes: bytes,
                    pct: pct
                });
            }

            // 2. Dominant Protocol (always shown if data exists)
            if (this.protocols.protocols && this.protocols.protocols.length > 0) {
                const topProto = this.protocols.protocols[0];
                const bytes = topProto.bytes || 0;
                const pct = totalBytes > 0 ? (bytes / totalBytes) : 0;
                baselineInsights.push({
                    id: 'protocol',
                    type: 'protocol',
                    tier: 'baseline',
                    label: 'Dominant Protocol',
                    key: topProto.proto_name || topProto.key,
                    absolute: topProto.bytes_fmt || this.fmtBytes(bytes),
                    relative: totalBytes > 0 ? `${(pct * 100).toFixed(1)}% of total traffic` : 'No traffic',
                    bytes: bytes,
                    pct: pct
                });
            }

            // 3. Top Destination (optional baseline, always shown if available)
            if (this.destinations && this.destinations.destinations && this.destinations.destinations.length > 0) {
                const topDest = this.destinations.destinations[0];
                const bytes = topDest.bytes || 0;
                const pct = totalBytes > 0 ? (bytes / totalBytes) : 0;
                baselineInsights.push({
                    id: 'destination',
                    type: 'destination',
                    tier: 'baseline',
                    label: 'Top Destination',
                    key: topDest.key,
                    absolute: topDest.bytes_fmt || this.fmtBytes(bytes),
                    relative: totalBytes > 0 ? `${(pct * 100).toFixed(1)}% of total traffic` : 'No traffic',
                    bytes: bytes,
                    pct: pct
                });
            }

            // ============================================
            // NOTABLE INSIGHTS (Conditional, with thresholds)
            // ============================================

            // 4. High-volume / Notable Port (only if meets threshold and not common)
            if (this.ports.ports && this.ports.ports.length > 0) {
                const topPort = this.ports.ports[0];
                const bytes = topPort.bytes || 0;
                const pct = totalBytes > 0 ? (bytes / totalBytes) : 0;
                const portNum = parseInt(topPort.key);
                if (pct >= config.minThreshold && !config.commonPorts.includes(portNum)) {
                    notableInsights.push({
                        id: 'port',
                        type: 'port',
                        tier: 'notable',
                        label: 'Notable Port',
                        key: topPort.key,
                        service: topPort.service || 'unknown',
                        absolute: topPort.bytes_fmt || this.fmtBytes(bytes),
                        relative: `${(pct * 100).toFixed(1)}% of total traffic`,
                        bytes: bytes,
                        pct: pct
                    });
                }
            }

            // Apply stability filter only to notable insights
            const stableNotableInsights = this.applyStabilityFilter(panel, notableInsights, 'notable');

            // Build final insights array
            let finalInsights = [...baselineInsights];

            // If we have no baseline insights at all (truly no data), show "No Activity"
            if (baselineInsights.length === 0) {
                finalInsights = [{
                    id: 'no-traffic',
                    type: 'anomaly',
                    tier: 'baseline',
                    label: 'Traffic Status',
                    key: 'No Activity',
                    absolute: '0 B',
                    relative: 'No traffic in time window',
                    isStabilityConfirmation: false
                }];
            } else {
                // Add stable notable insights (max 2 notable insights as per requirements)
                const maxNotable = 2;
                if (stableNotableInsights.length > 0) {
                    finalInsights.push(...stableNotableInsights.slice(0, maxNotable));
                } else if (baselineInsights.length > 0) {
                    // If no notable insights exist, add stability confirmation
                    // Always show stability confirmation when no notable insights (traffic patterns stable)
                    finalInsights.push({
                        id: 'stability',
                        type: 'anomaly',
                        tier: 'baseline',
                        label: 'Traffic Patterns',
                        key: 'Stable',
                        absolute: 'No anomalies detected',
                        relative: 'Within normal baseline',
                        isStabilityConfirmation: true
                    });
                }
            }

            // Sort by tier (baseline first) then by percentage (descending)
            // Stability confirmation should appear last
            finalInsights.sort((a, b) => {
                // Stability confirmation always last
                if (a.isStabilityConfirmation && !b.isStabilityConfirmation) return 1;
                if (!a.isStabilityConfirmation && b.isStabilityConfirmation) return -1;
                // Baseline insights first
                if (a.tier === 'baseline' && b.tier !== 'baseline') return -1;
                if (a.tier !== 'baseline' && b.tier === 'baseline') return 1;
                // Then by percentage
                return (b.pct || 0) - (a.pct || 0);
            });

            panel.insights = finalInsights;
            panel.loading = false;
        }
        // Future: Add firewall and hosts logic here
    },

    // Legacy alias for backward compatibility
    computeTrafficInsights() {
        this.computeInsights('traffic');
    },

    async fetchSources() {
        this.sources.loading = true;
        this.sources.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/stats/sources?range=${this.global_time_range}`);
            this.sources = { ...(await res.json()), loading: false, error: null };
            // Update insights after sources load
            this.computeTrafficInsights();
        } catch (e) {
            console.error('Failed to fetch sources:', e);
            this.sources.error = DashboardUtils?.getUserFriendlyError(e, 'load sources') || 'Failed to load sources';
        } finally {
            this.sources.loading = false;
            // defer sparkline draw after DOM update
            this.$nextTick(() => this.renderSparklines('source'));
        }
    },

    async fetchDestinations() {
        this.destinations.loading = true;
        this.destinations.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/stats/destinations?range=${this.global_time_range}`);
            this.destinations = { ...(await res.json()), loading: false, error: null };
            // Update insights after destinations load (for Top Destination baseline insight)
            this.computeTrafficInsights();
        } catch (e) {
            console.error('Failed to fetch destinations:', e);
            this.destinations.error = DashboardUtils?.getUserFriendlyError(e, 'load destinations') || 'Failed to load destinations';
        } finally {
            this.destinations.loading = false;
            this.$nextTick(() => this.renderSparklines('dest'));
        }
    },

    async fetchPorts() {
        this.ports.loading = true;
        this.ports.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/stats/ports?range=${this.global_time_range}`);
            this.ports = { ...(await res.json()), loading: false, error: null };
            // Update insights after ports load
            this.computeTrafficInsights();
        } catch (e) {
            console.error('Failed to fetch ports:', e);
            this.ports.error = DashboardUtils?.getUserFriendlyError(e, 'load ports') || 'Failed to load ports';
        } finally {
            this.ports.loading = false;
        }
    },

    async fetchHosts() {
        this.hosts.loading = true;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const [statsRes, listRes] = await Promise.all([
                safeFetchFn(`/api/hosts/stats`),
                safeFetchFn(`/api/hosts/list?range=${this.timeRange}&limit=60`)
            ]);

            if (statsRes.ok && listRes.ok) {
                const stats = await statsRes.json();
                const list = await listRes.json();
                this.hosts = {
                    ...this.hosts,
                    stats,
                    list,
                    loading: false
                };
                this.$nextTick(() => this.renderTrafficScatter());
            }
        } catch (e) {
            console.error('Failed to fetch hosts:', e);
            this.hosts.loading = false;
        }
    },

    renderTrafficScatter() {
        const ctx = document.getElementById('trafficScatterChart');
        if (!ctx || !this.hosts.list || this.hosts.list.length === 0) {
            this.trafficScatter.loading = false;
            return;
        }

        if (typeof Chart === 'undefined') {
            setTimeout(() => this.renderTrafficScatter(), 100);
            return;
        }

        const dataPoints = this.hosts.list.slice(0, 50).map(h => ({
            x: h.rx_bytes,
            y: h.tx_bytes,
            ip: h.ip,
            hostname: h.hostname
        }));

        if (_chartInstances['trafficScatter']) {
            _chartInstances['trafficScatter'].destroy();
        }

        _chartInstances['trafficScatter'] = new Chart(ctx, {
            type: 'scatter',
            data: {
                datasets: [{
                    label: 'Hosts',
                    data: dataPoints,
                    backgroundColor: (context) => {
                        const pt = context.raw;
                        if (!pt) return 'rgba(0, 243, 255, 0.6)';
                        // Color scale based on upload/download ratio or just use primary color
                        return pt.y > pt.x ? 'rgba(188, 19, 254, 0.7)' : 'rgba(0, 243, 255, 0.7)';
                    },
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    pointRadius: (context) => {
                        const pt = context.raw;
                        if (!pt) return 5;
                        // Size based on total traffic
                        return Math.max(4, Math.min(12, Math.sqrt((pt.x + pt.y) / 1000000)));
                    },
                    pointHoverRadius: 15
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        type: 'logarithmic',
                        position: 'bottom',
                        title: { display: true, text: 'Download Bytes', color: '#888' },
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#666', callback: (v) => this.fmtBytes(v) }
                    },
                    y: {
                        type: 'logarithmic',
                        title: { display: true, text: 'Upload Bytes', color: '#888' },
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#666', callback: (v) => this.fmtBytes(v) }
                    }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => {
                                const pt = ctx.raw;
                                return `${pt.ip}: ↓${this.fmtBytes(pt.x)} ↑${this.fmtBytes(pt.y)}`;
                            }
                        }
                    }
                }
            }
        });

        // Set loading to false after successful chart creation
        this.trafficScatter.loading = false;
    },

    switchHostsView(mode) {
        this.hosts.viewMode = mode;
        if (mode === 'discovered' && this.hosts.discovery.subnets.length === 0) {
            this.fetchDiscoverySubnets();
        }
    },

    async fetchDiscoverySubnets() {
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn('/api/discovery/subnets');
            if (res.ok) {
                const subnets = await res.json();
                this.hosts.discovery.subnets = subnets;
                if (subnets.length > 0 && !this.hosts.discovery.target) {
                    this.hosts.discovery.target = subnets[0].cidr;
                }
            }
        } catch (e) {
            console.error('Failed to fetch subnets:', e);
        }
    },

    async runDiscoveryScan() {
        if (!this.hosts.discovery.target) return;

        this.hosts.discovery.loading = true;
        this.hosts.discovery.error = null;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn('/api/discovery/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: this.hosts.discovery.target })
            });

            if (res.ok) {
                this.hosts.discovery.results = await res.json();
            } else {
                const err = await res.json();
                this.hosts.discovery.error = err.error || 'Scan failed';
            }
        } catch (e) {
            console.error('Discovery scan failed:', e);
            this.hosts.discovery.error = e.message || 'Scan failed';
        } finally {
            this.hosts.discovery.loading = false;
        }
    },


    async fetchFirewall() {
        this.firewall.loading = true;
        this.firewall.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/stats/firewall?range=${this.timeRange}`);
            this.firewall = { ...(await res.json()).firewall, loading: false, error: null };
        } catch (e) {
            console.error('Failed to fetch firewall:', e);
            this.firewall.error = DashboardUtils?.getUserFriendlyError(e, 'load firewall stats') || 'Failed to load firewall stats';
        } finally {
            this.firewall.loading = false;
        }
    },

    startFirewallStream() {
        try {
            if (!('EventSource' in window)) return;
            if (this.firewallES) return;
            const es = new EventSource('/api/stats/firewall/stream');
            this.firewallES = es;
            es.onopen = () => { this.firewallStreamActive = true; };
            es.onmessage = (evt) => {
                try {
                    const data = JSON.parse(evt.data);
                    if (data && data.firewall) {
                        this.firewall = { ...data.firewall, loading: false };
                    }
                } catch (e) { console.error(e); }
            };
            es.onerror = () => {
                // Mark inactive and retry later
                this.firewallStreamActive = false;
                try { es.close(); } catch (_) { }
                this.firewallES = null;
                // Retry after a delay
                setTimeout(() => this.startFirewallStream(), 5000);
            };
        } catch (e) { console.error(e); }
    },

    async fetchProtocols() {
        this.protocols.loading = true;
        this.protocols.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/stats/protocols?range=${this.global_time_range}`);
            this.protocols = { ...(await res.json()), loading: false, error: null };
            // Update insights after protocols load
            this.computeTrafficInsights();
        } catch (e) {
            console.error('Failed to fetch protocols:', e);
            this.protocols.error = DashboardUtils?.getUserFriendlyError(e, 'load protocols') || 'Failed to load protocols';
        } finally {
            this.protocols.loading = false;
        }
    },

    // ----- New widget fetchers (Option B: threat-focused) -----
    async fetchMaliciousPorts() {
        this.maliciousPorts.loading = true;
        try {
            // Add timeout to prevent indefinite waiting (30 seconds)
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000);

            const res = await fetch(`/api/stats/malicious_ports?range=${this.timeRange}`, {
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (res.ok) {
                const data = await res.json();
                this.maliciousPorts = { ...data, loading: false };
                return;
            } else {
                // If response is not ok, ensure we have a valid structure
                this.maliciousPorts = { ports: [], loading: false, has_syslog: false };
            }
        } catch (e) {
            if (e.name === 'AbortError') {
                console.error('Malicious ports request timed out');
            } else {
                console.error('Failed to fetch malicious ports:', e);
            }
        }

        // Fallback: filter existing ports for suspicious flag
        try {
            const fallback = (this.ports.ports || []).filter(p => p.suspicious || p.threat).slice(0, 20).map(p => ({
                port: p.key || 'n/a',
                service: p.service || '',
                bytes: p.bytes || 0,
                bytes_fmt: p.bytes_fmt || this.fmtBytes(p.bytes || 0),
                hits: p.hits || p.flows || 0
            }));
            this.maliciousPorts.ports = fallback;
            this.maliciousPorts.has_syslog = false;
        } catch (e) {
            console.error('Fallback failed for malicious ports:', e);
            // Ensure we always have a valid structure
            if (!this.maliciousPorts.ports) {
                this.maliciousPorts.ports = [];
            }
        } finally {
            this.maliciousPorts.loading = false;
        }
    },

    async fetchThreats() {
        this.threats.loading = true;
        try {
            const res = await fetch(`/api/stats/threats?range=${this.timeRange}`);
            if (res.ok) {
                const d = await res.json();
                this.threats = { ...(d) };
                return;
            }
        } catch (e) { /* ignore and fallback */ }
        finally { this.threats.loading = false; }

        // Fallback use alerts store to populate some rows
        const arr = (this.alerts.alerts || []).filter(a => a.type === 'threat' || a.threat || a.feed).slice(0, 10).map(a => ({
            ip: a.ip || a.src || a.dst || a.key || 'n/a',
            type: a.feed || a.type || 'feed',
            hits: a.count || 1
        }));
        this.threats.hits = arr;
    },

    async fetchFeedHealth() {
        this.feedHealth.loading = true;
        try {
            const res = await fetch('/api/stats/feeds');
            if (res.ok) {
                const d = await res.json();
                // Ensure summary structure exists even if API returns partial data
                this.feedHealth = {
                    feeds: d.feeds || [],
                    summary: d.summary || { total: 0, ok: 0, error: 0, total_ips: 0 },
                    loading: false
                };
            } else {
                // If API returns error, preserve existing data but mark as not loading
                console.error('Feed health fetch failed:', res.status, res.statusText);
                this.feedHealth.loading = false;
            }
        } catch (e) {
            console.error('Feed health fetch error:', e);
            this.feedHealth.loading = false;
        }
    },

    async fetchSecurityObservability() {
        this.securityObservability.loading = true;
        try {
            const res = await fetch('/api/security/score');
            if (res.ok) {
                const d = await res.json();
                this.securityObservability = { ...d, loading: false };
            }
        } catch (e) { console.error('Security observability fetch error:', e); }
        finally { this.securityObservability.loading = false; }
    },

    // Legacy function for backward compatibility
    async fetchSecurityScore() {
        return this.fetchSecurityObservability();
    },

    // FIXED-SCOPE: Active Alerts (realtime) - does not use global_time_range
    // Note: Returns current active alerts, not time-range dependent
    async fetchAlertHistory() {
        this.alertHistory.loading = true;
        try {
            const res = await fetch('/api/security/alerts/history');
            if (res.ok) {
                const d = await res.json();
                this.alertHistory = { ...d, loading: false };
            }
        } catch (e) { console.error('Alert history fetch error:', e); }
        finally { this.alertHistory.loading = false; }
    },

    // TIME-AWARE: Uses global timeRange for attack timeline data
    async fetchAttackTimeline() {
        this.attackTimeline.loading = true;
        try {
            const res = await fetch(`/api/security/attack-timeline?range=${this.timeRange}`);
            if (res.ok) {
                const d = await res.json();
                this.attackTimeline = { ...d, loading: false };
                this.renderAttackTimelineChart();
            }
        } catch (e) { console.error('Attack timeline fetch error:', e); }
        finally { this.attackTimeline.loading = false; }
    },

    async fetchMitreHeatmap() {
        this.mitreHeatmap.loading = true;
        try {
            const res = await fetch('/api/security/mitre-heatmap');
            if (res.ok) {
                const d = await res.json();
                this.mitreHeatmap = { ...d, loading: false };
            }
        } catch (e) { console.error('MITRE heatmap fetch error:', e); }
        finally { this.mitreHeatmap.loading = false; }
    },

    async fetchProtocolAnomalies() {
        this.protocolAnomalies.loading = true;
        try {
            const res = await fetch('/api/security/protocol-anomalies?range=' + this.timeRange);
            if (res.ok) {
                const d = await res.json();
                this.protocolAnomalies = { ...d, loading: false };
            }
        } catch (e) { console.error('Protocol anomalies fetch error:', e); }
        finally { this.protocolAnomalies.loading = false; }
    },

    // FIXED-SCOPE: Blocked Events (24h) - fixed 24h window, does not use global_time_range
    async fetchFirewallStatsOverview() {
        this.firewallStatsOverview.loading = true;
        try {
            const res = await fetch('/api/firewall/stats/overview');
            if (res.ok) {
                const d = await res.json();
                this.firewallStatsOverview = {
                    // Preserve null vs 0 distinction for truthfulness
                    blocked_events_24h: d.blocked_events_24h ?? null,
                    unique_blocked_sources: d.unique_blocked_sources ?? null,
                    new_blocked_ips: d.new_blocked_ips ?? null,
                    top_block_reason: d.top_block_reason || 'N/A',
                    top_block_count: d.top_block_count ?? null,
                    trends: d.trends || {},
                    loading: false
                };
            } else {
                this.firewallStatsOverview.loading = false;
            }
        } catch (e) {
            console.error('Firewall stats overview fetch error:', e);
            this.firewallStatsOverview.loading = false;
        }
    },

    async fetchRecentBlocks() {
        this.recentBlocks.loading = true;
        try {
            const res = await fetch('/api/firewall/logs/recent?limit=1000');
            if (res.ok) {
                const d = await res.json();
                const logs = d.logs || [];
                const stats = d.stats || this.computeRecentBlockStats(logs);

                this.recentBlocks = {
                    blocks: logs,
                    stats,
                    total_1h: stats?.blocks_last_hour || stats?.actions?.block || logs.length || 0,
                    loading: false,
                    lastUpdate: new Date().toISOString()
                };

                const targetView = this.recentBlocksView || 50;
                this.recentBlocksView = Math.min(targetView, logs.length || targetView, 1000);
            }
        } catch (e) { console.error('Recent blocks fetch error:', e); }
        finally { this.recentBlocks.loading = false; }
    },

    async runDetection() {
        this.showToast('Running detection algorithms...', 'info');
        try {
            const res = await fetch('/api/security/run-detection?range=' + this.timeRange);
            if (res.ok) {
                const d = await res.json();
                this.showToast(`Detection complete: ${d.new_alerts} new alerts`, d.new_alerts > 0 ? 'warning' : 'success');
                // Refresh alert history
                this.fetchAlertHistory();
                this.fetchAttackTimeline();
            }
        } catch (e) {
            console.error('Detection error:', e);
            this.showToast('Detection failed', 'error');
        }
    },

    renderAttackTimelineChart() {
        try {
            const canvas = document.getElementById('attackTimelineChart');
            if (!canvas || !this.attackTimeline.timeline) return;

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                setTimeout(() => this.renderAttackTimelineChart(), 100);
                return;
            }

            const ctx = canvas.getContext('2d');
            if (_chartInstances['_attackTimelineChart']) _chartInstances['_attackTimelineChart'].destroy();

            const labels = this.attackTimeline.timeline.map(t => t.hour);
            const critical = this.attackTimeline.timeline.map(t => t.critical || 0);
            const high = this.attackTimeline.timeline.map(t => t.high || 0);
            const medium = this.attackTimeline.timeline.map(t => t.medium || 0);
            const low = this.attackTimeline.timeline.map(t => t.low || 0);
            const fwBlocks = this.attackTimeline.timeline.map(t => t.fw_blocks || 0);

            const critColor = this.getCssVar('--neon-red') || 'rgba(255, 0, 60, 0.8)';
            const hasFwData = this.attackTimeline.has_fw_data;

            const datasets = [
                { label: 'Critical', data: critical, backgroundColor: critColor, stack: 'a', order: 2 },
                { label: 'High', data: high, backgroundColor: 'rgba(255, 165, 0, 0.8)', stack: 'a', order: 2 },
                { label: 'Medium', data: medium, backgroundColor: 'rgba(255, 255, 0, 0.7)', stack: 'a', order: 2 },
                { label: 'Low', data: low, backgroundColor: 'rgba(0, 255, 255, 0.5)', stack: 'a', order: 2 }
            ];

            // Add firewall blocks as a line overlay if data exists
            if (hasFwData) {
                datasets.push({
                    label: '🔥 FW Blocks',
                    data: fwBlocks,
                    type: 'line',
                    borderColor: 'rgba(0, 255, 100, 1)',
                    backgroundColor: 'rgba(0, 255, 100, 0.1)',
                    borderWidth: 2,
                    pointRadius: 3,
                    pointBackgroundColor: 'rgba(0, 255, 100, 1)',
                    fill: false,
                    tension: 0.3,
                    yAxisID: 'y1',
                    order: 1
                });
            }

            _chartInstances['_attackTimelineChart'] = new Chart(ctx, {
                type: 'bar',
                data: { labels, datasets },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: true, position: 'top', labels: { color: '#888', boxWidth: 12, padding: 8 } } },
                    scales: {
                        x: { stacked: true, grid: { display: false }, ticks: { color: '#666', maxRotation: 45 } },
                        y: { stacked: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#666' }, position: 'left' },
                        ...(hasFwData ? { y1: { grid: { display: false }, ticks: { color: 'rgba(0, 255, 100, 0.8)' }, position: 'right', title: { display: true, text: 'FW Blocks', color: 'rgba(0, 255, 100, 0.8)' } } } : {})
                    }
                }
            });
        } catch (e) {
            console.error('Chart render error:', e);
        }
    },

    get filteredAlerts() {
        let alerts = this.alertHistory.alerts || [];
        if (this.alertFilter.severity !== 'all') {
            alerts = alerts.filter(a => a.severity === this.alertFilter.severity);
        }
        if (this.alertFilter.type !== 'all') {
            alerts = alerts.filter(a => a.type === this.alertFilter.type);
        }
        return alerts;
    },

    get filteredRecentBlocks() {
        let filtered = this.recentBlocks.blocks || [];
        if (this.recentBlocksFilter.action !== 'all') {
            filtered = filtered.filter(b => b.action === this.recentBlocksFilter.action);
        }
        if (this.recentBlocksFilter.threatOnly) {
            filtered = filtered.filter(b => b.is_threat);
        }
        if (this.recentBlocksFilter.searchIP) {
            const searchIP = this.recentBlocksFilter.searchIP.toLowerCase();
            filtered = filtered.filter(b =>
                (b.src_ip && b.src_ip.includes(searchIP)) ||
                (b.dst_ip && b.dst_ip.includes(searchIP))
            );
        }
        if (this.recentBlocksFilter.port) {
            const port = this.recentBlocksFilter.port.toString();
            filtered = filtered.filter(b =>
                (b.src_port && b.src_port.toString().includes(port)) ||
                (b.dst_port && b.dst_port.toString().includes(port))
            );
        }
        if (this.recentBlocksFilter.protocol !== 'all') {
            filtered = filtered.filter(b =>
                (b.proto && b.proto.toUpperCase() === this.recentBlocksFilter.protocol.toUpperCase())
            );
        }
        return filtered;
    },

    get filteredFirewallSyslog() {
        let filtered = this.firewallSyslog.blocks || [];
        if (this.firewallSyslogFilter.action !== 'all') {
            filtered = filtered.filter(b => b.action === this.firewallSyslogFilter.action);
        }
        if (this.firewallSyslogFilter.threatOnly) {
            filtered = filtered.filter(b => b.is_threat);
        }
        if (this.firewallSyslogFilter.searchIP) {
            const searchIP = this.firewallSyslogFilter.searchIP.toLowerCase();
            filtered = filtered.filter(b =>
                (b.src_ip && b.src_ip.includes(searchIP)) ||
                (b.dst_ip && b.dst_ip.includes(searchIP))
            );
        }
        if (this.firewallSyslogFilter.port) {
            const port = this.firewallSyslogFilter.port.toString();
            filtered = filtered.filter(b =>
                (b.src_port && b.src_port.toString().includes(port)) ||
                (b.dst_port && b.dst_port.toString().includes(port))
            );
        }
        if (this.firewallSyslogFilter.protocol !== 'all') {
            filtered = filtered.filter(b =>
                (b.proto && b.proto.toUpperCase() === this.firewallSyslogFilter.protocol.toUpperCase())
            );
        }
        return filtered;
    },
    async fetchFirewallSyslog() {
        this.firewallSyslog.loading = true;
        try {
            const res = await fetch('/api/firewall/syslog/recent?limit=1000');
            if (res.ok) {
                const d = await res.json();
                const logs = d.logs || [];
                const stats = d.stats || {};
                this.firewallSyslog = {
                    blocks: logs,
                    stats,
                    total_1h: stats?.blocks_last_hour || stats?.actions?.block || logs.length || 0,
                    loading: false,
                    lastUpdate: new Date().toISOString()
                };
                const targetView = this.firewallSyslogView || 50;
                this.firewallSyslogView = Math.min(targetView, logs.length || targetView, 1000);
            }
        } catch (e) { console.error('Firewall syslog fetch error:', e); }
        finally { this.firewallSyslog.loading = false; }
    },

    async blockThreatIP(ip) {
        if (!confirm(`Block ${ip} via security webhook?`)) return;
        try {
            const res = await fetch('/api/security/block', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, action: 'block' })
            });
            if (res.ok) {
                const data = await res.json();
                if (data.success) {
                    this.showToast(`Sent block request for ${ip}`, 'success');
                } else {
                    this.showToast(data.message || 'Block request not processed', 'warning');
                }
            } else {
                this.showToast('Block request failed', 'error');
            }
        } catch (e) {
            console.error('Block error:', e);
            this.showToast('Block request failed', 'error');
        }
    },

    async fetchThreatsByCountry() {
        this.threatsByCountry.loading = true;
        try {
            const res = await fetch('/api/security/threats/by_country');
            if (res.ok) {
                const d = await res.json();
                this.threatsByCountry = { ...d, loading: false };
            }
        } catch (e) { console.error('Threats by country fetch error:', e); }
        finally { this.threatsByCountry.loading = false; }
    },

    async fetchThreatVelocity() {
        this.threatVelocity.loading = true;
        try {
            const res = await fetch('/api/security/threat_velocity');
            if (res.ok) {
                const d = await res.json();
                this.threatVelocity = { ...d, loading: false };
            }
        } catch (e) { console.error('Threat velocity fetch error:', e); }
        finally { this.threatVelocity.loading = false; }
    },

    async fetchTopThreatIPs() {
        this.topThreatIPs.loading = true;
        try {
            const res = await fetch('/api/security/top_threat_ips');
            if (res.ok) {
                const d = await res.json();
                this.topThreatIPs = { ...d, loading: false };
            }
        } catch (e) { console.error('Top threat IPs fetch error:', e); }
        finally { this.topThreatIPs.loading = false; }
    },

    async fetchWatchlist() {
        this.watchlist.loading = true;
        try {
            const res = await fetch('/api/security/watchlist');
            if (res.ok) {
                const d = await res.json();
                this.watchlist = { ...d, loading: false };
            }
        } catch (e) { console.error('Watchlist fetch error:', e); }
        finally { this.watchlist.loading = false; }
    },

    async addToWatchlist(ip) {
        if (!ip) ip = this.watchlistInput.trim();
        if (!ip) return;
        try {
            const res = await fetch('/api/security/watchlist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            if (res.ok) {
                this.watchlistInput = '';
                this.fetchWatchlist();
            }
        } catch (e) { console.error('Add to watchlist error:', e); }
    },

    async removeFromWatchlist(ip) {
        try {
            const res = await fetch('/api/security/watchlist', {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            if (res.ok) {
                this.fetchWatchlist();
            }
        } catch (e) { console.error('Remove from watchlist error:', e); }
    },

    exportThreats(format) {
        window.open(`/api/security/threats/export?format=${format}`, '_blank');
    },

    async fetchBlocklistRate() {
        this.blocklist.loading = true;
        try {
            const res = await fetch(`/api/stats/blocklist_rate?range=${this.timeRange}`);
            if (res.ok) {
                const d = await res.json();
                // expect { series: [{ts, rate}], current_rate: number, total_matches: number }
                this.blocklist = { ...d, loading: false };
                this.updateBlocklistChart(d.series || []);
                return;
            }
        } catch (e) { /* ignore */ }
        finally { this.blocklist.loading = false; }

        // Fallback: approximate from threats list length
        const now = Date.now();
        const rate = (this.threats.hits || []).length ? Math.min(100, ((this.threats.hits || []).length / Math.max(1, 10)) * 10).toFixed(1) : 0;
        this.blocklist.current_rate = rate;
        this.blocklist.total_matches = (this.threats.hits || []).reduce((s, t) => s + (t.hits || 1), 0);
        this.updateBlocklistChart([]);
    },

    updateBlocklistChart(series) {
        const ctx = document.getElementById('blocklistChart');
        if (!ctx) return;

        // Check if Chart.js is loaded
        if (typeof Chart === 'undefined') {
            setTimeout(() => this.renderBlocklistChart(), 100);
            return;
        }
        const labels = (series || []).map(s => new Date(s.ts).toLocaleTimeString());
        const values = (series || []).map(s => s.rate || 0);
        const blocked = (series || []).map(s => s.blocked || 0);
        const hasFwData = this.blocklist.has_fw_data;
        const color = this.getCssVar('--neon-red') || '#ff003c';

        const datasets = [
            { label: 'Match %', data: values, borderColor: color, backgroundColor: 'rgba(255,0,60,0.12)', fill: true, tension: 0.3, yAxisID: 'y' }
        ];

        // Add firewall blocks as second line if data exists
        if (hasFwData) {
            datasets.push({
                label: '🔥 FW Blocks',
                data: blocked,
                borderColor: 'rgba(0, 255, 100, 1)',
                backgroundColor: 'rgba(0, 255, 100, 0.1)',
                borderWidth: 2,
                pointRadius: 2,
                fill: true,
                tension: 0.3,
                yAxisID: 'y1'
            });
        }

        if (_chartInstances['blocklistChartInstance']) {
            _chartInstances['blocklistChartInstance'].data.labels = labels;
            _chartInstances['blocklistChartInstance'].data.datasets = datasets;
            _chartInstances['blocklistChartInstance'].options.scales = {
                x: { ticks: { color: '#888' }, grid: { color: '#333' } },
                y: { ticks: { color: '#888' }, grid: { color: '#333' }, suggestedMin: 0, suggestedMax: 100, position: 'left', title: { display: false } },
                ...(hasFwData ? { y1: { ticks: { color: 'rgba(0, 255, 100, 0.8)' }, grid: { display: false }, position: 'right', title: { display: true, text: 'Blocks', color: 'rgba(0, 255, 100, 0.8)', font: { size: 10 } } } } : {})
            };
            _chartInstances['blocklistChartInstance'].update();
        } else {
            _chartInstances['blocklistChartInstance'] = new Chart(ctx, {
                type: 'line',
                data: { labels, datasets },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: hasFwData, position: 'top', labels: { color: '#888', boxWidth: 10, padding: 6, font: { size: 10 } } } },
                    scales: {
                        x: { ticks: { color: '#888' }, grid: { color: '#333' } },
                        y: { ticks: { color: '#888' }, grid: { color: '#333' }, suggestedMin: 0, suggestedMax: 100, position: 'left' },
                        ...(hasFwData ? { y1: { ticks: { color: 'rgba(0, 255, 100, 0.8)' }, grid: { display: false }, position: 'right', title: { display: true, text: 'Blocks', color: 'rgba(0, 255, 100, 0.8)', font: { size: 10 } } } } : {})
                    }
                }
            });
        }
    },

    // TIME-AWARE: Active Alerts (uses global time range)
    async fetchAlerts() {
        this.alerts.loading = true;
        try {
            const res = await fetch(`/api/alerts?range=${this.timeRange}`);
            if (res.ok) this.alerts = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.alerts.loading = false; }
    },

    // TIME-AWARE: Active Flows (uses global time range)
    async fetchFlows() {
        this.flows.loading = true;
        try {
            // Fetch recent flows - get enough for sorting, but limit display
            const limit = 100;  // Fetch more for proper sorting, but display limited rows
            const res = await fetch(`/api/flows?range=${this.timeRange}&limit=${limit}`);
            if (res.ok) {
                const data = await res.json();
                // Sort by bytes descending by default (heaviest flows first)
                const sortedFlows = (data.flows || []).sort((a, b) => (b.bytes || 0) - (a.bytes || 0));
                this.flows = {
                    ...data,
                    flows: sortedFlows,
                    sortKey: 'bytes',
                    sortDesc: true,
                    viewLimit: this.flows.viewLimit || 15  // Preserve view limit setting
                };
            }
        } catch (e) { console.error(e); } finally { this.flows.loading = false; }
    },

    sortFlows(key) {
        if (this.flows.sortKey === key) {
            this.flows.sortDesc = !this.flows.sortDesc;
        } else {
            this.flows.sortKey = key;
            this.flows.sortDesc = true; // Default desc for new columns
        }

        const k = this.flows.sortKey;
        const d = this.flows.sortDesc ? -1 : 1;

        this.flows.flows.sort((a, b) => {
            let va, vb;

            if (k === 'age') {
                // Use age_seconds if available (preferred), fallback to first_seen_ts or ts
                va = a.age_seconds !== undefined ? a.age_seconds : (a.first_seen_ts || (new Date(a.ts).getTime() / 1000));
                vb = b.age_seconds !== undefined ? b.age_seconds : (b.first_seen_ts || (new Date(b.ts).getTime() / 1000));
            } else if (k === 'bytes') {
                va = a.bytes || 0;
                vb = b.bytes || 0;
            } else if (k === 'duration') {
                // Use duration_seconds if available, otherwise parse duration string
                va = a.duration_seconds !== undefined ? a.duration_seconds : parseFloat(a.duration) || 0;
                vb = b.duration_seconds !== undefined ? b.duration_seconds : parseFloat(b.duration) || 0;
            } else {
                // String sort (src, dst, proto_name)
                va = (a[k] || '').toString().toLowerCase();
                vb = (b[k] || '').toString().toLowerCase();
            }

            if (va < vb) return -1 * d;
            if (va > vb) return 1 * d;
            return 0;
        });
    },

    setFlowsViewLimit(limit) {
        this.flows.viewLimit = limit;
    },

    // Helper to check if IP is internal
    isInternalIP(ip) {
        if (!ip) return false;
        return ip.startsWith('192.168.') || ip.startsWith('10.') ||
            (ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') ||
                ip.startsWith('172.19.') || ip.startsWith('172.20.') || ip.startsWith('172.21.') ||
                ip.startsWith('172.22.') || ip.startsWith('172.23.') || ip.startsWith('172.24.') ||
                ip.startsWith('172.25.') || ip.startsWith('172.26.') || ip.startsWith('172.27.') ||
                ip.startsWith('172.28.') || ip.startsWith('172.29.') || ip.startsWith('172.30.') ||
                ip.startsWith('172.31.'));
    },

    // Get flow direction indicator
    getFlowDirection(flow) {
        if (!flow) return 'external';
        if (flow.direction) return flow.direction;
        const srcInt = flow.src_internal !== undefined ? flow.src_internal : this.isInternalIP(flow.src);
        const dstInt = flow.dst_internal !== undefined ? flow.dst_internal : this.isInternalIP(flow.dst);
        if (srcInt && !dstInt) return 'outbound';
        if (!srcInt && dstInt) return 'inbound';
        if (srcInt && dstInt) return 'internal';
        return 'external';
    },

    // Get direction arrow/indicator
    getDirectionIndicator(flow) {
        if (!flow) return { symbol: '→', color: 'var(--text-muted)', title: 'Unknown' };
        const dir = this.getFlowDirection(flow);
        if (dir === 'outbound') return { symbol: '↗', color: 'var(--signal-primary)', title: 'Outbound (Internal → External)' };
        if (dir === 'inbound') return { symbol: '↙', color: 'var(--signal-secondary)', title: 'Inbound (External → Internal)' };
        if (dir === 'internal') return { symbol: '↔', color: 'var(--signal-ok)', title: 'Internal (Internal → Internal)' };
        return { symbol: '↔', color: 'var(--text-muted)', title: 'External (External → External)' };
    },

    openFlowDetails(flow) {
        // Open Flow Details modal
        if (flow) {
            this.selectedFlow = flow;
            this.flowDetailsModalOpen = true;
        }
    },

    closeFlowDetailsModal() {
        this.flowDetailsModalOpen = false;
        this.selectedFlow = null;
    },

    // Unified event details modal (reuses Flow Details pattern)
    openEventDetails(event, eventType) {
        if (event) {
            this.selectedEvent = event;
            this.selectedEventType = eventType; // 'flow', 'firewall', 'threat'
            this.eventDetailsModalOpen = true;
        }
    },

    closeEventDetailsModal() {
        this.eventDetailsModalOpen = false;
        this.selectedEvent = null;
        this.selectedEventType = null;
    },

    // Calculate average rate for flow
    calculateFlowRate(flow) {
        if (!flow || !flow.duration_seconds || flow.duration_seconds === 0) return '0 B/s';
        const rate = flow.bytes / flow.duration_seconds;
        return this.fmtBytes(rate) + '/s';
    },

    // Format timestamp to relative time
    formatFlowTimestamp(ts) {
        if (!ts) return 'Unknown';
        if (typeof ts === 'number') {
            return this.timeAgo(ts);
        }
        // Try parsing string timestamp
        try {
            const date = new Date(ts);
            if (!isNaN(date.getTime())) {
                return this.timeAgo(date.getTime() / 1000);
            }
        } catch (e) { }
        return ts;
    },

    // Get icon for interesting flow flag
    getInterestingFlowIcon(flag) {
        const icons = {
            'long_low': '⏱️',
            'short_high': '⚡',
            'rare_port': '🔍',
            'new_external': '🆕',
            'repeated_short': '🔄'
        };
        return icons[flag] || '•';
    },

    // Get tooltip text for interesting flow flag
    getInterestingFlowTooltip(flag) {
        const tooltips = {
            'long_low': 'Long-lived low-volume flow: Extended duration with minimal data transfer',
            'short_high': 'Short-lived high-volume flow: Burst of data in brief connection',
            'rare_port': 'Rare destination port: Uncommon port in this batch',
            'new_external': 'New external IP: First appearance of this external address',
            'repeated_short': 'Repeated short connections: Multiple brief connections to same destination'
        };
        return tooltips[flag] || 'Interesting flow characteristic';
    },

    timeAgo(ts) {
        if (!ts) return '';
        // If ts is a number (Unix timestamp), use it directly
        if (typeof ts === 'number' && ts > 0) {
            const diff = Math.max(0, (Date.now() / 1000) - ts);
            if (diff < 60) return `${Math.round(diff)}s ago`;
            if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
            return `${Math.round(diff / 86400)}d ago`;
        }
        // String parsing fallback
        if (typeof ts === 'string') {
            // Ultra-robust parsing: extract all digit groups
            // This handles "2026-01-14 06:18:06", "2026-01-14T06:18:06", etc.
            const parts = ts.match(/\d+/g);
            if (parts && parts.length >= 6) {
                // [Year, Month, Day, Hour, Min, Sec]
                // Note: Month is 0-indexed in JS Date/UTC
                ts = Date.UTC(
                    parseInt(parts[0]),
                    parseInt(parts[1]) - 1,
                    parseInt(parts[2]),
                    parseInt(parts[3]),
                    parseInt(parts[4]),
                    parseInt(parts[5])
                ) / 1000;
            } else {
                // Fallback for other formats
                const parsed = Date.parse(ts);
                if (!isNaN(parsed)) ts = parsed / 1000;
                else return '';
            }
        }

        const diff = Math.max(0, (Date.now() / 1000) - ts);
        if (diff < 60) return `${Math.round(diff)}s ago`;
        if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
        return `${Math.round(diff / 86400)}d ago`;
    },

    // Format age from age_seconds (preferred method)
    formatAge(ageSeconds) {
        if (ageSeconds === undefined || ageSeconds === null || isNaN(ageSeconds)) return '';
        const age = Math.max(0, ageSeconds);
        if (age < 60) return `${Math.round(age)}s ago`;
        if (age < 3600) return `${Math.round(age / 60)}m ago`;
        if (age < 86400) return `${Math.round(age / 3600)}h ago`;
        return `${Math.round(age / 86400)}d ago`;
    },


    async fetchFlags() {
        this.flags.loading = true;
        try {
            const res = await fetch(`/api/stats/flags?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                this.flags = { ...data };
                this.updateFlagsChart(data.flags);
            }
        } catch (e) { console.error(e); } finally { this.flags.loading = false; }
    },

    async fetchASNs() {
        this.asns.loading = true;
        try {
            const res = await fetch(`/api/stats/asns?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                // Calc max for bar chart
                const max = Math.max(...data.asns.map(a => a.bytes));
                this.asns = { ...data, maxBytes: max };
            }
        } catch (e) { console.error(e); } finally { this.asns.loading = false; }
    },

    async fetchCountries() {
        this.countries.loading = true;
        try {
            const res = await fetch(`/api/stats/countries?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                this.countries = { ...data };
                // Defer chart update to ensure canvas is visible
                this.$nextTick(() => {
                    setTimeout(() => this.updateCountriesChart(data), 100);
                });
            }
        } catch (e) { console.error(e); } finally { this.countries.loading = false; }
    },

    async fetchWorldMap() {
        this.worldMap.loading = true;
        try {
            const res = await fetch(`/api/stats/worldmap?range=${this.global_time_range}`);
            if (res.ok) {
                const data = await res.json();
                this.worldMap = { ...data, lastUpdate: new Date().toISOString() };
            } else {
                console.error('[WorldMap] API error:', res.status);
            }
        } catch (e) { console.error('[WorldMap] Fetch error:', e); } finally {
            this.worldMap.loading = false;
            // Always render map after fetch (even with no data to show grid)
            this.$nextTick(() => this.renderWorldMap());
        }
    },

    // Simplified Low-Res GeoJSON for fallback (North America, SA, Europe, Africa, Asia, Aus)
    getFallbackGeoJSON() {
        return {
            "type": "FeatureCollection",
            "features": [
                { "type": "Feature", "properties": { "name": "World" }, "geometry": { "type": "Polygon", "coordinates": [[[-180, -90], [-180, 90], [180, 90], [180, -90], [-180, -90]]] } }
            ]
        };
    },

    renderWorldMap() {
        const container = document.getElementById('world-map-svg');
        if (!container) {
            console.warn('[WorldMap] Container not found');
            this.mapStatus = '';
            return;
        }

        // Don't check visibility strictly - Leaflet can initialize even if container is hidden
        // We'll call invalidateSize() when the container becomes visible

        // Check if Leaflet is loaded
        if (typeof L === 'undefined' || typeof L.map === 'undefined') {
            console.warn('[WorldMap] Leaflet not loaded yet, deferring map render');
            if (!this._leafletWaitAttempts) this._leafletWaitAttempts = 0;
            if (this._leafletWaitAttempts < 100) { // Wait up to 10 seconds (100 * 100ms)
                this._leafletWaitAttempts++;
                setTimeout(() => this.renderWorldMap(), 100);
            } else {
                console.error('[WorldMap] Leaflet failed to load after multiple attempts');
                this.worldMap.error = "Failed to load Map Library (Leaflet). Check connection.";
                this._leafletWaitAttempts = 0;
            }
            return;
        }
        this._leafletWaitAttempts = 0; // Reset on success

        // Initialize Leaflet if not already done
        let mapJustCreated = false;
        if (!this.map) {
            mapJustCreated = true;

            // Note: Container might have zero dimensions if tab is hidden
            // Leaflet can initialize on a 0x0 container - we'll call invalidateSize() when visible
            const containerRect = container.getBoundingClientRect();

            // Ensure no previous instance exists to prevent "Map container is already initialized" error
            if (container._leaflet_id) {
                container._leaflet_id = null;
            }

            // Clear any existing content
            container.innerHTML = '';

            try {

                this.map = L.map('world-map-svg', {
                    center: [20, 0],
                    zoom: 2,
                    minZoom: 1,
                    maxZoom: 8,
                    zoomControl: false,
                    attributionControl: false,
                    preferCanvas: true, // Use canvas for better performance
                    renderer: L.canvas()
                });

                // Initialize mapLayers array if not exists
                if (!this.mapLayers) {
                    this.mapLayers = [];
                }

                // Enable zoom control for visibility confirmation
                // Note: zoomControl was set to false in constructor, we can add it back
                L.control.zoom({ position: 'topright' }).addTo(this.map);

                // Add a base tile layer immediately so map is visible
                // (Container might have 0 dimensions if tab is hidden - Leaflet handles this)
                const baseTileLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    attribution: '&copy; OpenStreetMap &copy; CARTO',
                    subdomains: 'abcd',
                    maxZoom: 19
                });
                baseTileLayer.addTo(this.map);

                // Invalidate size - even if container has 0 dimensions, Leaflet will handle it
                this.map.whenReady(() => {
                    if (!this.map) return;
                    // Call invalidateSize - will work even if container is temporarily 0x0
                    if (this.map) {
                        this.map.invalidateSize();
                    }

                    // Try to load GeoJSON overlay (optional enhancement)
                    fetch('/static/world.geojson')
                        .then(r => {
                            if (!r.ok) throw new Error(`HTTP ${r.status}`);
                            return r.json();
                        })
                        .then(geoJsonData => {
                            if (!this.map) return;
                            // Add GeoJSON as an overlay layer (optional styling enhancement)
                            const geoJsonLayer = L.geoJSON(geoJsonData, {
                                style: {
                                    fillColor: '#1a1f2e',
                                    weight: 1,
                                    opacity: 0.3,
                                    color: '#2d3748',
                                    fillOpacity: 0.1
                                }
                            });
                            geoJsonLayer.addTo(this.map);
                        })
                        .catch(e => {
                            // GeoJSON is optional, just log and continue
                            console.warn('[WorldMap] GeoJSON overlay not available, using tiles only:', e.message);
                        });

                    // Render markers after map is ready
                    this.renderWorldMapMarkers();

                    // Force a view reset and invalidateSize - this will work even if container is 0x0 initially
                    setTimeout(() => {
                        if (this.map) {
                            const rect = container.getBoundingClientRect();
                            this.map.invalidateSize();
                            this.map.setView([20, 0], 2);
                            this.mapStatus = ''; // Clear status on success
                            // If container still has dimensions, great. If not, invalidateSize() will be called again when tab becomes visible
                        }
                    }, 300);
                });

            } catch (e) {
                console.error('[WorldMap] Leaflet init failed:', e);
                // Attempt recovery: remove any existing map instance on this container ID
                if (this.map) {
                    try {
                        this.map.remove();
                    } catch (removeError) {
                        console.error('[WorldMap] Error removing map:', removeError);
                    }
                    this.map = null;
                }
                // Clear container state
                if (container._leaflet_id) {
                    container._leaflet_id = null;
                }
                return;
            }

            // Don't continue to marker rendering if map was just created - markers will be rendered after tiles load
            return;
        }

        // Ensure map size is correct (important when container visibility changes)
        if (this.map) {
            // Use setTimeout to ensure DOM has updated and container is visible
            setTimeout(() => {
                if (this.map && container.offsetWidth > 0 && container.offsetHeight > 0) {
                    this.map.invalidateSize();
                }
            }, 100);
        }

        // Render markers if map exists
        if (this.map) {
            this.renderWorldMapMarkers();
        }
    },

    renderWorldMapMarkers() {
        if (!this.map) return;

        // Initialize mapLayers array if not exists
        if (!this.mapLayers) {
            this.mapLayers = [];
        }

        // Clear existing layers
        if (this.mapLayers.length > 0) {
            this.mapLayers.forEach(l => {
                try {
                    this.map.removeLayer(l);
                } catch (e) {
                    console.warn('[WorldMap] Error removing layer:', e);
                }
            });
        }
        this.mapLayers = [];

        const addMarker = (lat, lng, color, radius, popup) => {
            const marker = L.circleMarker([lat, lng], {
                radius: radius,
                fillColor: color,
                color: color,
                weight: 1,
                opacity: 1,
                fillOpacity: 0.7
            });
            if (popup) marker.bindPopup(popup);
            marker.addTo(this.map);
            this.mapLayers.push(marker);
        };

        const sources = this.worldMapLayers.sources ? (this.worldMap.sources || []) : [];
        const dests = this.worldMapLayers.destinations ? (this.worldMap.destinations || []) : [];
        const threats = this.worldMapLayers.threats ? (this.worldMap.threats || []) : [];

        // Determine emphasis based on map mode
        const modeEmphasis = {
            'exposure': { sources: 0.3, destinations: 1.0, threats: 0.8 },
            'attacks': { sources: 0.5, destinations: 0.6, threats: 1.0 },
            'traffic': { sources: 0.4, destinations: 0.7, threats: 0.9 }
        };
        const emphasis = modeEmphasis[this.worldMapMode] || modeEmphasis.traffic;

        // Check if country is selected for highlighting
        const isCountrySelected = (countryIso) => {
            return this.worldMapSelectedCountry && countryIso === this.worldMapSelectedCountry;
        };

        // Helper to get opacity based on selection
        const getOpacity = (countryIso, baseOpacity) => {
            if (!this.worldMapSelectedCountry) return baseOpacity;
            return isCountrySelected(countryIso) ? baseOpacity : 0.2;
        };

        // Draw Sources (Cyan - subtle, smaller)
        sources.forEach(p => {
            const baseSize = Math.min(10, Math.max(4, Math.log10(p.bytes + 1) * 2));
            const size = baseSize * emphasis.sources;
            const countryIso = p.country_iso || p.iso || '';
            const opacity = getOpacity(countryIso, 0.5 * emphasis.sources);

            const marker = L.circleMarker([p.lat, p.lng], {
                radius: size,
                fillColor: '#00eaff',  /* CYBERPUNK UI: signal-primary (cyan) - subtle */
                color: '#00eaff',
                weight: 1,
                opacity: opacity,
                fillOpacity: opacity * 0.8
            });
            marker.bindPopup(`<strong>🔼 SOURCE: ${p.ip}</strong><br>📍 ${p.city || ''}, ${p.country}<br>📊 ${p.bytes_fmt}<br>${p.flows ? `📈 ${p.flows} flows` : ''}<br><button onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${p.ip}')" style="margin-top:8px;padding:4px 8px;background:#00eaff;border:none;border-radius:4px;cursor:pointer;color:#000;font-weight:600;">Investigate IP</button>`);
            marker.on('click', () => {
                this.openIPModal(p.ip);
            });
            marker.on('mouseover', () => {
                this.worldMapHoveredPoint = { type: 'source', ip: p.ip, lat: p.lat, lng: p.lng, countryIso: countryIso };
                marker.setStyle({ opacity: 1, fillOpacity: 0.9, weight: 2 });
                // Show direction context: highlight related destinations if any
                this.showDirectionContext(marker, 'source');
            });
            marker.on('mouseout', () => {
                this.worldMapHoveredPoint = null;
                marker.setStyle({ opacity: opacity, fillOpacity: opacity * 0.8, weight: 1 });
                this.hideDirectionContext();
            });
            marker.addTo(this.map);
            this.mapLayers.push(marker);
        });

        // Draw Destinations (Purple - medium emphasis)
        dests.forEach(p => {
            const baseSize = Math.min(12, Math.max(5, Math.log10(p.bytes + 1) * 2.5));
            const size = baseSize * emphasis.destinations;
            const countryIso = p.country_iso || p.iso || '';
            const opacity = getOpacity(countryIso, 0.7 * emphasis.destinations);

            const marker = L.circleMarker([p.lat, p.lng], {
                radius: size,
                fillColor: '#7b7bff',  /* CYBERPUNK UI: signal-tertiary (purple) - medium */
                color: '#7b7bff',
                weight: 1.5,
                opacity: opacity,
                fillOpacity: opacity * 0.8
            });
            marker.bindPopup(`<strong>🔽 DESTINATION: ${p.ip}</strong><br>📍 ${p.city || ''}, ${p.country}<br>📊 ${p.bytes_fmt}<br>${p.flows ? `📈 ${p.flows} flows` : ''}<br><button onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${p.ip}')" style="margin-top:8px;padding:4px 8px;background:#7b7bff;border:none;border-radius:4px;cursor:pointer;color:#000;font-weight:600;">Investigate IP</button>`);
            marker.on('click', () => {
                this.openIPModal(p.ip);
            });
            marker.on('mouseover', () => {
                this.worldMapHoveredPoint = { type: 'destination', ip: p.ip, lat: p.lat, lng: p.lng, countryIso: countryIso };
                marker.setStyle({ opacity: 1, fillOpacity: 0.9, weight: 2.5 });
                // Show direction context: highlight related sources if any
                this.showDirectionContext(marker, 'destination');
            });
            marker.on('mouseout', () => {
                this.worldMapHoveredPoint = null;
                marker.setStyle({ opacity: opacity, fillOpacity: opacity * 0.8, weight: 1.5 });
                this.hideDirectionContext();
            });
            marker.addTo(this.map);
            this.mapLayers.push(marker);
        });

        // Draw Threats (Red - prominent but balanced, not overwhelming)
        threats.forEach(p => {
            const baseSize = Math.min(12, Math.max(7, Math.log10((p.bytes || 1000) + 1) * 2.8));
            const size = baseSize * emphasis.threats;
            const countryIso = p.country_iso || p.iso || '';
            // Slightly reduce opacity to balance visual dominance while keeping threats visible
            const opacity = getOpacity(countryIso, 0.85 * emphasis.threats);

            const threatMarker = L.circleMarker([p.lat, p.lng], {
                radius: size,
                fillColor: '#ff1744',  /* CYBERPUNK UI: signal-crit (red) - ONLY for threats, prominent but balanced */
                color: '#ff1744',
                weight: 2.5,
                opacity: opacity,
                fillOpacity: opacity * 0.85
            });
            threatMarker.bindPopup(`<strong>⚠️ THREAT: ${p.ip}</strong><br>📍 ${p.city || ''}, ${p.country}<br>${p.category ? `📋 Category: ${p.category}<br>` : ''}${p.feed ? `🔖 Feed: ${p.feed}<br>` : ''}<button onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${p.ip}')" style="margin-top:8px;padding:4px 8px;background:#ff1744;border:none;border-radius:4px;cursor:pointer;color:#fff;font-weight:600;">Investigate IP</button>`);
            threatMarker.on('click', () => {
                this.openIPModal(p.ip);
            });
            threatMarker.on('mouseover', () => {
                this.worldMapHoveredPoint = { type: 'threat', ip: p.ip, lat: p.lat, lng: p.lng, countryIso: countryIso };
                threatMarker.setStyle({ opacity: 1, fillOpacity: 1, weight: 3 });
            });
            threatMarker.on('mouseout', () => {
                this.worldMapHoveredPoint = null;
                threatMarker.setStyle({ opacity: opacity, fillOpacity: opacity * 0.9, weight: 2.5 });
            });
            threatMarker.addTo(this.map);
            this.mapLayers.push(threatMarker);
        });

        // Direction context is shown via hover events above (markers brighten on hover)
        // No animated arcs or lines - calm by default
    },

    showDirectionContext(hoveredMarker, type) {
        // Subtle direction context: related markers brighten slightly
        // This is handled in the hover events above via setStyle
        // No visual lines or arcs - just emphasis on hover
    },

    hideDirectionContext() {
        // Reset is handled in mouseout events above
    },

    resetWorldMapView() {
        if (this.map) {
            this.map.setView([20, 0], 2);
        }
        this.worldMapSelectedCountry = null;
        this.worldMapHoveredPoint = null;
        this.renderWorldMap();
    },

    selectCountryForMap(countryIso) {
        // Toggle: if same country clicked, deselect
        if (this.worldMapSelectedCountry === countryIso) {
            this.worldMapSelectedCountry = null;
        } else {
            this.worldMapSelectedCountry = countryIso;
        }
        this.renderWorldMap();
    },

    async fetchDurations() {
        this.durations.loading = true;
        try {
            const res = await fetch(`/api/stats/durations?range=${this.timeRange}`);
            if (res.ok) this.durations = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.durations.loading = false; }
    },

    async fetchTalkers() {
        this.talkers.loading = true;
        try {
            const res = await fetch(`/api/stats/talkers?range=${this.timeRange}`);
            if (res.ok) this.talkers = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.talkers.loading = false; }
    },

    async fetchServices() {
        this.services.loading = true;
        try {
            const res = await fetch(`/api/stats/services?range=${this.timeRange}`);
            if (res.ok) this.services = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.services.loading = false; }
    },

    // FIXED-SCOPE: Always 24h (by backend design) - ignoring global timeRange is intentional
    async fetchHourlyTraffic() {
        this.hourlyTraffic.loading = true;
        try {
            const res = await fetch('/api/stats/hourly');
            if (res.ok) {
                const data = await res.json();
                this.hourlyTraffic = { ...data };
                // Defer chart update to ensure canvas is visible
                this.$nextTick(() => {
                    setTimeout(() => this.updateHourlyChart(data), 100);
                });
            }
        } catch (e) { console.error(e); } finally { this.hourlyTraffic.loading = false; }
    },

    updateHourlyChart(data) {
        try {
            // Try both canvas IDs (for backward compatibility with overview widget)
            let ctx = document.getElementById('hourlyChart');
            let chartId = 'hourlyChart';
            if (!ctx || !data || !data.labels || !data.bytes || !Array.isArray(data.bytes) || data.bytes.length === 0) {
                // Silently return if canvas not found or data is empty (expected when no data available)
                return;
            }

            // Check if canvas parent container is visible
            const container = ctx.closest('.widget-body, .chart-wrapper-small');
            if (container && (!container.offsetParent || container.offsetWidth === 0 || container.offsetHeight === 0)) {
                // Container not visible yet, defer initialization (limit retries)
                if (!this._hourlyChartRetries) this._hourlyChartRetries = 0;
                if (this._hourlyChartRetries < 50) {
                    this._hourlyChartRetries++;
                    setTimeout(() => this.updateHourlyChart(data), 200);
                    return;
                } else {
                    console.warn('Hourly chart container not visible after retries, forcing render');
                    this._hourlyChartRetries = 0;
                }
            }
            this._hourlyChartRetries = 0;

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                setTimeout(() => this.updateHourlyChart(data), 100);
                return;
            }

            // Get gradient colors matching Top Services bars
            const cyanColor = this.getCssVar('--accent-cyan') || this.getCssVar('--signal-primary') || '#00eaff';
            const magentaColor = this.getCssVar('--accent-magenta') || '#ff00ff';

            // Use different chart instances for different canvas IDs
            const instanceKey = 'hourlyChartInstance';
            const chartInstance = _chartInstances[instanceKey];

            // Helper function to create gradient for each bar (matches Top Services gradient style)
            const createGradient = (chartCtx, isPeak = false) => {
                try {
                    // Ensure canvas has dimensions before creating gradient
                    const canvas = chartCtx.canvas;
                    const height = canvas.height || canvas.clientHeight || 200; // Fallback height
                    if (height <= 0) {
                        console.warn('Canvas height is 0, using fallback color');
                        return isPeak ? '#00ff88' : cyanColor;
                    }
                    const gradient = chartCtx.createLinearGradient(0, 0, 0, height);
                    // Use same gradient style as Top Services: cyan to magenta
                    // For peak hour, use brighter green to magenta; otherwise cyan to magenta
                    const startColor = isPeak ? '#00ff88' : cyanColor;
                    const endColor = magentaColor;
                    gradient.addColorStop(0, startColor);
                    gradient.addColorStop(1, endColor);
                    return gradient;
                } catch (e) {
                    console.warn('Gradient creation failed, using solid color:', e);
                    return isPeak ? '#00ff88' : cyanColor;
                }
            };

            if (chartInstance) {
                chartInstance.data.labels = data.labels;
                chartInstance.data.datasets[0].data = data.bytes;
                // Update gradients for each bar using the chart's context
                // Wait for chart to be fully rendered before creating gradients
                setTimeout(() => {
                    try {
                        const chartCtx = chartInstance.ctx;
                        if (chartCtx && chartCtx.canvas) {
                            chartInstance.data.datasets[0].backgroundColor = data.bytes.map((_, i) =>
                                createGradient(chartCtx, i === data.peak_hour)
                            );
                            chartInstance.data.datasets[0].borderColor = data.bytes.map((_, i) =>
                                i === data.peak_hour ? '#00ff88' : cyanColor
                            );
                            chartInstance.update('none'); // Use 'none' to prevent animation issues
                        }
                    } catch (e) {
                        console.error('Error updating chart gradients:', e);
                        // Fallback to solid colors
                        chartInstance.data.datasets[0].backgroundColor = data.bytes.map((_, i) =>
                            i === data.peak_hour ? '#00ff88' : cyanColor
                        );
                        chartInstance.data.datasets[0].borderColor = data.bytes.map((_, i) =>
                            i === data.peak_hour ? '#00ff88' : cyanColor
                        );
                        chartInstance.update('none');
                    }
                }, 50);
            } else {
                // Create chart first, then update with gradients
                const newChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: 'Traffic',
                            data: data.bytes,
                            backgroundColor: data.bytes.map((_, i) => i === data.peak_hour ? '#00ff88' : cyanColor), // Use solid colors initially
                            borderColor: data.bytes.map((_, i) => i === data.peak_hour ? '#00ff88' : cyanColor),
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: {
                                ticks: { color: '#888', font: { size: 9 }, maxRotation: 45 },
                                grid: { display: false }
                            },
                            y: {
                                ticks: {
                                    color: '#888',
                                    font: { size: 9 },
                                    callback: v => this.fmtBytes(v)
                                },
                                grid: { color: 'rgba(255,255,255,0.05)' }
                            }
                        },
                        animation: {
                            duration: 0 // Disable animation to prevent rendering issues
                        }
                    }
                });

                // Update with gradients after chart is fully rendered
                setTimeout(() => {
                    try {
                        const chartCtx = newChart.ctx;
                        if (chartCtx && chartCtx.canvas && chartCtx.canvas.height > 0) {
                            newChart.data.datasets[0].backgroundColor = data.bytes.map((_, i) =>
                                createGradient(chartCtx, i === data.peak_hour)
                            );
                            newChart.update('none');
                        }
                    } catch (e) {
                        console.warn('Gradient update failed, keeping solid colors:', e);
                    }
                }, 100);

                _chartInstances[instanceKey] = newChart;
            }
        } catch (e) {
            console.error('Chart render error:', e);
        }
    },

    async fetchFlowStats() {
        this.flowStats.loading = true;
        try {
            const res = await fetch(`/api/stats/flow_stats?range=${this.timeRange}`);
            if (res.ok) this.flowStats = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.flowStats.loading = false; }
    },





    async fetchProtoMix() {
        this.protoMix.loading = true;
        try {
            const res = await fetch(`/api/stats/proto_mix?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                this.protoMix = { ...data };
                // Defer chart update to ensure canvas is visible
                this.$nextTick(() => {
                    setTimeout(() => this.updateProtoMixChart(data), 100);
                });
            }
        } catch (e) { console.error(e); } finally { this.protoMix.loading = false; }
    },

    async fetchProtocolHierarchy() {
        this.protocolHierarchy.loading = true;
        try {
            const res = await fetch(`/api/stats/protocol_hierarchy?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                this.protocolHierarchy = { data: data, loading: false };
                this.$nextTick(() => {
                    setTimeout(() => this.renderProtocolHierarchyChart(), 100);
                });
            }
        } catch (e) {
            console.error('fetchProtocolHierarchy error:', e);
        } finally {
            this.protocolHierarchy.loading = false;
        }
    },

    renderProtocolHierarchyChart() {
        const ctx = document.getElementById('protocolHierarchyChart');
        if (!ctx || !this.protocolHierarchy.data) return;

        if (typeof Chart === 'undefined') {
            setTimeout(() => this.renderProtocolHierarchyChart(), 100);
            return;
        }

        // Prepare data for double doughnut
        // Inner ring: L4 Protocols
        // Outer ring: L7 Services
        const hierarchy = this.protocolHierarchy.data;
        const l4Labels = [];
        const l4Data = [];
        // Helper to add alpha to hex colors (Cyberpunk Style)
        const addAlpha = (hex, alpha) => {
            if (!hex.startsWith('#')) return hex; // Fallback if not hex
            const r = parseInt(hex.slice(1, 3), 16);
            const g = parseInt(hex.slice(3, 5), 16);
            const b = parseInt(hex.slice(5, 7), 16);
            return `rgba(${r}, ${g}, ${b}, ${alpha})`;
        };

        const cyan = this.getCssVar('--neon-cyan') || '#00eaff';
        const purple = this.getCssVar('--neon-purple') || '#bc13fe';
        const green = this.getCssVar('--neon-green') || '#00ff88';
        const yellow = this.getCssVar('--neon-yellow') || '#ffff00';

        const l4Colors = [cyan, purple, green, yellow];
        const l4Backgrounds = [];

        const l7Labels = [];
        const l7Data = [];
        const l7Backgrounds = [];

        if (hierarchy.children) {
            hierarchy.children.forEach((l4, i) => {
                l4Labels.push(l4.name);
                l4Data.push(l4.total_bytes);
                const color = l4Colors[i % l4Colors.length];
                l4Backgrounds.push(color);

                if (l4.children) {
                    l4.children.forEach(l7 => {
                        l7Labels.push(l7.name);
                        l7Data.push(l7.value);
                        l7Backgrounds.push(addAlpha(color, 0.6));
                    });
                }
            });
        }

        // Destroy existing
        if (_chartInstances['protocolHierarchy']) {
            _chartInstances['protocolHierarchy'].destroy();
        }

        _chartInstances['protocolHierarchy'] = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: l7Labels,
                datasets: [
                    {
                        label: 'Service (L7)',
                        data: l7Data,
                        backgroundColor: l7Backgrounds,
                        borderColor: 'rgba(0,0,0,0.5)',
                        borderWidth: 1,
                        weight: 2,
                        hoverOffset: 15
                    },
                    {
                        label: 'Protocol (L4)',
                        data: l4Data,
                        backgroundColor: l4Backgrounds,
                        borderColor: 'rgba(0,0,0,0.5)',
                        borderWidth: 2,
                        weight: 1,
                        hoverOffset: 10
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '45%',
                radius: '90%',
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const val = this.fmtBytes(context.raw);
                                return `${context.chart.data.labels[context.dataIndex] || ''}: ${val}`;
                            }
                        }
                    }
                },
                cutout: '30%'
            }
        });
    },

    // FIXED-SCOPE: Anomalies (24h) - fixed 24h window, does not use global_time_range
    // Note: Returns anomalies_24h field, not time-range dependent
    async fetchNetworkStatsOverview() {
        this.networkStatsOverview.loading = true;
        try {
            const res = await fetch('/api/network/stats/overview');
            if (res.ok) {
                const d = await res.json();
                this.networkStatsOverview = {
                    // Preserve null vs 0 distinction for truthfulness
                    active_flows: d.active_flows ?? null,
                    external_connections: d.external_connections ?? null,
                    anomalies_24h: d.anomalies_24h ?? null,
                    trends: d.trends || {},
                    loading: false
                };
            } else {
                this.networkStatsOverview.loading = false;
            }
        } catch (e) {
            console.error('Network stats overview fetch error:', e);
            this.networkStatsOverview.loading = false;
        }
    },

    async fetchBaselineSignals() {
        this.baselineSignals.loading = true;
        try {
            const res = await fetch('/api/health/baseline-signals');
            if (res.ok) {
                const d = await res.json();
                this.baselineSignals = {
                    signals: d.signals || [],
                    signal_details: d.signal_details || [],
                    metrics: d.metrics || {},
                    baselines_available: d.baselines_available || {},
                    loading: false
                };
            } else {
                this.baselineSignals.loading = false;
            }
        } catch (e) {
            console.error('Baseline signals fetch error:', e);
            this.baselineSignals.loading = false;
        }
    },

    async fetchNetHealth() {
        this.netHealth.loading = true;
        try {
            const res = await fetch(`/api/stats/net_health?range=${this.timeRange}`);
            if (res.ok) this.netHealth = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.netHealth.loading = false; }
    },

    async fetchIngestionRates() {
        try {
            const response = await fetch('/api/server/ingestion');
            if (!response.ok) return;
            const data = await response.json();
            this.ingestionRates = data.rates;
        } catch (e) {
            console.error("Failed to fetch ingestion rates:", e);
            this.ingestionRates = null;
        }
    },

    async fetchServerHealth() {
        // Prevent concurrent requests
        if (this._serverHealthFetching) return;
        this._serverHealthFetching = true;

        // Only set loading on initial fetch (prevent flickering on refresh)
        const isInitialLoad = !this.serverHealth.timestamp;
        if (isInitialLoad) {
            this.serverHealth.loading = true;
        }
        this.serverHealth.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/server/health?_=${Date.now()}`);
            if (res.ok) {
                const data = await res.json();
                // Update nested properties individually to ensure Alpine.js reactivity
                // This ensures all widget bindings (cpu.percent, memory.percent, etc.) are properly updated
                if (data.cpu) this.serverHealth.cpu = data.cpu;
                if (data.memory) this.serverHealth.memory = data.memory;
                if (data.disk) this.serverHealth.disk = data.disk;
                if (data.syslog) this.serverHealth.syslog = data.syslog;
                if (data.firewall_syslog) this.serverHealth.firewall_syslog = data.firewall_syslog;
                if (data.netflow) this.serverHealth.netflow = data.netflow;
                if (data.database) this.serverHealth.database = data.database;
                if (data.system) this.serverHealth.system = data.system;
                if (data.network) this.serverHealth.network = data.network;
                if (data.cache) this.serverHealth.cache = data.cache;
                if (data.process) this.serverHealth.process = data.process;
                if (data.timestamp) this.serverHealth.timestamp = data.timestamp;
                this.serverHealth.loading = false;
                this.serverHealth.error = null;
            } else if (res.status === 429) {
                // Rate limited - pause auto-refresh temporarily
                console.warn('Rate limited on server health, pausing auto-refresh');
                if (this.serverHealthRefreshTimer) {
                    clearInterval(this.serverHealthRefreshTimer);
                    this.serverHealthRefreshTimer = null;
                }
                this.serverHealth.error = 'Rate limited - auto-refresh paused';
            } else {
                const errorMsg = `Server health fetch failed: ${res.status}`;
                console.error(errorMsg);
                this.serverHealth.error = DashboardUtils?.getUserFriendlyError(new Error(errorMsg), 'load server health') || errorMsg;
                this.serverHealth.loading = false;
            }
        } catch (e) {
            console.error('Server health fetch error:', e);
            this.serverHealth.error = DashboardUtils?.getUserFriendlyError(e, 'load server health') || 'Failed to load server health';
        } finally {
            this.serverHealth.loading = false;
            this._serverHealthFetching = false;
        }
    },

    startServerHealthAutoRefresh() {
        // Clear existing timer if any
        if (this.serverHealthRefreshTimer) {
            clearInterval(this.serverHealthRefreshTimer);
            this.serverHealthRefreshTimer = null;
        }

        // Only start if server tab is active
        if (this.activeTab !== 'server') return;

        // Initial fetch
        this.fetchServerHealth();
        this.fetchDatabaseStats();
        this.fetchServerLogs(100);

        // Set up 2-second interval refresh for real-time updates (independent of global refresh)
        this.serverHealthRefreshTimer = setInterval(() => {
            if (this.activeTab === 'server' && !this.paused) {
                this.fetchServerHealth();
                // Database stats don't need frequent updates - refresh every 30 seconds
                const now = Date.now();
                if (!this._lastDatabaseStatsFetch || (now - this._lastDatabaseStatsFetch) > 30000) {
                    this.fetchDatabaseStats();
                    this._lastDatabaseStatsFetch = now;
                }
                // Logs refresh every 10 seconds
                if (!this._lastServerLogsFetch || (now - this._lastServerLogsFetch) > 10000) {
                    this.fetchServerLogs(this.serverLogs.lines || 100);
                    this._lastServerLogsFetch = now;
                }
            } else {
                // Clean up if tab changed or paused
                if (this.serverHealthRefreshTimer) {
                    clearInterval(this.serverHealthRefreshTimer);
                    this.serverHealthRefreshTimer = null;
                }
            }
        }, 2000);
    },

    async fetchServerLogs(lines = 100) {
        if (this._serverLogsFetching) return;
        this._serverLogsFetching = true;
        this.serverLogs.loading = true;
        this.serverLogs.lines = lines;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/server/logs?lines=${lines}&_=${Date.now()}`);
            if (res.ok) {
                const data = await res.json();
                this.serverLogs.logs = data.logs || [];
                this.serverLogs.count = data.count || 0;
                this.serverLogs.source = data.source || 'none';
                this.serverLogs.container = data.container || '';
                this.serverLogs.loading = false;
            } else {
                this.serverLogs.logs = [`Error fetching logs: ${res.status} ${res.statusText}`];
                this.serverLogs.count = 1;
                this.serverLogs.loading = false;
            }
        } catch (e) {
            console.error('Server logs fetch error:', e);
            this.serverLogs.logs = [`Error: ${e.message}`];
            this.serverLogs.count = 1;
            this.serverLogs.loading = false;
        } finally {
            this._serverLogsFetching = false;
        }
    },

    async fetchDatabaseStats() {
        if (this._databaseStatsFetching) return;
        this._databaseStatsFetching = true;

        const isInitialLoad = !this.databaseStats.timestamp;
        if (isInitialLoad) {
            this.databaseStats.loading = true;
        }
        this.databaseStats.error = null;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/server/database-stats?_=${Date.now()}`);
            if (res.ok) {
                const data = await res.json();
                this.databaseStats.databases = data.databases || [];
                this.databaseStats.timestamp = data.timestamp;
                this.databaseStats.loading = false;
                this.databaseStats.error = null;

                // Render sparklines after data update (non-reactive, one-time render)
                this.$nextTick(() => {
                    this.renderDatabaseSizeSparklines();
                });
            } else {
                const errorMsg = `Database stats fetch failed: ${res.status}`;
                console.error(errorMsg);
                this.databaseStats.error = DashboardUtils?.getUserFriendlyError(new Error(errorMsg), 'load database stats') || errorMsg;
                this.databaseStats.loading = false;
            }
        } catch (e) {
            console.error('Database stats fetch error:', e);
            this.databaseStats.error = DashboardUtils?.getUserFriendlyError(e, 'load database stats') || 'Failed to load database stats';
            this.databaseStats.loading = false;
        } finally {
            this._databaseStatsFetching = false;
        }
    },

    renderDatabaseSizeSparklines() {
        // Safe sparkline rendering: only reads existing data, no reactivity triggers
        if (!this.databaseStats || !this.databaseStats.databases) return;

        this.databaseStats.databases.forEach(db => {
            if (!db.size_history || db.size_history.length < 2) return;

            const canvasId = `dbSparkline_${db.name}`;
            const canvas = document.getElementById(canvasId);
            if (!canvas) return;

            // Check if data has changed (compare last rendered data hash)
            const dataHash = JSON.stringify(db.size_history);
            if (canvas._lastDataHash === dataHash) return; // Skip if data unchanged

            const ctx = canvas.getContext('2d');
            const w = canvas.width;
            const h = canvas.height;

            // Clear canvas
            ctx.clearRect(0, 0, w, h);

            // Get size history values
            const values = db.size_history;
            if (values.length < 2) return;

            // Calculate min/max for scaling
            const min = Math.min(...values);
            const max = Math.max(...values);
            const range = max - min || 1; // Avoid division by zero

            // Draw sparkline
            const step = w / (values.length - 1);
            const grad = ctx.createLinearGradient(0, 0, w, 0);
            grad.addColorStop(0, '#00f3ff');
            grad.addColorStop(1, '#bc13fe');

            ctx.strokeStyle = grad;
            ctx.lineWidth = 1.5;
            ctx.beginPath();

            for (let i = 0; i < values.length; i++) {
                const x = i * step;
                const normalized = (values[i] - min) / range;
                const y = h - (normalized * (h - 4)) - 2; // Leave 2px padding

                if (i === 0) {
                    ctx.moveTo(x, y);
                } else {
                    ctx.lineTo(x, y);
                }
            }

            ctx.stroke();

            // Store data hash to prevent unnecessary re-renders
            canvas._lastDataHash = dataHash;
        });
    },

    async fetchFirewallSNMP() {
        // Prevent concurrent requests
        if (this._firewallSNMPFetching) return;
        this._firewallSNMPFetching = true;

        const isInitialLoad = !this.firewallSNMP.last_poll;
        if (isInitialLoad) {
            this.firewallSNMP.loading = true;
        }
        this.firewallSNMP.error = null;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/firewall/snmp-status?_=${Date.now()}`);

            if (res.ok) {
                const data = await res.json();
                if (data.error) {
                    this.firewallSNMP.error = data.error;
                    this.firewallSNMP.poll_success = false;
                } else {
                    this.firewallSNMP.cpu_percent = data.cpu_percent;
                    this.firewallSNMP.memory_percent = data.memory_percent;
                    this.firewallSNMP.active_sessions = data.active_sessions;
                    this.firewallSNMP.total_throughput_mbps = data.total_throughput_mbps;
                    this.firewallSNMP.uptime_formatted = data.uptime_formatted;
                    this.firewallSNMP.uptime_seconds = data.uptime_seconds;
                    this.firewallSNMP.interfaces = data.interfaces || [];
                    this.firewallSNMP.last_poll = data.last_poll;
                    this.firewallSNMP.poll_success = data.poll_success;
                    this.firewallSNMP.traffic_correlation = data.traffic_correlation || null;
                    this.firewallSNMP.error = null;
                }
            } else {
                this.firewallSNMP.error = 'Failed to fetch SNMP data';
                this.firewallSNMP.poll_success = false;
            }
        } catch (e) {
            console.error('Firewall SNMP fetch error:', e);
            this.firewallSNMP.error = 'SNMP service unavailable';
            this.firewallSNMP.poll_success = false;
        } finally {
            this.firewallSNMP.loading = false;
            this._firewallSNMPFetching = false;
        }
    },

    async fetchBandwidth() {
        this.bandwidth.loading = true;
        this.bandwidth.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/bandwidth?range=${this.global_time_range}`);
            const data = await res.json();
            this.bandwidth = { ...data, loading: false, error: null };
            this.updateBwChart(data);
        } catch (e) {
            console.error('Failed to fetch bandwidth:', e);
            this.bandwidth.error = DashboardUtils?.getUserFriendlyError(e, 'load bandwidth') || 'Failed to load bandwidth';
        } finally {
            this.bandwidth.loading = false;
        }
    },

    updateBwChart(data) {
        try {
            const ctx = document.getElementById('bwChart');
            if (!ctx || !data || !data.labels) return;

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                console.warn('Chart.js not loaded yet, deferring chart creation');
                setTimeout(() => this.updateBwChart(data), 100);
                return;
            }

            // Prevent recursive updates
            if (this._bwUpdating) return;
            this._bwUpdating = true;

            const colorArea = 'rgba(0, 243, 255, 0.2)';
            const colorLine = this.getCssVar('--neon-cyan') || '#00f3ff';
            const colorFlows = this.getCssVar('--neon-purple') || '#bc13fe';

            // Destroy existing chart if it exists but is in bad state
            if (_chartInstances['bwChartInstance']) {
                try {
                    _chartInstances['bwChartInstance'].data.labels = data.labels;
                    _chartInstances['bwChartInstance'].data.datasets[0].data = data.bandwidth;
                    _chartInstances['bwChartInstance'].data.datasets[1].data = data.flows;
                    _chartInstances['bwChartInstance'].update('none'); // 'none' mode prevents animation
                } catch (e) {
                    // Chart instance is corrupted, destroy and recreate
                    console.warn('Bandwidth chart instance corrupted, recreating:', e);
                    try {
                        _chartInstances['bwChartInstance'].destroy();
                    } catch { }
                    _chartInstances['bwChartInstance'] = null;
                }
            }

            // Create new chart if instance doesn't exist
            if (!_chartInstances['bwChartInstance']) {
                _chartInstances['bwChartInstance'] = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: data.labels,
                        datasets: [
                            {
                                label: 'Traffic (Mbps)',
                                data: data.bandwidth,
                                borderColor: colorLine,
                                backgroundColor: colorArea,
                                borderWidth: 2,
                                fill: true,
                                tension: 0.4,
                                yAxisID: 'y'
                            },
                            {
                                label: 'Flows/s',
                                data: data.flows,
                                borderColor: colorFlows,
                                backgroundColor: 'transparent',
                                borderWidth: 2,
                                tension: 0.4,
                                yAxisID: 'y1'
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: { mode: 'index', intersect: false },
                        plugins: { legend: { labels: { color: '#e0e0e0' } } },
                        scales: {
                            y: {
                                type: 'linear',
                                display: true,
                                position: 'left',
                                grid: { color: '#333' },
                                ticks: { color: '#888' }
                            },
                            y1: {
                                type: 'linear',
                                display: true,
                                position: 'right',
                                grid: { drawOnChartArea: false },
                                ticks: { color: '#888' }
                            },
                            x: {
                                grid: { color: '#333' },
                                ticks: { color: '#888' }
                            }
                        },
                        animation: false // Disable animation to prevent reactive loops
                    }
                });
            }
            this._bwUpdating = false;
        } catch (e) {
            console.error('Chart render error:', e);
            this._bwUpdating = false;
        }
    },

    async fetchPacketSizes() {
        this.packetSizes.loading = true;
        try {
            const res = await fetch(`/api/stats/packet_sizes?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                this.packetSizes = { ...data };
                // Defer chart update to ensure canvas is visible
                this.$nextTick(() => {
                    setTimeout(() => this.updatePktSizeChart(data), 100);
                });
            }
        } catch (e) { console.error(e); } finally { this.packetSizes.loading = false; }
    },

    updatePktSizeChart(data) {
        try {
            const ctx = document.getElementById('pktSizeChart');
            if (!ctx || !data || !data.labels) return;

            // Check if canvas parent container is visible
            const container = ctx.closest('.widget-body, .chart-wrapper-small');
            if (container && (!container.offsetParent || container.offsetWidth === 0 || container.offsetHeight === 0)) {
                // Container not visible yet, defer initialization (limit retries)
                if (!this._pktSizeRetries) this._pktSizeRetries = 0;
                if (this._pktSizeRetries < 50) {
                    this._pktSizeRetries++;
                    setTimeout(() => this.updatePktSizeChart(data), 200);
                    return;
                } else {
                    console.warn('Packet Size chart container not visible after retries, forcing render');
                    this._pktSizeRetries = 0;
                }
            }
            this._pktSizeRetries = 0;

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                setTimeout(() => this.updatePktSizeChart(data), 100);
                return;
            }

            // Prevent recursive updates
            if (this._pktSizeUpdating) return;
            this._pktSizeUpdating = true;

            // Cyberpunk palette
            const colors = ['#bc13fe', '#00f3ff', '#0aff0a', '#ffff00', '#ff003c'];

            // Destroy existing chart if it exists but is in bad state
            if (_chartInstances['pktSizeChartInstance']) {
                try {
                    _chartInstances['pktSizeChartInstance'].data.labels = data.labels;
                    _chartInstances['pktSizeChartInstance'].data.datasets[0].data = data.data;
                    _chartInstances['pktSizeChartInstance'].update('none'); // 'none' mode prevents animation that might trigger reactivity
                } catch (e) {
                    // Chart instance is corrupted, destroy and recreate
                    console.warn('Packet Size chart instance corrupted, recreating:', e);
                    try {
                        _chartInstances['pktSizeChartInstance'].destroy();
                    } catch { }
                    _chartInstances['pktSizeChartInstance'] = null;
                }
            }

            // Create new chart if instance doesn't exist
            if (!_chartInstances['pktSizeChartInstance']) {
                _chartInstances['pktSizeChartInstance'] = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: 'Flows',
                            data: data.data,
                            backgroundColor: colors,
                            borderWidth: 0
                        }]
                    },
                    options: {
                        indexAxis: 'y', // Horizontal bar
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: false, // Disable animation to prevent reactive loops
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            x: {
                                grid: { color: '#333' },
                                ticks: { color: '#888' }
                            },
                            y: {
                                grid: { display: false },
                                ticks: { color: '#e0e0e0', font: { size: 10 } }
                            }
                        }
                    }
                });
            }
            this._pktSizeUpdating = false;
        } catch (e) {
            console.error('Chart render error:', e);
            this._pktSizeUpdating = false;
        }
    },

    updateCountriesChart(data) {
        try {
            // Prevent recursive updates
            if (this._countriesUpdating) return;
            this._countriesUpdating = true;

            const ctx = document.getElementById('countriesChart');
            if (!ctx || !data) {
                this._countriesUpdating = false;
                return;
            }

            // Check if canvas parent container is visible
            const container = ctx.closest('.widget-body, .chart-wrapper-small');
            if (container && (!container.offsetParent || container.offsetWidth === 0 || container.offsetHeight === 0)) {
                // Container not visible yet, defer initialization (limit retries)
                if (!this._countriesRetries) this._countriesRetries = 0;
                if (this._countriesRetries < 50) {
                    this._countriesRetries++;
                    this._countriesUpdating = false;
                    setTimeout(() => this.updateCountriesChart(data), 200);
                    return;
                } else {
                    console.warn('Countries chart container not visible after retries, forcing render');
                    this._countriesRetries = 0;
                }
            }
            this._countriesRetries = 0;

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                this._countriesUpdating = false;
                setTimeout(() => this.updateCountriesChart(data), 100);
                return;
            }

            const labels = data.labels || [];
            const values = data.bytes || [];
            const colors = ['#00f3ff', '#bc13fe', '#0aff0a', '#ffff00', '#ff003c', '#ff7f50', '#7fffd4', '#ffd700', '#00fa9a', '#ffa07a'];

            if (_chartInstances['countriesChartInstance']) {
                try {
                    _chartInstances['countriesChartInstance'].data.labels = labels;
                    _chartInstances['countriesChartInstance'].data.datasets[0].data = values;
                    _chartInstances['countriesChartInstance'].update('none'); // 'none' mode prevents animation
                } catch (e) {
                    // Chart instance is corrupted, destroy and recreate
                    console.warn('Countries chart instance corrupted, recreating:', e);
                    try {
                        _chartInstances['countriesChartInstance'].destroy();
                    } catch { }
                    _chartInstances['countriesChartInstance'] = null;
                }
            }

            // Create new chart if instance doesn't exist
            if (!_chartInstances['countriesChartInstance']) {
                _chartInstances['countriesChartInstance'] = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels,
                        datasets: [{
                            label: 'Bytes',
                            data: values,
                            backgroundColor: colors,
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: false, // Disable animation to prevent reactive loops
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { ticks: { color: '#888' }, grid: { color: '#333' } },
                            y: { ticks: { color: '#888' }, grid: { color: '#333' } }
                        },
                        onClick: (e, elements, chart) => {
                            if (elements && elements.length > 0) {
                                // Just open the expanded table for now, regardless of which bar was clicked
                                // A future enhancement could be to filter the expanded table by the specific country
                                this.openExpandedTable('countries');
                            }
                        },
                        onHover: (e, elements) => {
                            e.native.target.style.cursor = elements && elements.length > 0 ? 'pointer' : 'default';
                        }
                    }
                });
            }
            this._countriesUpdating = false;
        } catch (e) {
            console.error('Chart render error:', e);
            this._countriesUpdating = false;
        }
    },

    updateProtoMixChart(data) {
        try {
            // Prevent recursive updates
            if (this._protoMixUpdating) return;
            this._protoMixUpdating = true;

            const ctx = document.getElementById('protoMixChart');
            if (!ctx || !data || !data.labels) {
                this._protoMixUpdating = false;
                return;
            }

            // Check if canvas parent container is visible
            const container = ctx.closest('.widget-body, .chart-wrapper-small');
            if (container && (!container.offsetParent || container.offsetWidth === 0 || container.offsetHeight === 0)) {
                // Container not visible yet, defer initialization (limit retries)
                if (!this._protoMixRetries) this._protoMixRetries = 0;
                if (this._protoMixRetries < 50) {
                    this._protoMixRetries++;
                    this._protoMixUpdating = false;
                    setTimeout(() => this.updateProtoMixChart(data), 200);
                    return;
                } else {
                    console.warn('Protocol Mix chart container not visible after retries, forcing render');
                    this._protoMixRetries = 0;
                }
            }
            this._protoMixRetries = 0;

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                this._protoMixUpdating = false;
                setTimeout(() => this.updateProtoMixChart(data), 100);
                return;
            }

            const labels = data.labels || [];
            const bytes = data.bytes || [];
            const colors = data.colors || ['#00f3ff', '#bc13fe', '#00ff88', '#ffff00', '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4'];

            if (_chartInstances['protoMixChartInstance']) {
                try {
                    _chartInstances['protoMixChartInstance'].data.labels = labels;
                    _chartInstances['protoMixChartInstance'].data.datasets[0].data = bytes;
                    _chartInstances['protoMixChartInstance'].data.datasets[0].backgroundColor = colors;
                    _chartInstances['protoMixChartInstance'].update('none'); // 'none' mode prevents animation
                } catch (e) {
                    // Chart instance is corrupted, destroy and recreate
                    console.warn('Protocol Mix chart instance corrupted, recreating:', e);
                    try {
                        _chartInstances['protoMixChartInstance'].destroy();
                    } catch { }
                    _chartInstances['protoMixChartInstance'] = null;
                }
            }

            // Create new chart if instance doesn't exist
            if (!_chartInstances['protoMixChartInstance']) {
                _chartInstances['protoMixChartInstance'] = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: bytes,
                            backgroundColor: colors,
                            borderColor: 'rgba(0,0,0,0.3)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: false, // Disable animation to prevent reactive loops
                        plugins: {
                            legend: {
                                display: true,
                                position: 'right',
                                labels: {
                                    color: '#aaa',
                                    font: { size: 10 },
                                    boxWidth: 12
                                }
                            },
                            tooltip: {
                                callbacks: {
                                    label: function (context) {
                                        const label = context.label || '';
                                        const value = data.bytes_fmt ? data.bytes_fmt[context.dataIndex] : context.formattedValue;
                                        const pct = data.percentages ? data.percentages[context.dataIndex] : '';
                                        return `${label}: ${value}${pct ? ' (' + pct + '%)' : ''}`;
                                    }
                                }
                            }
                        }
                    }
                });
            }
            this._protoMixUpdating = false;
        } catch (e) {
            console.error('Chart render error:', e);
            this._protoMixUpdating = false;
        }
    },

    updateFlagsChart(flagsData) {
        try {
            const ctx = document.getElementById('flagsChart');
            if (!ctx || !flagsData) return;

            // Check if canvas parent container is visible
            const container = ctx.closest('.widget-body, .chart-wrapper-small');
            if (container && (!container.offsetParent || container.offsetWidth === 0 || container.offsetHeight === 0)) {
                // Container not visible yet, defer initialization
                if (!this._flagsRetries) this._flagsRetries = 0;
                if (this._flagsRetries < 50) {
                    this._flagsRetries++;
                    setTimeout(() => this.updateFlagsChart(flagsData), 200);
                    return;
                } else {
                    console.warn('Flags chart container not visible after retries, forcing render');
                    this._flagsRetries = 0;
                }
            }
            this._flagsRetries = 0;

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                setTimeout(() => this.updateFlagsChart(flagsData), 100);
                return;
            }

            // Prevent recursive updates
            if (this._flagsUpdating) return;
            this._flagsUpdating = true;

            const labels = flagsData.map(f => f.flag);
            const data = flagsData.map(f => f.count);
            // Cyberpunk palette - using theme colors
            const cyanColor = this.getCssVar('--accent-cyan') || this.getCssVar('--signal-primary') || '#00eaff';
            const purpleColor = this.getCssVar('--accent-magenta') || this.getCssVar('--signal-tertiary') || '#7b7bff';
            const greenColor = this.getCssVar('--signal-ok') || '#00ff88';
            const redColor = this.getCssVar('--signal-crit') || '#ff1744';
            const yellowColor = this.getCssVar('--signal-warn') || '#ffb400';
            const colors = [cyanColor, purpleColor, greenColor, redColor, yellowColor, '#ffffff'];

            // Destroy existing chart to force legend regeneration with correct labels
            if (_chartInstances['flagsChartInstance']) {
                try {
                    _chartInstances['flagsChartInstance'].destroy();
                } catch (e) {
                    console.warn('Error destroying flags chart:', e);
                }
                _chartInstances['flagsChartInstance'] = null;
            }

            // Create new chart if instance doesn't exist
            if (!_chartInstances['flagsChartInstance']) {
                _chartInstances['flagsChartInstance'] = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: data,
                            backgroundColor: colors,
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: false, // Disable animation to prevent reactive loops
                        plugins: {
                            legend: {
                                display: false // Disable Chart.js legend - we'll create custom HTML legend
                            }
                        }
                    }
                });
            }
            this._flagsUpdating = false;
        } catch (e) {
            console.error('Chart render error:', e);
            this._flagsUpdating = false;
        }
    },

    // --- Controls Logic ---

    async loadNotifyStatus() {
        try {
            const res = await fetch('/api/notify_status');
            if (res.ok) {
                const d = await res.json();
                const now = Date.now() / 1000;
                this.notify = {
                    email: d.email,
                    webhook: d.webhook,
                    muted: d.mute_until && d.mute_until > now
                };
            }
        } catch (e) { console.error(e); }
    },

    async toggleNotify(target) {
        try {
            const currentState = target === 'email' ? this.notify.email : this.notify.webhook;
            const res = await fetch('/api/notify_toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target, state: !currentState })
            });
            if (res.ok) this.loadNotifyStatus();
        } catch (e) { console.error(e); }
    },

    async muteAlerts() {
        try {
            const body = this.notify.muted ? { mute: false } : { mute: true, minutes: 60 };
            const res = await fetch('/api/notify_mute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (res.ok) this.loadNotifyStatus();
        } catch (e) { console.error(e); }
    },

    // ---- Drag & Drop Reordering ----
    setupDragAndDrop() {
        const grids = document.querySelectorAll('.grid[data-reorder="true"][data-grid-id]');
        grids.forEach((grid) => {
            const gridId = grid.getAttribute('data-grid-id');
            // Apply saved order
            this.applyGridOrder(grid, gridId);

            grid.addEventListener('dragover', (e) => {
                e.preventDefault();
                const afterEl = this.getCardAfterPosition(grid, e.clientY);
                const dragging = document.querySelector('.card.dragging');
                if (!dragging) return;
                if (afterEl == null) {
                    grid.appendChild(dragging);
                } else {
                    grid.insertBefore(dragging, afterEl);
                }
            });

            Array.from(grid.children).forEach(card => this.makeCardDraggable(card, gridId));

            const obs = new MutationObserver(() => {
                Array.from(grid.children).forEach(card => this.makeCardDraggable(card, gridId));
            });
            obs.observe(grid, { childList: true });
        });
    },

    makeCardDraggable(card, gridId) {
        if (!(card instanceof HTMLElement) || card.classList.contains('wide-card')) return;
        // set draggable based on current mode
        card.setAttribute('draggable', this.editMode.toString());

        if (!card.dataset.widgetId) card.dataset.widgetId = this.computeWidgetId(card, gridId);
        // Add listeners once (idempotent setup is implied, but listeners are cheap)
        if (!card._dragListenersAttached) {
            card.addEventListener('dragstart', () => {
                if (this.editMode) card.classList.add('dragging');
                else e.preventDefault(); // Should not match here if draggable=false, but just in case
            });
            card.addEventListener('dragend', () => {
                card.classList.remove('dragging');
                const grid = card.closest('.grid[data-grid-id]');
                if (grid) {
                    const gid = grid.getAttribute('data-grid-id');
                    this.saveGridOrder(grid, gid);
                }
            });
            card._dragListenersAttached = true;
        }
    },

    computeWidgetId(card, gridId) {
        let txt = '';
        const h2span = card.querySelector('h2 span');
        if (h2span) txt = h2span.textContent.trim();
        if (!txt) {
            const label = card.querySelector('.label');
            if (label) txt = label.textContent.trim();
        }
        if (!txt) txt = 'card';
        txt = txt.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
        return gridId + ':' + txt;
    },

    saveGridOrder(grid, gridId) {
        const ids = Array.from(grid.children)
            .filter(el => el instanceof HTMLElement && !el.classList.contains('wide-card'))
            .map(el => el.dataset.widgetId || '');
        try { localStorage.setItem('gridOrder:' + gridId, JSON.stringify(ids)); } catch (e) { console.error(e); }
    },

    applyGridOrder(grid, gridId) {
        try {
            const raw = localStorage.getItem('gridOrder:' + gridId);
            if (!raw) return;
            const order = JSON.parse(raw);
            const map = new Map();
            Array.from(grid.children).forEach(el => {
                if (el instanceof HTMLElement) {
                    if (!el.dataset.widgetId) el.dataset.widgetId = this.computeWidgetId(el, gridId);
                    map.set(el.dataset.widgetId, el);
                }
            });
            order.forEach(id => {
                const el = map.get(id);
                if (el) grid.appendChild(el);
            });
        } catch (e) { console.error(e); }
    },

    getCardAfterPosition(grid, y) {
        const cards = [...grid.querySelectorAll('.card[draggable="true"]:not(.dragging)')];
        return cards.reduce((closest, child) => {
            const box = child.getBoundingClientRect();
            const offset = y - box.top - box.height / 2;
            if (offset < 0 && offset > closest.offset) {
                return { offset: offset, element: child };
            } else {
                return closest;
            }
        }, { offset: Number.NEGATIVE_INFINITY }).element;
    },

    async sendTestAlert() {
        fetch('/api/test_alert').then(r => r.json()).then(() => {
            // Trigger refresh immediately to show it
            this.fetchAlerts();
        }).catch(console.error);
    },

    async refreshFeed() {
        fetch('/api/threat_refresh', { method: 'POST' }).then(r => r.json()).then(d => {
            if (d.threat_status) this.threatStatus = d.threat_status;
        }).catch(console.error);
    },

    exportCSV() {
        window.location.href = '/api/export?range=' + this.timeRange;
    },

    exportJSON() {
        window.location.href = '/api/export_json?range=' + this.timeRange;
    },

    exportAlerts(fmt) {
        window.location.href = '/api/alerts_export?format=' + fmt;
    },

    // === FIREWALL INVESTIGATION FUNCTIONS ===

    async investigateIP() {
        if (!this.ipInvestigation.searchIP.trim()) return;

        // Open modal first
        this.ipInvestigationModalOpen = true;

        this.ipInvestigation.loading = true;
        this.ipInvestigation.result = null;
        this.ipInvestigation.error = null;

        try {
            // Add timeout to prevent hanging
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

            const res = await fetch(`/api/ip_detail/${encodeURIComponent(this.ipInvestigation.searchIP)}?range=${this.timeRange}`, {
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            }

            const data = await res.json();

            // Determine classification
            const ip = this.ipInvestigation.searchIP;
            const isInternal = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') || ip.startsWith('172.19.') || ip.startsWith('172.20.') || ip.startsWith('172.21.') || ip.startsWith('172.22.') || ip.startsWith('172.23.') || ip.startsWith('172.24.') || ip.startsWith('172.25.') || ip.startsWith('172.26.') || ip.startsWith('172.27.') || ip.startsWith('172.28.') || ip.startsWith('172.29.') || ip.startsWith('172.30.') || ip.startsWith('172.31.');

            // Check if it's a threat
            const isThreat = this.threats.hits.some(t => t.ip === ip);

            // Calculate total traffic
            const totalBytes = (data.direction?.upload || 0) + (data.direction?.download || 0);

            this.ipInvestigation.result = {
                ...data,
                classification: isInternal ? 'Internal' : 'External',
                is_threat: isThreat,
                total_bytes_fmt: this.fmtBytes(totalBytes),
                flow_count: (data.src_ports?.length || 0) + (data.dst_ports?.length || 0),
                country: data.geo?.country || data.country,
                region: data.region || data.geo?.region,
                asn: data.geo?.asn || data.asn,
                related_ips: data.related_ips || []
            };

            // Load timeline data if available
            this.$nextTick(() => {
                this.loadIPTimeline(ip);
            });
        } catch (err) {
            console.error('IP investigation failed:', err);
            if (err.name === 'AbortError') {
                this.ipInvestigation.error = 'Request timed out. The IP investigation is taking too long. Try a shorter time range.';
            } else {
                this.ipInvestigation.error = err.message || 'Failed to investigate IP. Please try again.';
            }
            this.showToast(this.ipInvestigation.error, 'error');
        } finally {
            this.ipInvestigation.loading = false;
        }
    },

    openIPInvestigationModal(ip = null) {
        if (ip) {
            this.ipInvestigation.searchIP = ip;
        }
        this.ipInvestigationModalOpen = true;
        // If IP is provided, automatically trigger investigation
        if (ip) {
            this.$nextTick(() => {
                this.investigateIP();
            });
        }
    },

    exportInvestigationResults(format) {
        if (!this.ipInvestigation.result) return;

        const data = this.ipInvestigation.result;
        const ip = this.ipInvestigation.searchIP;

        if (format === 'json') {
            const jsonStr = JSON.stringify(data, null, 2);
            const blob = new Blob([jsonStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ip-investigation-${ip}-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            this.showToast('Investigation data exported as JSON', 'success');
        } else if (format === 'csv') {
            // Create CSV with key information
            const lines = [
                'Field,Value',
                `IP Address,${ip}`,
                `Classification,${data.classification || 'N/A'}`,
                `Threat Status,${data.is_threat ? 'THREAT' : 'Clean'}`,
                `Country,${data.country || data.geo?.country || 'N/A'}`,
                `Region,${data.region || data.geo?.region || 'N/A'}`,
                `ASN,${data.asn || data.geo?.asn || 'N/A'}`,
                `Hostname,${data.hostname || 'N/A'}`,
                `Total Traffic,${data.total_bytes_fmt || 'N/A'}`,
                `Total Flows,${data.flow_count || 0}`
            ];
            const csvStr = lines.join('\n');
            const blob = new Blob([csvStr], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ip-investigation-${ip}-${Date.now()}.csv`;
            a.click();
            URL.revokeObjectURL(url);
            this.showToast('Investigation data exported as CSV', 'success');
        }
    },

    copyInvestigationIP() {
        if (!this.ipInvestigation.searchIP) return;
        navigator.clipboard.writeText(this.ipInvestigation.searchIP).then(() => {
            this.showToast('IP address copied to clipboard', 'success');
        }).catch(() => {
            this.showToast('Failed to copy IP address', 'error');
        });
    },

    async loadIPTimeline(ip) {
        if (!ip) return;
        this.ipInvestigation.timeline.loading = true;
        try {
            const compareParam = this.ipInvestigation.timeline.compareHistory ? '&compare=true' : '';
            // Try source timeline first (more common)
            const res = await fetch(`/api/trends/source/${encodeURIComponent(ip)}?range=${this.timeRange}${compareParam}`);
            if (res.ok) {
                const data = await res.json();
                this.ipInvestigation.timeline = {
                    labels: data.labels || [],
                    bytes: data.bytes || [],
                    flows: data.flows || [],
                    comparison: data.comparison || null,
                    loading: false,
                    compareHistory: this.ipInvestigation.timeline.compareHistory
                };
                this.$nextTick(() => {
                    this.renderIPTimelineChart();
                });
            } else {
                // Try destination timeline as fallback
                const resDest = await fetch(`/api/trends/dest/${encodeURIComponent(ip)}?range=${this.timeRange}${compareParam}`);
                if (resDest.ok) {
                    const data = await resDest.json();
                    this.ipInvestigation.timeline = {
                        labels: data.labels || [],
                        bytes: data.bytes || [],
                        flows: data.flows || [],
                        comparison: data.comparison || null,
                        loading: false,
                        compareHistory: this.ipInvestigation.timeline.compareHistory
                    };
                    this.$nextTick(() => {
                        this.renderIPTimelineChart();
                    });
                } else {
                    this.ipInvestigation.timeline.loading = false;
                }
            }
        } catch (err) {
            console.error('IP timeline load error:', err);
            this.ipInvestigation.timeline.loading = false;
        }
    },

    renderIPTimelineChart() {
        try {
            const canvas = document.getElementById('ipInvestigationTimelineChart');
            if (!canvas || !this.ipInvestigation.timeline.labels || this.ipInvestigation.timeline.labels.length === 0) return;

            if (typeof Chart === 'undefined') {
                setTimeout(() => this.renderIPTimelineChart(), 100);
                return;
            }

            const ctx = canvas.getContext('2d');
            if (_chartInstances['_ipInvestigationTimelineChart']) _chartInstances['_ipInvestigationTimelineChart'].destroy();

            const labels = this.ipInvestigation.timeline.labels;
            const bytes = this.ipInvestigation.timeline.bytes;
            const flows = this.ipInvestigation.timeline.flows;
            const comparison = this.ipInvestigation.timeline.comparison;

            const datasets = [
                {
                    label: 'Bytes',
                    data: bytes,
                    borderColor: this.getCssVar('--neon-cyan') || 'rgba(0, 243, 255, 1)',
                    backgroundColor: 'rgba(0, 243, 255, 0.1)',
                    yAxisID: 'y',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Flows',
                    data: flows,
                    borderColor: this.getCssVar('--neon-green') || 'rgba(0, 255, 136, 1)',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    yAxisID: 'y1',
                    tension: 0.3,
                    fill: false
                }
            ];

            // Add comparison data if available
            if (comparison && comparison.bytes) {
                datasets.push({
                    label: 'Bytes (Previous Period)',
                    data: comparison.bytes,
                    borderColor: 'rgba(255, 152, 0, 0.6)',
                    backgroundColor: 'rgba(255, 152, 0, 0.05)',
                    yAxisID: 'y',
                    tension: 0.3,
                    fill: false,
                    borderDash: [5, 5]
                });
                if (comparison.flows) {
                    datasets.push({
                        label: 'Flows (Previous Period)',
                        data: comparison.flows,
                        borderColor: 'rgba(156, 39, 176, 0.6)',
                        backgroundColor: 'rgba(156, 39, 176, 0.05)',
                        yAxisID: 'y1',
                        tension: 0.3,
                        fill: false,
                        borderDash: [5, 5]
                    });
                }
            }

            _chartInstances['_ipInvestigationTimelineChart'] = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: datasets
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                color: this.getCssVar('--text-secondary') || '#888',
                                boxWidth: 12,
                                padding: 8
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(20, 24, 33, 0.95)',
                            titleColor: this.getCssVar('--text-primary') || '#fff',
                            bodyColor: this.getCssVar('--text-secondary') || '#ccc',
                            borderColor: 'rgba(0, 243, 255, 0.3)',
                            borderWidth: 1,
                            callbacks: {
                                label: (context) => {
                                    if (context.datasetIndex === 0) {
                                        return `Bytes: ${this.fmtBytes(context.parsed.y)}`;
                                    } else {
                                        return `Flows: ${context.parsed.y.toLocaleString()}`;
                                    }
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: {
                                color: this.getCssVar('--text-muted') || '#666',
                                maxRotation: 45,
                                minRotation: 45
                            }
                        },
                        y: {
                            type: 'linear',
                            position: 'left',
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: {
                                color: this.getCssVar('--text-muted') || '#666',
                                callback: (value) => this.fmtBytes(value)
                            },
                            title: {
                                display: true,
                                text: 'Bytes',
                                color: this.getCssVar('--text-secondary') || '#888'
                            }
                        },
                        y1: {
                            type: 'linear',
                            position: 'right',
                            grid: { display: false },
                            ticks: {
                                color: 'rgba(0, 255, 136, 0.8)'
                            },
                            title: {
                                display: true,
                                text: 'Flows',
                                color: 'rgba(0, 255, 136, 0.8)'
                            }
                        }
                    },
                    interaction: {
                        mode: 'index',
                        intersect: false
                    }
                }
            });
        } catch (e) {
            console.error('IP timeline chart render error:', e);
        }
    },

    async searchFlows() {
        this.flowSearch.loading = true;
        this.flowSearch.results = [];

        try {
            const params = new URLSearchParams({ range: this.timeRange });
            if (this.flowSearch.filters.srcIP) params.append('src_ip', this.flowSearch.filters.srcIP);
            if (this.flowSearch.filters.dstIP) params.append('dst_ip', this.flowSearch.filters.dstIP);
            if (this.flowSearch.filters.port) params.append('port', this.flowSearch.filters.port);
            if (this.flowSearch.filters.protocol) params.append('protocol', this.flowSearch.filters.protocol);
            if (this.flowSearch.filters.country) params.append('country', this.flowSearch.filters.country);

            const res = await fetch(`/api/forensics/flow-search?${params}`);
            const data = await res.json();

            this.flowSearch.results = (data.flows || []).map(f => ({
                ...f,
                bytes_fmt: this.fmtBytes(f.bytes || 0)
            }));
        } catch (err) {
            console.error('Flow search failed:', err);
            this.flowSearch.results = [];
        } finally {
            this.flowSearch.loading = false;
        }
    },

    exportFlowSearchResults() {
        if (this.flowSearch.results.length === 0) return;

        const csv = [
            ['Source', 'Destination', 'Protocol', 'Port', 'Traffic'].join(','),
            ...this.flowSearch.results.map(f =>
                [f.src, f.dst, f.proto, f.port, f.bytes_fmt].join(',')
            )
        ].join('\n');

        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `flow-search-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    },

    async fetchAlertCorrelation() {
        this.alertCorrelation.loading = true;

        try {
            const res = await fetch(`/api/forensics/alert-correlation?range=${this.timeRange}`);
            const data = await res.json();
            this.alertCorrelation.chains = data.chains || [];
        } catch (err) {
            console.error('Alert correlation fetch failed:', err);
            // Build correlation from alert history as fallback
            const alerts = this.alertHistory.alerts || [];
            const byIP = {};

            alerts.forEach(alert => {
                const ip = alert.ip || alert.source_ip;
                if (!ip) return;
                if (!byIP[ip]) byIP[ip] = [];
                byIP[ip].push(alert);
            });

            this.alertCorrelation.chains = Object.entries(byIP)
                .filter(([ip, alerts]) => alerts.length > 1)
                .map(([ip, alerts]) => ({
                    ip,
                    alerts: alerts.map(a => ({
                        id: a.msg,
                        type: a.type,
                        message: a.msg,
                        time: a.time || a.timestamp
                    })),
                    timespan: alerts.length > 1 ?
                        `${alerts[0].time || 'recent'} - ${alerts[alerts.length - 1].time || 'recent'}` :
                        'recent'
                }));
        } finally {
            this.alertCorrelation.loading = false;
        }
    },

    async fetchThreatActivityTimeline() {
        this.threatActivityTimeline.loading = true;
        try {
            // Use global time range for consistency
            const res = await fetch(`/api/security/attack-timeline?range=${this.timeRange}`);
            if (res.ok) {
                const d = await res.json();
                // Calculate peak hour
                let peak_count = 0;
                let peak_hour = null;
                if (d.timeline && d.timeline.length > 0) {
                    const peak = d.timeline.reduce((max, item) => {
                        const total = item.total || 0;
                        return total > max.total ? { hour: item.hour, total: total } : max;
                    }, { hour: null, total: 0 });
                    peak_count = peak.total;
                    peak_hour = peak.hour;
                }

                this.threatActivityTimeline = {
                    ...d,
                    peak_count,
                    peak_hour,
                    loading: false
                };
                this.$nextTick(() => {
                    this.renderThreatActivityTimelineChart();
                });
            }
        } catch (e) {
            console.error('Threat activity timeline fetch error:', e);
        } finally {
            this.threatActivityTimeline.loading = false;
        }
    },

    renderThreatActivityTimelineChart() {
        try {
            const canvas = document.getElementById('threatActivityTimelineChart');
            if (!canvas || !this.threatActivityTimeline.timeline) return;

            // Check if canvas is actually in the DOM and has dimensions
            if (!canvas.getContext) {
                console.warn('Threat Activity Timeline chart canvas not ready');
                return;
            }

            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                setTimeout(() => this.renderThreatActivityTimelineChart(), 100);
                return;
            }

            const ctx = canvas.getContext('2d');
            if (!ctx) {
                console.warn('Threat Activity Timeline chart: could not get 2d context');
                return;
            }

            if (_chartInstances['_threatActivityTimelineChart']) {
                try {
                    _chartInstances['_threatActivityTimelineChart'].destroy();
                } catch (e) {
                    console.warn('Error destroying threat activity timeline chart:', e);
                }
            }

            const labels = this.threatActivityTimeline.timeline.map(t => t.hour);
            const critical = this.threatActivityTimeline.timeline.map(t => t.critical || 0);
            const high = this.threatActivityTimeline.timeline.map(t => t.high || 0);
            const medium = this.threatActivityTimeline.timeline.map(t => t.medium || 0);
            const low = this.threatActivityTimeline.timeline.map(t => t.low || 0);
            const fwBlocks = this.threatActivityTimeline.timeline.map(t => t.fw_blocks || 0);

            const critColor = this.getCssVar('--neon-red') || 'rgba(255, 0, 60, 0.8)';
            const hasFwData = this.threatActivityTimeline.has_fw_data;

            const datasets = [
                { label: 'Critical', data: critical, backgroundColor: critColor, stack: 'severity', order: 2 },
                { label: 'High', data: high, backgroundColor: 'rgba(255, 165, 0, 0.8)', stack: 'severity', order: 2 },
                { label: 'Medium', data: medium, backgroundColor: 'rgba(255, 255, 0, 0.7)', stack: 'severity', order: 2 },
                { label: 'Low', data: low, backgroundColor: 'rgba(0, 255, 255, 0.5)', stack: 'severity', order: 2 }
            ];

            // Add firewall blocks as a line overlay if data exists
            if (hasFwData) {
                datasets.push({
                    label: '🔥 FW Blocks',
                    data: fwBlocks,
                    type: 'line',
                    borderColor: 'rgba(0, 255, 100, 1)',
                    backgroundColor: 'rgba(0, 255, 100, 0.1)',
                    borderWidth: 2,
                    pointRadius: 3,
                    pointBackgroundColor: 'rgba(0, 255, 100, 1)',
                    fill: false,
                    tension: 0.3,
                    yAxisID: 'y1',
                    order: 1
                });
            }

            _chartInstances['_threatActivityTimelineChart'] = new Chart(ctx, {
                type: 'bar',
                data: { labels, datasets },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                color: this.getCssVar('--text-secondary') || '#888',
                                boxWidth: 12,
                                padding: 8
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: 'rgba(20, 24, 33, 0.95)',
                            titleColor: this.getCssVar('--text-primary') || '#fff',
                            bodyColor: this.getCssVar('--text-secondary') || '#ccc',
                            borderColor: 'rgba(0, 243, 255, 0.3)',
                            borderWidth: 1
                        }
                    },
                    scales: {
                        x: {
                            stacked: true,
                            grid: { display: false },
                            ticks: {
                                color: this.getCssVar('--text-muted') || '#666',
                                maxRotation: 45,
                                minRotation: 45
                            }
                        },
                        y: {
                            stacked: true,
                            grid: { color: 'rgba(255,255,255,0.05)' },
                            ticks: { color: this.getCssVar('--text-muted') || '#666' },
                            position: 'left',
                            title: {
                                display: true,
                                text: 'Threats',
                                color: this.getCssVar('--text-secondary') || '#888'
                            }
                        },
                        ...(hasFwData ? {
                            y1: {
                                grid: { display: false },
                                ticks: { color: 'rgba(0, 255, 100, 0.8)' },
                                position: 'right',
                                title: {
                                    display: true,
                                    text: 'FW Blocks',
                                    color: 'rgba(0, 255, 100, 0.8)'
                                }
                            }
                        } : {})
                    },
                    interaction: {
                        mode: 'index',
                        intersect: false
                    }
                }
            });
        } catch (e) {
            console.error('Threat activity timeline chart render error:', e);
        }
    },

    exportThreatActivityTimeline(format) {
        if (!this.threatActivityTimeline.timeline || this.threatActivityTimeline.timeline.length === 0) {
            this.showToast('No timeline data to export', 'warning');
            return;
        }

        const timeline = this.threatActivityTimeline.timeline;

        if (format === 'csv') {
            const lines = [
                'Hour,Total Threats,Critical,High,Medium,Low,Firewall Blocks'
            ];
            timeline.forEach(item => {
                lines.push([
                    item.hour,
                    item.total || 0,
                    item.critical || 0,
                    item.high || 0,
                    item.medium || 0,
                    item.low || 0,
                    item.fw_blocks || 0
                ].join(','));
            });

            const csvStr = lines.join('\n');
            const blob = new Blob([csvStr], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threat-activity-timeline-${Date.now()}.csv`;
            a.click();
            URL.revokeObjectURL(url);
            this.showToast('Timeline data exported as CSV', 'success');
        } else if (format === 'json') {
            const jsonStr = JSON.stringify({
                timeRange: this.timeRange,
                total_24h: this.threatActivityTimeline.total_24h,
                peak_hour: this.threatActivityTimeline.peak_hour,
                peak_count: this.threatActivityTimeline.peak_count,
                timeline: timeline
            }, null, 2);
            const blob = new Blob([jsonStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threat-activity-timeline-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            this.showToast('Timeline data exported as JSON', 'success');
        }
    },

    // Helpers - Using DashboardUtils module
    fmtBytes(bytes) {
        return DashboardUtils.fmtBytes(bytes);
    },

    // Expose fmtBytes to templates
    get fmtBytes() {
        return DashboardUtils.fmtBytes;
    },

    computeRecentBlockStats(logs = []) {
        return DashboardUtils.computeRecentBlockStats(logs);
    },

    setRecentBlocksView(count) {
        const safeCount = Math.max(10, count || 10);
        const maxAvailable = this.recentBlocks?.blocks?.length || safeCount;
        this.recentBlocksView = Math.min(safeCount, Math.min(1000, maxAvailable));
    },

    startRecentBlocksAutoRefresh() {
        // Clear existing timer if any
        if (this.recentBlocksRefreshTimer) {
            clearInterval(this.recentBlocksRefreshTimer);
            this.recentBlocksRefreshTimer = null;
        }

        // Only start if auto-refresh is enabled
        if (!this.recentBlocksAutoRefresh) return;

        // Initial fetch
        this.fetchRecentBlocks();

        // Set up interval: refresh every 3 seconds for real-time feel
        const refreshInterval = 3000;
        this.recentBlocksRefreshTimer = setInterval(() => {
            if (this.recentBlocksAutoRefresh && this.activeTab === 'forensics') {
                this.fetchRecentBlocksIncremental();
            }
        }, refreshInterval);
    },

    toggleRecentBlocksAutoRefresh() {
        if (this.recentBlocksAutoRefresh) {
            this.startRecentBlocksAutoRefresh();
        } else {
            if (this.recentBlocksRefreshTimer) {
                clearInterval(this.recentBlocksRefreshTimer);
                this.recentBlocksRefreshTimer = null;
            }
        }
    },

    async fetchRecentBlocksIncremental() {
        // Incremental update: only fetch if we're on the forensics tab and widget is visible
        if (this.activeTab !== 'forensics' || this.isMinimized('recentBlocks')) {
            return;
        }

        // Prevent concurrent requests
        if (this._recentBlocksFetching) return;
        this._recentBlocksFetching = true;

        // Use regular fetch for now (backend supports since parameter but we'll use full refresh for simplicity)
        // This ensures we always have the latest data
        try {
            const res = await fetch('/api/firewall/logs/recent?limit=1000');

            if (res.ok) {
                const d = await res.json();
                const newLogs = d.logs || [];
                const stats = d.stats || this.computeRecentBlockStats(newLogs);

                // Check if we have new data by comparing latest timestamp
                const currentLatestTs = this.recentBlocks?.stats?.latest_ts || 0;
                const newLatestTs = stats?.latest_ts || 0;

                // Only update if we have newer data
                if (newLatestTs > currentLatestTs || newLogs.length !== (this.recentBlocks?.blocks?.length || 0)) {
                    this.recentBlocks = {
                        blocks: newLogs,
                        stats,
                        total_1h: stats?.blocks_last_hour || stats?.actions?.block || newLogs.length || 0,
                        loading: false,
                        lastUpdate: new Date().toISOString()
                    };

                    // Update view count if needed
                    const targetView = this.recentBlocksView || 50;
                    this.recentBlocksView = Math.min(targetView, newLogs.length || targetView, 1000);
                }
            } else if (res.status === 429) {
                // Rate limited - back off by stopping auto-refresh temporarily
                console.warn('Rate limited on firewall logs, pausing auto-refresh');
                this.recentBlocksAutoRefresh = false;
                if (this.recentBlocksRefreshTimer) {
                    clearInterval(this.recentBlocksRefreshTimer);
                    this.recentBlocksRefreshTimer = null;
                }
            }
        } catch (e) {
            console.error('Incremental recent blocks fetch error:', e);
        } finally {
            this._recentBlocksFetching = false;
        }
    },

    startFirewallSyslogAutoRefresh() {
        // Clear existing timer if any
        if (this.firewallSyslogRefreshTimer) {
            clearInterval(this.firewallSyslogRefreshTimer);
            this.firewallSyslogRefreshTimer = null;
        }

        // Only start if auto-refresh is enabled
        if (!this.firewallSyslogAutoRefresh) return;

        // Initial fetch
        this.fetchFirewallSyslog();

        // Set up interval: refresh every 3 seconds for real-time feel
        const refreshInterval = 3000;
        this.firewallSyslogRefreshTimer = setInterval(() => {
            if (this.firewallSyslogAutoRefresh && this.activeTab === 'firewall') {
                this.fetchFirewallSyslogIncremental();
            }
        }, refreshInterval);
    },

    toggleFirewallSyslogAutoRefresh() {
        if (this.firewallSyslogAutoRefresh) {
            this.startFirewallSyslogAutoRefresh();
        } else {
            if (this.firewallSyslogRefreshTimer) {
                clearInterval(this.firewallSyslogRefreshTimer);
                this.firewallSyslogRefreshTimer = null;
            }
        }
    },

    async fetchFirewallSyslogIncremental() {
        // Incremental update: only fetch if we're on the firewall tab and widget is visible
        if (this.activeTab !== 'firewall' || this.isMinimized('firewallSyslog')) {
            return;
        }

        // Prevent concurrent requests
        if (this._firewallSyslogFetching) return;
        this._firewallSyslogFetching = true;

        // Use regular fetch for now (backend supports since parameter but we'll use full refresh for simplicity)
        // This ensures we always have the latest data
        try {
            const res = await fetch('/api/firewall/syslog/recent?limit=1000');

            if (res.ok) {
                const d = await res.json();
                const newLogs = d.logs || [];
                const stats = d.stats || this.computeRecentBlockStats(newLogs);

                this.firewallSyslog = {
                    blocks: newLogs,
                    stats,
                    total_1h: stats?.blocks_last_hour || stats?.actions?.block || newLogs.length || 0,
                    loading: false,
                    lastUpdate: new Date().toISOString()
                };

                // Update view count if needed
                const targetView = this.firewallSyslogView || 50;
                this.firewallSyslogView = Math.min(targetView, newLogs.length || targetView, 1000);
            } else if (res.status === 429) {
                // Rate limited - back off by stopping auto-refresh temporarily
                console.warn('Rate limited on firewall syslog, pausing auto-refresh');
                this.firewallSyslogAutoRefresh = false;
                if (this.firewallSyslogRefreshTimer) {
                    clearInterval(this.firewallSyslogRefreshTimer);
                    this.firewallSyslogRefreshTimer = null;
                }
            }
        } catch (e) {
            console.error('Incremental firewall syslog fetch error:', e);
        } finally {
            this._firewallSyslogFetching = false;
        }
    },

    timeAgo(ts) {
        return DashboardUtils.timeAgo(ts);
    },

    flagFromIso(iso) {
        return DashboardUtils.flagFromIso(iso);
    },

    // Compact Mode
    loadCompactMode() {
        const saved = localStorage.getItem('compactMode');
        this.compactMode = saved === '1';
        if (this.compactMode) {
            document.body.classList.add('compact-mode');
        }
    },

    toggleCompactMode() {
        this.compactMode = !this.compactMode;
    },

    // Sidebar Collapse
    loadSidebarState() {
        const saved = localStorage.getItem('sidebarCollapsed');
        // Default to collapsed (true) if no saved preference
        this.sidebarCollapsed = saved !== null ? saved === '1' : true;
        if (this.sidebarCollapsed) {
            document.body.classList.add('sidebar-collapsed');
        }
    },

    toggleSidebar() {
        this.sidebarCollapsed = !this.sidebarCollapsed;
    },

    toggleSidebarMobile() {
        this.sidebarCollapsed = !this.sidebarCollapsed;
        // Add/remove backdrop on mobile
        if (window.innerWidth <= 768) {
            if (this.sidebarCollapsed) {
                document.body.classList.remove('sidebar-open');
            } else {
                document.body.classList.add('sidebar-open');
            }
        }
    },

    // Widget Management Methods - Using DashboardWidgets module
    loadWidgetPreferences() {
        DashboardWidgets.loadPreferences(this);
    },

    saveWidgetPreferences() {
        DashboardWidgets.savePreferences(this);
    },

    toggleWidget(widgetId) {
        DashboardWidgets.toggleWidget(this, widgetId);
    },

    toggleMinimize(widgetId) {
        DashboardWidgets.toggleMinimize(this, widgetId);
    },

    isMinimized(widgetId) {
        return DashboardWidgets.isMinimized(this, widgetId);
    },

    isVisible(widgetId) {
        return DashboardWidgets.isVisible(this, widgetId);
    },

    getWidgetLabel(widgetId) {
        return DashboardWidgets.getWidgetLabel(this, widgetId);
    },

    resetWidgetPreferences() {
        DashboardWidgets.resetPreferences(this);
    },

    async openIPModal(ip) {
        this.selectedIP = ip;
        this.modalOpen = true;
        this.ipLoading = true;
        // Initialize ipDetails with timeline structure to prevent null reference errors
        this.ipDetails = { timeline: { labels: [], bytes: [], flows: [], loading: true } };
        try {
            // Add timeout to prevent hanging on slow/unresponsive endpoints
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout

            const res = await fetch(`/api/ip_detail/${ip}`, { signal: controller.signal });
            clearTimeout(timeoutId);

            if (res.ok) {
                const data = await res.json();
                this.ipDetails = { ...data, timeline: this.ipDetails.timeline };
            } else {
                this.ipDetails = { error: `Server error: ${res.status}`, timeline: { labels: [], bytes: [], flows: [], loading: false } };
            }
        } catch (e) {
            console.error(e);
            if (e.name === 'AbortError') {
                this.ipDetails = { error: 'Request timed out - IP detail unavailable', timeline: { labels: [], bytes: [], flows: [], loading: false } };
            } else {
                this.ipDetails = { error: 'Failed to load details', timeline: { labels: [], bytes: [], flows: [], loading: false } };
            }
        }
        this.ipLoading = false;
    },

    applyFilter(ip) {
        this.openIPModal(ip);
    },

    // Navigation helpers for Overview stat box click-throughs
    navigateToActiveAlerts() {
        this.loadTab('security');
    },

    openAlerts() {
        // Navigate to Security tab and ensure alert history is loaded
        this.loadTab('security');
        // Ensure alert history is fetched if not already loaded
        if (this.alertHistory.loading || !this.alertHistory.alerts || this.alertHistory.alerts.length === 0) {
            this.fetchAlertHistory();
        }
        // Scroll to alert history section after a brief delay to allow tab to render
        this.$nextTick(() => {
            setTimeout(() => {
                const alertSection = document.getElementById('section-security');
                if (alertSection) {
                    // Try to find alert history widget by searching for the title
                    const headings = alertSection.querySelectorAll('h2');
                    let alertWidget = null;
                    for (const h2 of headings) {
                        if (h2.textContent && h2.textContent.includes('Alert History')) {
                            alertWidget = h2.closest('.card');
                            break;
                        }
                    }
                    if (alertWidget) {
                        alertWidget.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    } else {
                        // Fallback: scroll to security section
                        alertSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }
                }
            }, 300);
        });
    },

    navigateToActiveFlows() {
        this.loadTab('network');
        this.$nextTick(() => {
            if (this.flows) {
                this.flows.viewLimit = 15;
            }
            this.fetchFlows();
        });
    },

    navigateToExternalConnections() {
        this.loadTab('network');
        this.$nextTick(() => {
            if (this.flows) {
                this.flows.viewLimit = 15;
            }
            this.fetchFlows();
            // Note: External connections filtering would be done in the flows table UI
            // The flows endpoint already includes direction information
        });
    },

    navigateToFirewallLogs() {
        this.loadTab('forensics');
        // Firewall logs are already loaded when forensics tab opens
    },

    navigateToAnomalies() {
        this.loadTab('network');
        // Anomalies are shown in the Active Flows table with detection indicators
        this.$nextTick(() => {
            if (this.flows) {
                this.flows.viewLimit = 15;
            }
            this.fetchFlows();
        });
    },

    loadTab(tab) {
        this.activeTab = tab;
        const now = Date.now();

        // Load tab-specific data
        if (tab === 'firewall-snmp') {
            this.fetchFirewallSNMP();
            // Set up refresh interval (10-30s TTL as per requirements)
            if (this.firewallSNMPRefreshTimer) {
                clearInterval(this.firewallSNMPRefreshTimer);
            }
            this.firewallSNMPRefreshTimer = setInterval(() => {
                if (this.activeTab === 'firewall-snmp' && !this.paused) {
                    this.fetchFirewallSNMP();
                } else {
                    if (this.firewallSNMPRefreshTimer) {
                        clearInterval(this.firewallSNMPRefreshTimer);
                        this.firewallSNMPRefreshTimer = null;
                    }
                }
            }, 10000); // 10 second refresh
        }
        if (tab === 'overview') {
            if (now - this.lastFetch.worldmap > this.heavyTTL) {
                this.fetchWorldMap();
                this.lastFetch.worldmap = now;
            }
            // Fetch data needed for Overview stat boxes
            this.fetchNetworkStatsOverview();
            this.fetchFirewallStatsOverview();
            this.fetchNetHealth();
            this.fetchSecurityObservability();
            this.fetchAlertHistory();
            this.fetchBaselineSignals();
            // Map initialization is handled by IntersectionObserver when section becomes visible
            // Just fetch data here if needed
        } else if (tab === 'server') {
            this.startServerHealthAutoRefresh();
        } else if (tab === 'security') {
            if (now - this.lastFetch.security > this.heavyTTL) {
                this.fetchSecurityObservability();
                this.fetchAlertHistory();
                this.fetchThreatsByCountry();
                this.fetchThreatVelocity();
                this.fetchTopThreatIPs();
                // Removed: this.fetchRiskIndex(); // Replaced with predictiveRisk in securityObservability
                this.fetchMitreHeatmap();
                this.fetchProtocolAnomalies();
                this.fetchFeedHealth();
                this.fetchWatchlist();
                this.fetchMaliciousPorts();
                this.fetchThreatActivityTimeline();
                this.lastFetch.security = now;
            }
        } else if (tab === 'network') {
            if (now - this.lastFetch.network > this.heavyTTL) {
                this.fetchFlags();
                this.fetchDurations();
                this.fetchPacketSizes();
                this.fetchProtocols();
                this.fetchFlowStats();
                this.fetchProtoMix();
                this.fetchNetworkStatsOverview();
                this.fetchNetHealth();
                this.fetchASNs();
                this.fetchCountries();
                this.fetchTalkers();
                this.fetchServices();
                this.fetchHourlyTraffic();
                this.lastFetch.network = now;
            }
            // Re-render charts when network tab becomes visible
            this.$nextTick(() => {
                setTimeout(() => {
                    if (this.countries && this.countries.labels) this.updateCountriesChart(this.countries);
                    if (this.protoMix && this.protoMix.labels) this.updateProtoMixChart(this.protoMix);
                    if (this.hourlyTraffic && this.hourlyTraffic.labels) this.updateHourlyChart(this.hourlyTraffic);
                    if (this.packetSizes && this.packetSizes.labels) this.updatePktSizeChart(this.packetSizes);
                }, 200);
            });

        } else if (tab === 'hosts') {
            this.fetchHosts();
        } else if (tab === 'forensics') {
            if (now - this.lastFetch.flows > this.mediumTTL) {
                this.fetchFlows();
                this.lastFetch.flows = now;
            }
            this.fetchFirewallStatsOverview();
            this.fetchRecentBlocks();
            this.fetchAlertCorrelation();
            // Start auto-refresh for firewall logs
            this.startRecentBlocksAutoRefresh();
        } else if (tab === 'firewall') {
            this.fetchFirewallStatsOverview();
            this.fetchRecentBlocks();
            this.fetchFirewallSyslog();
            this.fetchAlertCorrelation();
            // Start auto-refresh for firewall logs
            this.startRecentBlocksAutoRefresh();
            this.startFirewallSyslogAutoRefresh();
        } else if (tab === 'assistant') {
            // Load available models when assistant tab is opened
            this.fetchOllamaModels();
        }
    },

    // ----- Ollama Chat Methods -----
    async fetchOllamaModels() {
        try {
            const res = await fetch('/api/ollama/models');
            if (res.ok) {
                const data = await res.json();
                const models = data.models || [];
                // Ensure default model is in the list if no models returned
                if (models.length === 0) {
                    this.ollamaChat.availableModels = ['deepseek-coder-v2:16b'];
                } else {
                    // Ensure default model is included if not already present
                    const defaultModel = 'deepseek-coder-v2:16b';
                    if (!models.includes(defaultModel)) {
                        this.ollamaChat.availableModels = [defaultModel, ...models];
                    } else {
                        this.ollamaChat.availableModels = models;
                    }
                }
            }
        } catch (e) {
            console.error('Failed to fetch Ollama models:', e);
            // Fallback to default model if fetch fails
            this.ollamaChat.availableModels = ['deepseek-coder-v2:16b'];
        }
    },

    getDashboardContext() {
        // Gather current dashboard data for context
        const context = {
            timestamp: new Date().toISOString(),
            timeRange: this.timeRange,
            security: {
                score: this.securityScore?.score || 0,
                grade: this.securityScore?.grade || 'N/A',
                status: this.securityScore?.status || 'unknown',
                threats: this.threats?.hits?.length || 0,
                threatsBlocked: this.securityScore?.fw_threats_blocked || 0,
                alerts: this.alertHistory?.alerts?.length || 0,
                // Enhanced threat analysis data
                recentAlerts: (this.alertHistory?.alerts?.slice(0, 5) || []).map(alert => ({
                    type: alert.type,
                    severity: alert.severity,
                    ip: alert.ip || alert.source_ip,
                    timestamp: alert.timestamp,
                    message: alert.message
                })),
                threatHits: (this.threats?.hits?.slice(0, 10) || []).map(hit => ({
                    ip: hit.ip,
                    category: hit.category,
                    feeds: hit.feeds,
                    firstSeen: hit.first_seen,
                    lastSeen: hit.last_seen
                }))
            },
            network: {
                totalFlows: this.summary?.total_flows || 0,
                totalBytes: this.summary?.total_bytes_fmt || this.summary?.total_bytes || 0,
                totalPackets: this.summary?.total_packets || 0,
                topSources: (this.sources?.sources?.slice(0, 5) || []).map(s => ({
                    ip: s.key,
                    bytes: s.bytes_fmt || s.bytes,
                    flows: s.flows
                })),
                topDestinations: (this.destinations?.destinations?.slice(0, 5) || []).map(d => ({
                    ip: d.key,
                    bytes: d.bytes_fmt || d.bytes,
                    flows: d.flows
                })),
                // Network health indicators
                healthIndicators: this.netHealth?.indicators || [],
                healthScore: this.netHealth?.health_score || 100,
                firewallActive: this.netHealth?.firewall_active || false
            },
            firewall: {
                cpu: this.firewall?.cpu_percent || null,
                memory: this.firewall?.mem_percent || null,
                uptime: this.firewall?.sys_uptime || null,
                blocksLastHour: this.firewall?.blocks_1h || 0,
                syslogActive: this.firewall?.syslog_active || false,
                // Enhanced firewall metrics
                interfaceStatus: this.firewallSNMP?.interfaces || {},
                errorRates: this.firewallSNMP?.error_rates || {}
            },
            // Add forensics data
            forensics: {
                recentFlows: this.flows?.flows?.slice(0, 20) || [],
                topTalkers: this.talkers?.talkers?.slice(0, 10) || [],
                protocols: this.protocols?.protocols?.slice(0, 10) || []
            }
        };
        return context;
    },

    formatDashboardContext(context) {
        // Format context as a readable string for the LLM
        let contextText = `## Current Dashboard Data (as of ${new Date(context.timestamp).toLocaleString()})\n\n`;
        contextText += `Time Range: ${context.timeRange}\n\n`;

        contextText += `### Security Metrics\n`;
        contextText += `- Security Score: ${context.security.score}/100 (Grade: ${context.security.grade}, Status: ${context.security.status})\n`;
        contextText += `- Active Threats Detected: ${context.security.threats}\n`;
        if (context.security.threatsBlocked > 0) {
            contextText += `- Threats Blocked by Firewall: ${context.security.threatsBlocked}\n`;
        }
        if (context.security.alerts > 0) {
            contextText += `- Recent Alerts: ${context.security.alerts}\n`;
        }

        // Enhanced threat analysis section
        if (context.security.recentAlerts.length > 0) {
            contextText += `\n### Recent Security Alerts (Last 5)\n`;
            context.security.recentAlerts.forEach(alert => {
                contextText += `- ${alert.type} (${alert.severity}): ${alert.message} [IP: ${alert.ip}]\n`;
            });
        }

        if (context.security.threatHits.length > 0) {
            contextText += `\n### Current Threat Intelligence Hits\n`;
            context.security.threatHits.forEach(hit => {
                contextText += `- ${hit.ip}: ${hit.category} (Sources: ${hit.feeds?.join(', ') || 'Unknown'})\n`;
            });
        }

        contextText += `\n### Network Statistics\n`;
        if (context.network.totalFlows > 0) {
            contextText += `- Total Flows: ${context.network.totalFlows.toLocaleString()}\n`;
        }
        if (context.network.totalBytes) {
            contextText += `- Total Traffic: ${context.network.totalBytes}\n`;
        }
        if (context.network.totalPackets > 0) {
            contextText += `- Total Packets: ${context.network.totalPackets.toLocaleString()}\n`;
        }
        if (context.network.topSources.length > 0) {
            contextText += `- Top Sources: ${context.network.topSources.map(s => `${s.ip} (${s.bytes}, ${s.flows} flows)`).join(', ')}\n`;
        }
        if (context.network.topDestinations.length > 0) {
            contextText += `- Top Destinations: ${context.network.topDestinations.map(d => `${d.ip} (${d.bytes}, ${d.flows} flows)`).join(', ')}\n`;
        }

        // Network health indicators
        if (context.network.healthIndicators.length > 0) {
            contextText += `\n### Network Health Indicators\n`;
            context.network.healthIndicators.forEach(indicator => {
                contextText += `- ${indicator.name}: ${indicator.value} (${indicator.status}) ${indicator.icon}\n`;
            });
        }

        contextText += `\n### Firewall Status\n`;
        if (context.firewall.cpu !== null) {
            contextText += `- CPU Usage: ${context.firewall.cpu}%\n`;
        }
        if (context.firewall.memory !== null) {
            contextText += `- Memory Usage: ${context.firewall.memory}%\n`;
        }
        contextText += `- Blocks Last Hour: ${context.firewall.blocksLastHour}\n`;
        contextText += `- Syslog Active: ${context.firewall.syslogActive ? 'Yes' : 'No'}\n`;

        // Forensics data
        if (context.forensics.recentFlows.length > 0) {
            contextText += `\n### Recent Flow Activity (Sample)\n`;
            context.forensics.recentFlows.slice(0, 5).forEach(flow => {
                contextText += `- ${flow.src_ip}:${flow.src_port} → ${flow.dst_ip}:${flow.dst_port} (${flow.proto}) - ${flow.bytes_fmt}\n`;
            });
        }

        if (context.forensics.topTalkers.length > 0) {
            contextText += `\n### Top Talkers\n`;
            context.forensics.topTalkers.slice(0, 5).forEach(talker => {
                contextText += `- ${talker.ip}: ${talker.bytes_fmt} (${talker.flows} flows)\n`;
            });
        }

        return contextText;
    },

    async sendChatMessage() {
        const message = this.ollamaChat.inputMessage.trim();
        if (!message || this.ollamaChat.loading) return;

        // Add user message to chat
        this.ollamaChat.messages.push({
            role: 'user',
            content: message,
            timestamp: new Date().toLocaleTimeString()
        });

        // Clear input
        this.ollamaChat.inputMessage = '';
        this.ollamaChat.loading = true;
        this.ollamaChat.error = null;

        try {
            let response;

            // Use specialized threat analysis endpoint for non-general analysis types
            if (this.ollamaChat.analysisType !== 'general' && this.ollamaChat.includeContext) {
                const res = await fetch('/api/ollama/threat-analysis', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        query: message,
                        type: this.ollamaChat.analysisType,
                        model: this.ollamaChat.model
                    })
                });

                if (!res.ok) {
                    const errorData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
                    throw new Error(errorData.error || `Request failed: ${res.status}`);
                }

                response = await res.json();
            } else {
                // Use regular chat endpoint
                let messageToSend = message;

                // Optionally include dashboard context
                if (this.ollamaChat.includeContext) {
                    const context = this.getDashboardContext();
                    const contextText = this.formatDashboardContext(context);

                    // Create enhanced message with context
                    const systemPrompt = `You are an AI assistant for a network security and traffic monitoring dashboard. You have access to real-time network data, security metrics, threat intelligence, and firewall statistics. Use the following dashboard context to answer questions accurately.\n\n${contextText}\n\nWhen answering questions, reference specific metrics when relevant. Be concise but informative.`;

                    messageToSend = `${systemPrompt}\n\nUser Question: ${message}`;
                }

                const res = await fetch('/api/ollama/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        message: messageToSend,
                        model: this.ollamaChat.model,
                        stream: false
                    })
                });

                if (!res.ok) {
                    const errorData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
                    throw new Error(errorData.error || `Request failed: ${res.status}`);
                }

                response = await res.json();
            }

            // Extract response content
            let responseText = '';
            if (response.message && response.message.content) {
                responseText = response.message.content;
            } else if (response.content) {
                responseText = response.content;
            } else {
                responseText = JSON.stringify(response);
            }

            // Add assistant response to chat
            this.ollamaChat.messages.push({
                role: 'assistant',
                content: responseText,
                timestamp: new Date().toLocaleTimeString()
            });

        } catch (e) {
            console.error('Chat error:', e);
            this.ollamaChat.error = e.message || 'Failed to get response from Ollama';
            this.ollamaChat.messages.push({
                role: 'assistant',
                content: `Error: ${this.ollamaChat.error}`,
                timestamp: new Date().toLocaleTimeString()
            });
        } finally {
            this.ollamaChat.loading = false;
            // Scroll to bottom of chat
            this.$nextTick(() => {
                const chatMessages = document.querySelector('.chat-messages');
                if (chatMessages) {
                    chatMessages.scrollTop = chatMessages.scrollHeight;
                }
            });
        }
    },

    clearChat() {
        this.ollamaChat.messages = [];
        this.ollamaChat.error = null;
    },

    // ----- Forensics Methods -----
    async generateTimeline() {
        const { targetIp, timeRange } = this.forensics.timeline;
        if (!targetIp) {
            this.forensics.timeline.error = 'Target IP is required';
            return;
        }

        this.forensics.timeline.loading = true;
        this.forensics.timeline.error = null;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn('/api/forensics/timeline', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_ip: targetIp,
                    time_range: timeRange,
                    include_context: true
                })
            });

            if (res.ok) {
                const data = await res.json();
                this.forensics.timeline.data = data;
            } else {
                const errorData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
                throw new Error(errorData.error || `Request failed: ${res.status}`);
            }
        } catch (e) {
            console.error('Timeline generation error:', e);
            this.forensics.timeline.error = e.message || 'Failed to generate timeline';
        } finally {
            this.forensics.timeline.loading = false;
        }
    },

    async reconstructSession() {
        const { srcIp, dstIp, timeRange } = this.forensics.session;
        if (!srcIp || !dstIp) {
            this.forensics.session.error = 'Both source and destination IPs are required';
            return;
        }

        this.forensics.session.loading = true;
        this.forensics.session.error = null;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn('/api/forensics/session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    src_ip: srcIp,
                    dst_ip: dstIp,
                    time_range: timeRange
                })
            });

            if (res.ok) {
                const data = await res.json();
                this.forensics.session.data = data;
            } else {
                const errorData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
                throw new Error(errorData.error || `Request failed: ${res.status}`);
            }
        } catch (e) {
            console.error('Session reconstruction error:', e);
            this.forensics.session.error = e.message || 'Failed to reconstruct session';
        } finally {
            this.forensics.session.loading = false;
        }
    },

    async collectEvidence() {
        const { incidentType, targetIps, timeRange, preserveData } = this.forensics.evidence;
        if (!targetIps.length) {
            this.forensics.evidence.error = 'Target IPs are required for evidence collection';
            return;
        }

        this.forensics.evidence.loading = true;
        this.forensics.evidence.error = null;

        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn('/api/forensics/evidence', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    incident_type: incidentType,
                    target_ips: targetIps,
                    time_range: timeRange,
                    preserve_data: preserveData
                })
            });

            if (res.ok) {
                const data = await res.json();
                this.forensics.evidence.report = data;
            } else {
                const errorData = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
                throw new Error(errorData.error || `Request failed: ${res.status}`);
            }
        } catch (e) {
            console.error('Evidence collection error:', e);
            this.forensics.evidence.error = e.message || 'Failed to collect evidence';
        } finally {
            this.forensics.evidence.loading = false;
        }
    },

    clearForensicsData() {
        this.forensics.timeline.data = null;
        this.forensics.timeline.error = null;
        this.forensics.session.data = null;
        this.forensics.session.error = null;
        this.forensics.evidence.report = null;
        this.forensics.evidence.error = null;
    },

    // ----- Expanded Views & Graph -----

    async openExpandedTable(type) {
        this.expandedModalOpen = true;
        this.expandedLoading = true;
        this.expandedData = [];

        const titles = {
            'sources': 'Top 100 Sources',
            'destinations': 'Top 100 Destinations',
            'ports': 'Top 100 Ports',
            'conversations': 'Active Flows (Top 100)',
            'flows': 'Active Flows (Top 100)',
            'countries': 'Top Countries by Traffic'
        };
        this.expandedTitle = titles[type] || 'Expanded Data';

        try {
            let url = '';
            let processRow = null;

            if (type === 'sources') {
                url = `/api/stats/sources?range=${this.timeRange}&limit=100`;
                this.expandedColumns = ['IP', 'Hostname', 'Region', 'Flows', 'Bytes'];
                processRow = (row) => [
                    `<span class="text-cyan clickable" onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${row.key}')">${row.key}</span>`,
                    row.hostname || '-',
                    row.region || '-',
                    row.flows.toLocaleString(),
                    row.bytes_fmt
                ];
            } else if (type === 'destinations') {
                url = `/api/stats/destinations?range=${this.timeRange}&limit=100`;
                this.expandedColumns = ['IP', 'Hostname', 'Region', 'Flows', 'Bytes'];
                processRow = (row) => [
                    `<span class="text-purple clickable" onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${row.key}')">${row.key}</span>`,
                    row.hostname || '-',
                    row.region || '-',
                    row.flows.toLocaleString(),
                    row.bytes_fmt
                ];
            } else if (type === 'ports') {
                url = `/api/stats/ports?range=${this.timeRange}&limit=100`;
                this.expandedColumns = ['Port', 'Service', 'Flows', 'Bytes'];
                processRow = (row) => [
                    `<span class="text-cyan">${row.key}</span>`,
                    row.service,
                    (row.flows || 0).toLocaleString(),
                    row.bytes_fmt
                ];
            } else if (type === 'conversations' || type === 'flows') {
                url = `/api/flows?range=${this.timeRange}&limit=100`;
                this.expandedColumns = ['Source', 'Target', 'Proto/Port', 'Service', 'Packets', 'Bytes'];
                processRow = (row) => [
                    `<div class="truncate" style="max-width:200px" title="${row.src_hostname || ''}"><span class="text-cyan clickable" onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${row.src}')">${row.src}</span></div>`,
                    `<div class="truncate" style="max-width:200px" title="${row.dst_hostname || ''}"><span class="text-purple clickable" onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${row.dst}')">${row.dst}</span></div>`,
                    `${row.proto}/${row.port}`,
                    row.service,
                    row.packets.toLocaleString(),
                    row.bytes_fmt
                ];
            } else if (type === 'countries') {
                url = `/api/stats/countries?range=${this.timeRange}&limit=100`; // Assuming endpoint exists or maps to threats
                // Actually threatsByCountry uses /api/stats/threats/by_country if it's threats, or just flow stats? 
                // Let's assume flow stats by country for now, or fallback to threat countries if that's what the widget is.
                // The widget title is "Top Countries" (Network tab) or "Threats by Country" (Security tab)?
                // Network tab "Top Countries" uses `this.fetchCountries`.
                // Security tab "Threats by Country" uses `this.fetchThreatsByCountry`.
                // The chart is in Network tab "Top Countries" (line 1240 index.html).
                // So I need /api/stats/countries (Network tab).
                url = `/api/stats/countries?range=${this.timeRange}&limit=100`;
                this.expandedColumns = ['Country', 'Flows', 'Bytes', '%'];
                processRow = (row) => [
                    `<span class="country-flag">${row.country_code}</span> ${row.country_name}`,
                    (row.flows || 0).toLocaleString(),
                    row.bytes_fmt,
                    row.pct ? row.pct + '%' : '-'
                ];
            }

            const res = await fetch(url);
            if (res.ok) {
                const json = await res.json();
                const list = json[type] || json.conversations || [];
                this.expandedData = list.map(processRow);
            }
        } catch (e) {
            console.error(e);
        } finally {
            this.expandedLoading = false;
        }
    },


    // ----- Sparklines -----
    async renderSparklines(kind) {
        const canvases = document.querySelectorAll(`canvas.spark[data-kind="${kind}"]`);
        Charts.renderSparklines(canvases, this.timeRange, (k, ip) => this.openTrendModal(k, ip));
    },

    openTrendModal(kind, ip) {
        this.trendKind = kind;
        this.trendIP = ip;
        this.trendModalOpen = true;
        this.$nextTick(() => this.fetchIpTrend());
    },

    async fetchIpTrend() {
        try {
            const range = this.timeRange === '15m' ? '6h' : this.timeRange; // ensure enough buckets for spark
            const url = this.trendKind === 'source' ? `/api/trends/source/${this.trendIP}?range=${range}` : `/api/trends/dest/${this.trendIP}?range=${range}`;
            const res = await fetch(url);
            if (!res.ok) return;
            const data = await res.json();
            this.updateTrendChart(data);
        } catch (e) { console.error(e); }
    },

    updateTrendChart(data) {
        const ctx = document.getElementById('ipTrendChart');
        this.trendChartInstance = Charts.updateTrendChart(ctx, this.trendChartInstance, data);
    }
});
