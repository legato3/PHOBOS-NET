import { API } from './api.js?v=3.0.3';
import { Charts } from './charts.js?v=3.0.3';
import { DashboardWidgets } from './widgets.js?v=3.0.3';
import * as DashboardUtils from './utils.js?v=3.0.3';

export const Store = () => ({
    initDone: false,
    activeTab: 'overview',
    mapStatus: '', // Debug status for map loading

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
        conversations: 0,
        alertCorrelation: 0,
        threatActivityTimeline: 0
    },
    heavyTTL: 60000, // 60s for heavy widgets
    mediumTTL: 30000, // 30s for conversations

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
        includeContext: true // Include dashboard context in messages
    },

    // Mobile UI state
    showMobileFilters: false,

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
    conversations: { conversations: [], loading: true },

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

    netHealth: { indicators: [], health_score: 100, status: 'healthy', status_icon: '💚', loading: true, firewall_active: false, blocks_1h: 0 },
    serverHealth: { cpu: {}, memory: {}, disk: {}, syslog: {}, netflow: {}, database: {}, loading: true },

    // Security Features
    securityScore: { score: 100, grade: 'A', status: 'excellent', reasons: [], loading: true, trend: null, prevScore: null, fw_blocks_1h: 0, fw_threats_blocked: 0 },
    alertHistory: { alerts: [], total: 0, by_severity: {}, loading: true },
    threatsByCountry: { countries: [], total_blocked: 0, has_fw_data: false, loading: true },
    watchlist: { watchlist: [], count: 0, loading: true },
    watchlistInput: '',
    alertHistoryOpen: false,
    watchlistModalOpen: false,
    ipInvestigationModalOpen: false,
    threatVelocity: { current: 0, trend: 0, total_24h: 0, peak: 0, loading: true },
    topThreatIPs: { ips: [], loading: true },
    riskIndex: { score: 0, max_score: 100, level: 'LOW', color: 'green', factors: [], loading: true },

    // New Security Widgets
    attackTimeline: { timeline: [], peak_hour: null, peak_count: 0, total_24h: 0, fw_blocks_24h: 0, has_fw_data: false, loading: true },
    mitreHeatmap: { techniques: [], by_tactic: {}, total_techniques: 0, loading: true },
    protocolAnomalies: { protocols: [], anomaly_count: 0, loading: true },
    recentBlocks: { blocks: [], total_1h: 0, loading: true, stats: { total: 0, actions: {}, threats: 0, unique_src: 0, unique_dst: 0, blocks_last_hour: 0, passes_last_hour: 0 }, lastUpdate: null },
    recentBlocksView: 50,
    recentBlocksFilter: { action: 'all', searchIP: '', port: '', protocol: 'all', threatOnly: false },
    recentBlocksAutoRefresh: true,
    recentBlocksRefreshTimer: null,

    // Forensics Investigation Tools
    ipInvestigation: { searchIP: '', result: null, loading: false, error: null, timeline: { labels: [], bytes: [], flows: [], loading: false, compareHistory: false } },
    flowSearch: { filters: { srcIP: '', dstIP: '', port: '', protocol: '', country: '' }, results: [], loading: false },
    alertCorrelation: { chains: [], loading: false, showExplanation: false },
    threatActivityTimeline: { timeline: [], peak_hour: null, peak_count: 0, total_24h: 0, loading: true, timeRange: '24h', showDescription: false },

    // Alert Filtering
    alertFilter: { severity: 'all', type: 'all' },
    alertTypes: ['all', 'threat_ip', 'port_scan', 'brute_force', 'data_exfil', 'dns_tunneling', 'lateral_movement', 'suspicious_port', 'large_transfer', 'watchlist', 'off_hours', 'new_country', 'protocol_anomaly'],

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
            securityScore: 'Security Score',
            alertHistory: 'Alert History',
            threatsByCountry: 'Threats by Country',
            threatVelocity: 'Threat Velocity',
            topThreatIPs: 'Top Threat IPs',
            riskIndex: 'Network Risk Index',
            conversations: 'Recent Conversations',
            alertCorrelation: 'Alert Correlation & Attack Chains',
            threatActivityTimeline: 'Threat Activity Timeline',
            talkers: 'Top Talkers',
            services: 'Top Services',
            hourlyTraffic: 'Traffic by Hour',
            flowStats: 'Flow Statistics',

            netHealth: 'Network Health',
            insights: 'Traffic Insights',
            mitreHeatmap: 'MITRE ATT&CK Coverage',
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
        nfdump_dir: '',
        geoip_city_path: '',
        geoip_asn_path: '',
        threat_feeds_path: '',
        internal_networks: ''
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
    networkGraphInstance: null,

    // Conversation View (List/Sankey)
    conversationView: 'list', // 'list' or 'sankey'
    sankeyChartInstance: null,

    // World Map
    worldMap: { loading: false, sources: [], destinations: [], threats: [], blocked: [], source_countries: [], dest_countries: [], threat_countries: [], blocked_countries: [], summary: null, lastUpdate: null },
    worldMapLayers: { sources: true, destinations: true, threats: true, blocked: false },
    insights: { loading: false }, // Dummy object for insights widget (uses data from other widgets)
    map: null,
    mapLayers: [],

    bwChartInstance: null,
    flagsChartInstance: null,
    pktSizeChartInstance: null,
    hourlyChartInstance: null,
    hourlyChart2Instance: null,

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

    init() {
        // Polyfill requestIdleCallback for better browser support
        const idleCallback = window.requestIdleCallback || ((cb) => setTimeout(cb, 1));

        // Mark as initialized immediately for rendering
        this.initDone = true;

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
                } else {
                    if (this.recentBlocksRefreshTimer) {
                        clearInterval(this.recentBlocksRefreshTimer);
                        this.recentBlocksRefreshTimer = null;
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
        ['section-summary', 'section-worldmap', 'section-analytics', 'section-topstats', 'section-security', 'section-conversations'].forEach(id => {
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
            if (this.fullscreenChartInstance) {
                this.fullscreenChartInstance.destroy();
            }

            // Clone the chart configuration
            const config = JSON.parse(JSON.stringify(sourceChart.config));
            config.options = config.options || {};
            config.options.responsive = true;
            config.options.maintainAspectRatio = false;

            this.fullscreenChartInstance = new Chart(canvas, config);
        });
    },

    closeFullscreenChart() {
        if (this.fullscreenChartInstance) {
            this.fullscreenChartInstance.destroy();
            this.fullscreenChartInstance = null;
        }
        this.fullscreenChart = null;
    },

    getChartInstance(chartId) {
        switch (chartId) {
            case 'bwChart': return this.bwChartInstance;
            case 'flagsChart': return this.flagsChartInstance;
            case 'pktSizeChart': return this.pktSizeChartInstance;
            case 'hourlyChart': return this.hourlyChartInstance;
            case 'hourlyChart2': return this.hourlyChart2Instance;

            case 'countriesChart': return this.countriesChartInstance;
            case 'blocklistChart': return this.blocklistChartInstance;
            default: return null;
        }
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
            }
        } catch (e) { console.error('Failed to load config:', e); }
        this.configLoading = false;
    },

    async saveConfig() {
        this.configSaving = true;
        try {
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(this.config)
            });
            if (res.ok) {
                const result = await res.json();
                if (result.config) {
                    this.config = { ...this.config, ...result.config };
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

        if (sectionId === 'section-worldmap' && this.isVisible('worldMap')) {
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
                                console.log(`[WorldMap] Container has dimensions ${rect.width}x${rect.height}, initializing map`);
                                this.renderWorldMap();
                            } 
                            // If parent has dimensions but container doesn't, force container dimensions
                            else if (parentRect && parentRect.width > 0 && parentRect.height > 0) {
                                console.log(`[WorldMap] Parent has dimensions ${parentRect.width}x${parentRect.height}, forcing container dimensions`);
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
                                console.log('[WorldMap] No dimensions yet, setting up ResizeObserver');
                                this._mapResizeObserver = new ResizeObserver((entries) => {
                                    for (const entry of entries) {
                                        const { width, height } = entry.contentRect;
                                        if (width > 0 && height > 0 && !this.map) {
                                            console.log(`[WorldMap] ResizeObserver - Container has dimensions ${width}x${height}, initializing map`);
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

                if (this.isVisible('netHealth')) this.fetchNetHealth();
                this.lastFetch.network = now;
            }
        }
        if (sectionId === 'section-security') {
            if (now - this.lastFetch.security > this.heavyTTL) {
                this.fetchSecurityScore();
                this.fetchAlertHistory();
                this.fetchThreatsByCountry();
                this.fetchThreatVelocity();
                this.fetchTopThreatIPs();
                this.fetchRiskIndex();
                this.fetchAttackTimeline();
                this.fetchMitreHeatmap();
                this.fetchProtocolAnomalies();
                this.fetchRecentBlocks();
                this.fetchFeedHealth();
                this.fetchWatchlist();
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
        if (sectionId === 'section-conversations' && this.isVisible('conversations')) {
            if (now - this.lastFetch.conversations > this.mediumTTL) {
                this.fetchConversations();
                this.lastFetch.conversations = now;
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

        // Then fetch key charts in parallel, resilient to failure
        await Promise.allSettled([
            this.fetchBandwidth(),
            this.fetchAlerts(),
            this.fetchBlocklistRate(),
            this.fetchThreats()
        ]);

        // Then fetch the rest of the core data
        this.fetchSources(); // Top 10 sources
        this.fetchDestinations(); // Top 10 dests
        this.fetchPorts();

        // Fetch Overview Widgets (New)

        if (this.isVisible('talkers')) this.fetchTalkers();
        if (this.isVisible('netHealth')) this.fetchNetHealth();

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
                this.fetchHourlyTraffic()
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
                this.fetchRiskIndex(),
                this.fetchAttackTimeline(),
                this.fetchMitreHeatmap(),
                this.fetchProtocolAnomalies(),
                this.fetchRecentBlocks(),
                this.fetchFeedHealth(),
                this.fetchWatchlist()
            ]);
            this.lastFetch.security = now;
        }

        if (this.isSectionVisible('section-conversations') && (now - this.lastFetch.conversations > this.mediumTTL)) {
            this.fetchConversations();
            this.lastFetch.conversations = now;
        }

        // Render sparklines for top IPs (throttled via sparkTTL)
        this.renderSparklines('source');
        this.renderSparklines('dest');

        this.loadNotifyStatus();
    },

    get filteredSources() {
        let list = this.sources.sources;
        if (this.searchQuery) {
            const q = this.searchQuery.toLowerCase();
            list = list.filter(s => s.key.includes(q) || (s.hostname && s.hostname.includes(q)));
        }
        return list.slice(0, 5);
    },

    get filteredDestinations() {
        let list = this.destinations.destinations;
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

    async fetchSources() {
        this.sources.loading = true;
        this.sources.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/stats/sources?range=${this.timeRange}`);
            this.sources = { ...(await res.json()), loading: false, error: null };
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
            const res = await safeFetchFn(`/api/stats/destinations?range=${this.timeRange}`);
            this.destinations = { ...(await res.json()), loading: false, error: null };
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
            const res = await safeFetchFn(`/api/stats/ports?range=${this.timeRange}`);
            this.ports = { ...(await res.json()), loading: false, error: null };
        } catch (e) {
            console.error('Failed to fetch ports:', e);
            this.ports.error = DashboardUtils?.getUserFriendlyError(e, 'load ports') || 'Failed to load ports';
        } finally {
            this.ports.loading = false;
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
            const res = await safeFetchFn(`/api/stats/protocols?range=${this.timeRange}`);
            if (res.ok) {
                this.protocols = { ...(await res.json()), loading: false, error: null };
            } else {
                const errorMsg = `Protocols fetch failed: ${res.status}`;
                console.error(errorMsg);
                this.protocols.error = DashboardUtils?.getUserFriendlyError(new Error(errorMsg), 'load protocols') || errorMsg;
            }
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
            const res = await fetch(`/api/stats/malicious_ports?range=${this.timeRange}`);
            if (res.ok) {
                const data = await res.json();
                this.maliciousPorts = { ...data, loading: false };
                return;
            }
        } catch (e) {
            console.error('Failed to fetch malicious ports:', e);
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
                this.feedHealth = { ...d, loading: false };
            }
        } catch (e) { console.error('Feed health fetch error:', e); }
        finally { this.feedHealth.loading = false; }
    },

    async fetchSecurityScore() {
        this.securityScore.loading = true;
        try {
            const res = await fetch('/api/security/score');
            if (res.ok) {
                const d = await res.json();
                // Track trend
                const prevScore = this.securityScore.score;
                if (prevScore && prevScore !== d.score) {
                    d.trend = d.score > prevScore ? 'up' : 'down';
                    d.prevScore = prevScore;
                }
                this.securityScore = { ...d, loading: false };
            }
        } catch (e) { console.error('Security score fetch error:', e); }
        finally { this.securityScore.loading = false; }
    },

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

    async fetchAttackTimeline() {
        this.attackTimeline.loading = true;
        try {
            const res = await fetch('/api/security/attack-timeline');
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
            if (this._attackTimelineChart) this._attackTimelineChart.destroy();

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

            this._attackTimelineChart = new Chart(ctx, {
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

        // Apply action filter
        if (this.recentBlocksFilter.action !== 'all') {
            filtered = filtered.filter(b => b.action === this.recentBlocksFilter.action);
        }

        // Apply threat filter
        if (this.recentBlocksFilter.threatOnly) {
            filtered = filtered.filter(b => b.is_threat);
        }

        // Apply IP search filter
        if (this.recentBlocksFilter.searchIP) {
            const searchIP = this.recentBlocksFilter.searchIP.toLowerCase();
            filtered = filtered.filter(b =>
                (b.src_ip && b.src_ip.includes(searchIP)) ||
                (b.dst_ip && b.dst_ip.includes(searchIP))
            );
        }

        // Apply port filter
        if (this.recentBlocksFilter.port) {
            const port = this.recentBlocksFilter.port.toString();
            filtered = filtered.filter(b =>
                (b.src_port && b.src_port.toString().includes(port)) ||
                (b.dst_port && b.dst_port.toString().includes(port))
            );
        }

        // Apply protocol filter
        if (this.recentBlocksFilter.protocol !== 'all') {
            filtered = filtered.filter(b =>
                (b.proto && b.proto.toUpperCase() === this.recentBlocksFilter.protocol.toUpperCase())
            );
        }

        return filtered;
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
                this.showToast(`Sent block request for ${ip}`, 'success');
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

    async fetchRiskIndex() {
        this.riskIndex.loading = true;
        try {
            const res = await fetch('/api/security/risk_index');
            if (res.ok) {
                const d = await res.json();
                this.riskIndex = { ...d, loading: false };
            }
        } catch (e) { console.error('Risk index fetch error:', e); }
        finally { this.riskIndex.loading = false; }
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

        if (this.blocklistChartInstance) {
            this.blocklistChartInstance.data.labels = labels;
            this.blocklistChartInstance.data.datasets = datasets;
            this.blocklistChartInstance.options.scales = {
                x: { ticks: { color: '#888' }, grid: { color: '#333' } },
                y: { ticks: { color: '#888' }, grid: { color: '#333' }, suggestedMin: 0, suggestedMax: 100, position: 'left', title: { display: false } },
                ...(hasFwData ? { y1: { ticks: { color: 'rgba(0, 255, 100, 0.8)' }, grid: { display: false }, position: 'right', title: { display: true, text: 'Blocks', color: 'rgba(0, 255, 100, 0.8)', font: { size: 10 } } } } : {})
            };
            this.blocklistChartInstance.update();
        } else {
            this.blocklistChartInstance = new Chart(ctx, {
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

    async fetchAlerts() {
        this.alerts.loading = true;
        try {
            const res = await fetch(`/api/alerts?range=${this.timeRange}`);
            if (res.ok) this.alerts = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.alerts.loading = false; }
    },

    async fetchConversations() {
        this.conversations.loading = true;
        try {
            // Fetch more for Sankey/Graph
            const limit = this.conversationView === 'sankey' ? 50 : 10;
            const res = await fetch(`/api/conversations?range=${this.timeRange}&limit=${limit}`);
            if (res.ok) {
                const data = await res.json();
                this.conversations = { ...data };
                if (this.conversationView === 'sankey') {
                    this.$nextTick(() => this.renderSankey());
                }
            }
        } catch (e) { console.error(e); } finally { this.conversations.loading = false; }
    },

    toggleConversationView(view) {
        this.conversationView = view;
        if (view === 'sankey') {
            this.fetchConversations(); // Re-fetch with higher limit
        }
    },

    renderSankey() {
        const ctx = document.getElementById('sankeyChart');
        if (!ctx) return;

        // Destroy existing
        if (this.sankeyChartInstance) {
            this.sankeyChartInstance.destroy();
            this.sankeyChartInstance = null;
        }

        const raw = this.conversations.conversations || [];
        if (raw.length === 0) return;

        // Transform data: src -> service -> dst
        // To reduce clutter, we can aggregate
        // ChartJS Sankey expects: { from, to, flow }
        const data = [];

        // Limit to top flows to avoid messy graph
        const top = raw.slice(0, 30);

        top.forEach(c => {
            const src = c.src; // IP
            const dst = c.dst; // IP
            const flow = c.bytes;

            // Determine middle node (Service or Proto/Port)
            let service = c.service;
            if (!service || service === 'unknown') {
                service = `${c.proto}/${c.port}`;
            }

            // Add two links
            data.push({ from: src, to: service, flow: flow });
            data.push({ from: service, to: dst, flow: flow });
        });

        // Node colors map (simple hash)
        const getColor = (key) => {
            let hash = 0;
            for (let i = 0; i < key.length; i++) {
                hash = key.charCodeAt(i) + ((hash << 5) - hash);
            }
            const c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
            return '#' + '00000'.substring(0, 6 - c.length) + c;
        };

        const colors = {
            'http': '#00f3ff', 'https': '#00f3ff', 'ssh': '#ff003c', 'dns': '#ffff00'
        };

        this.sankeyChartInstance = new Chart(ctx, {
            type: 'sankey',
            data: {
                datasets: [{
                    label: 'Traffic Flow',
                    data: data,
                    colorFrom: (c) => getColor(c.dataset.data[c.dataIndex].from),
                    colorTo: (c) => getColor(c.dataset.data[c.dataIndex].to),
                    colorMode: 'gradient', // or 'to' or 'from'
                    size: 'max', // or 'min'
                    borderWidth: 0,
                    nodeWidth: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => {
                                const item = ctx.raw;
                                return `${item.from} -> ${item.to}: ${this.fmtBytes(item.flow)}`;
                            }
                        }
                    }
                },
                layout: { padding: 20 }
            }
        });
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
            const res = await fetch(`/api/stats/worldmap?range=${this.timeRange}`);
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
        console.log('[WorldMap] renderWorldMap() called');
        const container = document.getElementById('world-map-svg');
        if (!container) {
            console.warn('[WorldMap] Container not found');
            this.mapStatus = '';
            return;
        }
        console.log('[WorldMap] Container found:', container);
        
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
            console.log('[WorldMap] Container dimensions before init:', containerRect.width, 'x', containerRect.height);
            
            // Ensure no previous instance exists to prevent "Map container is already initialized" error
            if (container._leaflet_id) {
                container._leaflet_id = null;
            }

            // Clear any existing content
            container.innerHTML = '';

            try {

                console.log('[WorldMap] Creating Leaflet map instance...');
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
                console.log('[WorldMap] Map instance created:', this.map);

                // Initialize mapLayers array if not exists
                if (!this.mapLayers) {
                    this.mapLayers = [];
                }

                // Enable zoom control for visibility confirmation
                // Note: zoomControl was set to false in constructor, we can add it back
                L.control.zoom({ position: 'topright' }).addTo(this.map);

                // Add a base tile layer immediately so map is visible
                // (Container might have 0 dimensions if tab is hidden - Leaflet handles this)
                console.log('[WorldMap] Adding base tile layer...');
                const baseTileLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    attribution: '&copy; OpenStreetMap &copy; CARTO',
                    subdomains: 'abcd',
                    maxZoom: 19
                });
                baseTileLayer.addTo(this.map);
                console.log('[WorldMap] Base tile layer added to map');

                // Invalidate size - even if container has 0 dimensions, Leaflet will handle it
                this.map.whenReady(() => {
                    if (!this.map) return;
                    console.log('[WorldMap] Map whenReady callback fired');
                    // Call invalidateSize - will work even if container is temporarily 0x0
                    if (this.map) {
                        this.map.invalidateSize();
                        console.log('[WorldMap] invalidateSize() called in whenReady');
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
                            console.log('[WorldMap] Delayed check - Container dimensions:', rect.width, 'x', rect.height);
                            this.map.invalidateSize();
                            this.map.setView([20, 0], 2);
                            this.mapStatus = ''; // Clear status on success
                            console.log('[WorldMap] Map initialized successfully, view set to [20, 0], zoom 2');
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

        // Draw Sources (Green)
        sources.forEach(p => {
            const size = Math.min(12, Math.max(5, Math.log10(p.bytes + 1) * 2.5));
            const marker = L.circleMarker([p.lat, p.lng], {
                radius: size,
                fillColor: '#00ff64',
                color: '#00ff64',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.7
            });
            marker.bindPopup(`<strong>🔼 SOURCE: ${p.ip}</strong><br>📍 ${p.city || ''}, ${p.country}<br>📊 ${p.bytes_fmt}<br>${p.flows ? `📈 ${p.flows} flows` : ''}<br><button onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${p.ip}')" style="margin-top:8px;padding:4px 8px;background:#00ff64;border:none;border-radius:4px;cursor:pointer;color:#000;font-weight:600;">Investigate IP</button>`);
            marker.on('click', () => {
                this.openIPModal(p.ip);
            });
            marker.addTo(this.map);
            this.mapLayers.push(marker);
        });

        // Draw Destinations (Blue)
        dests.forEach(p => {
            const size = Math.min(12, Math.max(5, Math.log10(p.bytes + 1) * 2.5));
            const marker = L.circleMarker([p.lat, p.lng], {
                radius: size,
                fillColor: '#00f3ff',
                color: '#00f3ff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.7
            });
            marker.bindPopup(`<strong>🔽 DESTINATION: ${p.ip}</strong><br>📍 ${p.city || ''}, ${p.country}<br>📊 ${p.bytes_fmt}<br>${p.flows ? `📈 ${p.flows} flows` : ''}<br><button onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${p.ip}')" style="margin-top:8px;padding:4px 8px;background:#00f3ff;border:none;border-radius:4px;cursor:pointer;color:#000;font-weight:600;">Investigate IP</button>`);
            marker.on('click', () => {
                this.openIPModal(p.ip);
            });
            marker.addTo(this.map);
            this.mapLayers.push(marker);
        });

        // Draw Threats (Red)
        threats.forEach(p => {
            const threatMarker = L.circleMarker([p.lat, p.lng], {
                radius: 8,
                fillColor: '#ff003c',
                color: '#ff003c',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.8
            });
            threatMarker.bindPopup(`<strong>⚠️ THREAT: ${p.ip}</strong><br>📍 ${p.city || ''}, ${p.country}<br>${p.category ? `📋 Category: ${p.category}<br>` : ''}${p.feed ? `🔖 Feed: ${p.feed}<br>` : ''}<button onclick="document.querySelector('[x-data]').__x.$data.openIPModal('${p.ip}')" style="margin-top:8px;padding:4px 8px;background:#ff003c;border:none;border-radius:4px;cursor:pointer;color:#fff;font-weight:600;">Investigate IP</button>`);
            threatMarker.on('click', () => {
                this.openIPModal(p.ip);
            });
            threatMarker.addTo(this.map);
            this.mapLayers.push(threatMarker);
        });
    },

    resetWorldMapView() {
        if (this.map) {
            this.map.setView([20, 0], 2);
        }
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

    async fetchHourlyTraffic() {
        this.hourlyTraffic.loading = true;
        try {
            const res = await fetch(`/api/stats/hourly?range=${this.timeRange}`);
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
            if (!ctx || !data || !data.labels) return;

            // Check if canvas parent container is visible
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

            const peakColor = this.getCssVar('--neon-green') || '#00ff88';
            const normColor = this.getCssVar('--neon-cyan') || '#00f3ff';

            // Use different chart instances for different canvas IDs
            const instanceKey = 'hourlyChartInstance';
            const chartInstance = this[instanceKey];

            if (chartInstance) {
                chartInstance.data.labels = data.labels;
                chartInstance.data.datasets[0].data = data.bytes;
                chartInstance.update();
            } else {
                const newChart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: 'Traffic',
                            data: data.bytes,
                            backgroundColor: data.bytes.map((_, i) => i === data.peak_hour ? peakColor : normColor),
                            borderColor: data.bytes.map((_, i) => i === data.peak_hour ? peakColor : normColor),
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
                        }
                    }
                });
                this[instanceKey] = newChart;
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





    async fetchNetHealth() {
        this.netHealth.loading = true;
        try {
            const res = await fetch(`/api/stats/net_health?range=${this.timeRange}`);
            if (res.ok) this.netHealth = { ...(await res.json()) };
        } catch (e) { console.error(e); } finally { this.netHealth.loading = false; }
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

        // Set up 2-second interval refresh for real-time updates (independent of global refresh)
        this.serverHealthRefreshTimer = setInterval(() => {
            if (this.activeTab === 'server' && !this.paused) {
                this.fetchServerHealth();
            } else {
                // Clean up if tab changed or paused
                if (this.serverHealthRefreshTimer) {
                    clearInterval(this.serverHealthRefreshTimer);
                    this.serverHealthRefreshTimer = null;
                }
            }
        }, 2000);
    },

    async fetchBandwidth() {
        this.bandwidth.loading = true;
        this.bandwidth.error = null;
        try {
            const safeFetchFn = DashboardUtils?.safeFetch || fetch;
            const res = await safeFetchFn(`/api/bandwidth?range=${this.timeRange}`);
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

            const colorArea = 'rgba(0, 243, 255, 0.2)';
            const colorLine = this.getCssVar('--neon-cyan') || '#00f3ff';
            const colorFlows = this.getCssVar('--neon-purple') || '#bc13fe';

            if (this.bwChartInstance) {
                this.bwChartInstance.data.labels = data.labels;
                this.bwChartInstance.data.datasets[0].data = data.bandwidth;
                this.bwChartInstance.data.datasets[1].data = data.flows;
                this.bwChartInstance.update();
            } else {
                this.bwChartInstance = new Chart(ctx, {
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
                        }
                    }
                });
            }
        } catch (e) {
            console.error('Chart render error:', e);
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
            if (this.pktSizeChartInstance) {
                try {
                    this.pktSizeChartInstance.data.labels = data.labels;
                    this.pktSizeChartInstance.data.datasets[0].data = data.data;
                    this.pktSizeChartInstance.update('none'); // 'none' mode prevents animation that might trigger reactivity
                } catch (e) {
                    // Chart instance is corrupted, destroy and recreate
                    console.warn('Packet Size chart instance corrupted, recreating:', e);
                    try {
                        this.pktSizeChartInstance.destroy();
                    } catch {}
                    this.pktSizeChartInstance = null;
                }
            }

            // Create new chart if instance doesn't exist
            if (!this.pktSizeChartInstance) {
                this.pktSizeChartInstance = new Chart(ctx, {
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
            const ctx = document.getElementById('countriesChart');
            if (!ctx || !data) return;

            // Check if canvas parent container is visible
            // Check if canvas parent container is visible
            const container = ctx.closest('.widget-body, .chart-wrapper-small');
            if (container && (!container.offsetParent || container.offsetWidth === 0 || container.offsetHeight === 0)) {
                // Container not visible yet, defer initialization (limit retries)
                if (!this._countriesRetries) this._countriesRetries = 0;
                if (this._countriesRetries < 50) {
                    this._countriesRetries++;
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
                setTimeout(() => this.updateCountriesChart(data), 100);
                return;
            }
            const labels = data.labels || [];
            const values = data.bytes || [];
            const colors = ['#00f3ff', '#bc13fe', '#0aff0a', '#ffff00', '#ff003c', '#ff7f50', '#7fffd4', '#ffd700', '#00fa9a', '#ffa07a'];
            if (this.countriesChartInstance) {
                this.countriesChartInstance.data.labels = labels;
                this.countriesChartInstance.data.datasets[0].data = values;
                this.countriesChartInstance.update();
            } else {
                this.countriesChartInstance = new Chart(ctx, {
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
        } catch (e) {
            console.error('Chart render error:', e);
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
            // Cyberpunk palette
            const colors = ['#00f3ff', '#bc13fe', '#0aff0a', '#ff003c', '#ffff00', '#ffffff'];

            // Destroy existing chart if it exists but is in bad state
            if (this.flagsChartInstance) {
                try {
                    this.flagsChartInstance.data.labels = labels;
                    this.flagsChartInstance.data.datasets[0].data = data;
                    this.flagsChartInstance.update('none'); // 'none' mode prevents animation
                } catch (e) {
                    // Chart instance is corrupted, destroy and recreate
                    console.warn('Flags chart instance corrupted, recreating:', e);
                    try {
                        this.flagsChartInstance.destroy();
                    } catch {}
                    this.flagsChartInstance = null;
                }
            }

            // Create new chart if instance doesn't exist
            if (!this.flagsChartInstance) {
                this.flagsChartInstance = new Chart(ctx, {
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
                            legend: { position: 'right', labels: { color: '#e0e0e0', boxWidth: 12 } }
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

    // === FORENSICS INVESTIGATION FUNCTIONS ===

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
            if (this._ipInvestigationTimelineChart) this._ipInvestigationTimelineChart.destroy();

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

            this._ipInvestigationTimelineChart = new Chart(ctx, {
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
            // For now, use mock data from conversations as fallback
            const filtered = this.conversations.conversations.filter(c => {
                if (this.flowSearch.filters.srcIP && !c.src.includes(this.flowSearch.filters.srcIP)) return false;
                if (this.flowSearch.filters.dstIP && !c.dst.includes(this.flowSearch.filters.dstIP)) return false;
                if (this.flowSearch.filters.port && c.port !== parseInt(this.flowSearch.filters.port)) return false;
                if (this.flowSearch.filters.protocol && c.proto.toLowerCase() !== this.flowSearch.filters.protocol.toLowerCase()) return false;
                return true;
            });
            this.flowSearch.results = filtered.map(c => ({
                src: c.src,
                dst: c.dst,
                proto: c.proto,
                port: c.port,
                bytes_fmt: c.bytes_fmt
            }));
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
            const res = await fetch(`/api/security/attack-timeline?range=${this.threatActivityTimeline.timeRange || '24h'}`);
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

            if (this._threatActivityTimelineChart) {
                try {
                    this._threatActivityTimelineChart.destroy();
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

            this._threatActivityTimelineChart = new Chart(ctx, {
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
                timeRange: this.threatActivityTimeline.timeRange,
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
        this.ipDetails = null;
        try {
            const res = await fetch(`/api/ip_detail/${ip}`);
            if (res.ok) this.ipDetails = await res.json();
        } catch (e) { console.error(e); }
        this.ipLoading = false;
    },

    applyFilter(ip) {
        this.openIPModal(ip);
    },

    loadTab(tab) {
        this.activeTab = tab;
        const now = Date.now();
        if (tab === 'overview') {
            if (now - this.lastFetch.worldmap > this.heavyTTL) {
                this.fetchWorldMap();
                this.lastFetch.worldmap = now;
            }
            // Map initialization is handled by IntersectionObserver when section becomes visible
            // Just fetch data here if needed
        } else if (tab === 'server') {
            this.startServerHealthAutoRefresh();
        } else if (tab === 'security') {
            if (now - this.lastFetch.security > this.heavyTTL) {
                this.fetchSecurityScore();
                this.fetchAlertHistory();
                this.fetchThreatsByCountry();
                this.fetchThreatVelocity();
                this.fetchTopThreatIPs();
                this.fetchRiskIndex();
                this.fetchAttackTimeline();
                this.fetchMitreHeatmap();
                this.fetchProtocolAnomalies();
                this.fetchFeedHealth();
                this.fetchWatchlist();
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
        } else if (tab === 'forensics') {
            if (now - this.lastFetch.conversations > this.mediumTTL) {
                this.fetchConversations();
                this.lastFetch.conversations = now;
            }
            this.fetchRecentBlocks();
            this.fetchAlertCorrelation();
            this.fetchThreatActivityTimeline();
            // Start auto-refresh for firewall logs
            this.startRecentBlocksAutoRefresh();
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
                alerts: this.alertHistory?.alerts?.length || 0
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
                }))
            },
            firewall: {
                cpu: this.firewall?.cpu_percent || null,
                memory: this.firewall?.mem_percent || null,
                uptime: this.firewall?.sys_uptime || null,
                blocksLastHour: this.firewall?.blocks_1h || 0,
                syslogActive: this.firewall?.syslog_active || false
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
        contextText += `\n### Firewall Status\n`;
        if (context.firewall.cpu !== null) {
            contextText += `- CPU Usage: ${context.firewall.cpu}%\n`;
        }
        if (context.firewall.memory !== null) {
            contextText += `- Memory Usage: ${context.firewall.memory}%\n`;
        }
        contextText += `- Blocks Last Hour: ${context.firewall.blocksLastHour}\n`;
        contextText += `- Syslog Active: ${context.firewall.syslogActive ? 'Yes' : 'No'}\n`;

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

            const data = await res.json();

            // Extract response message
            let responseText = '';
            if (data.message && data.message.content) {
                responseText = data.message.content;
            } else if (data.response) {
                responseText = data.response;
            } else if (typeof data === 'string') {
                responseText = data;
            } else {
                responseText = JSON.stringify(data);
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

    // ----- Expanded Views & Graph -----

    async openExpandedTable(type) {
        this.expandedModalOpen = true;
        this.expandedLoading = true;
        this.expandedData = [];

        const titles = {
            'sources': 'Top 100 Sources',
            'destinations': 'Top 100 Destinations',
            'ports': 'Top 100 Ports',
            'conversations': 'Recent Conversations (Top 100)',
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
            } else if (type === 'conversations') {
                url = `/api/conversations?range=${this.timeRange}&limit=100`;
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

    async openNetworkGraph() {
        this.networkGraphOpen = true;
        // Wait for modal transition
        setTimeout(() => {
            this.renderNetworkGraph();
        }, 100);
    },

    async renderNetworkGraph() {
        const container = document.getElementById('network-graph-container');
        if (!container) {
            return;
        }

        // Get container dimensions
        const rect = container.getBoundingClientRect();

        // Check if vis library is loaded
        if (typeof vis === 'undefined' || !vis.Network) {
            console.error('[Graph] vis-network library not loaded');
            container.innerHTML = '<div style="color:var(--neon-red); text-align:center; padding-top:50px">vis-network library not loaded. Check console.</div>';
            return;
        }

        // Ensure container has dimensions (vis-network needs explicit size)
        if (rect.height < 100) {
            container.style.height = '70vh';
        }

        // Clear previous
        container.innerHTML = '<div class="spinner" style="margin: 50px auto;"></div>';

        try {
            // Fetch top conversations
            const res = await fetch(`/api/conversations?range=${this.timeRange}&limit=100`);
            if (!res.ok) throw new Error("Failed to fetch graph data: " + res.status);
            const json = await res.json();
            const convs = json.conversations || [];

            if (convs.length === 0) {
                container.innerHTML = '<div style="color:var(--text-muted); text-align:center; padding-top:50px">No conversation data available</div>';
                return;
            }

            // Nodes and Edges
            const nodes = new Map();
            const edges = [];

            convs.forEach(c => {
                // Source Node
                if (!nodes.has(c.src)) {
                    nodes.set(c.src, {
                        id: c.src,
                        label: c.src,
                        title: c.src_hostname || c.src,
                        group: 'source',
                        value: 1 // base size
                    });
                } else {
                    nodes.get(c.src).value += 1;
                    if (nodes.get(c.src).group === 'dest') nodes.get(c.src).group = 'both';
                }

                // Dest Node
                if (!nodes.has(c.dst)) {
                    nodes.set(c.dst, {
                        id: c.dst,
                        label: c.dst,
                        title: c.dst_hostname || c.dst,
                        group: 'dest',
                        value: 1
                    });
                } else {
                    nodes.get(c.dst).value += 1;
                    if (nodes.get(c.dst).group === 'source') nodes.get(c.dst).group = 'both';
                }

                // Edge
                edges.push({
                    from: c.src,
                    to: c.dst,
                    value: c.bytes, // thickness
                    title: `${c.proto}/${c.port} (${c.bytes_fmt})`,
                    color: { inherit: 'from' }
                });
            });

            const data = {
                nodes: Array.from(nodes.values()),
                edges: edges
            };

            const options = {
                nodes: {
                    shape: 'dot',
                    font: { color: '#e0e0e0', face: 'monospace' },
                    scaling: { min: 10, max: 30 }
                },
                edges: {
                    color: { color: '#333', highlight: '#00f3ff' },
                    smooth: { type: 'continuous' }
                },
                groups: {
                    source: { color: { background: '#00f3ff', border: '#00f3ff' } },
                    dest: { color: { background: '#bc13fe', border: '#bc13fe' } },
                    both: { color: { background: '#0aff0a', border: '#0aff0a' } }
                },
                physics: {
                    stabilization: false,
                    barnesHut: { gravitationalConstant: -8000, springConstant: 0.04, springLength: 95 }
                },
                interaction: { tooltipDelay: 200, hover: true }
            };

            container.innerHTML = ''; // clear spinner

            this.networkGraphInstance = new vis.Network(container, data, options);

            // Click handler
            this.networkGraphInstance.on("click", (params) => {
                if (params.nodes.length > 0) {
                    const nodeId = params.nodes[0];
                    this.openIPModal(nodeId);
                }
            });

        } catch (e) {
            console.error('[Graph] Error:', e);
            container.innerHTML = '<div style="color:var(--neon-red); text-align:center; padding-top:50px">Failed to load graph: ' + e.message + '</div>';
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
