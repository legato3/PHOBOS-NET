// Register Service Worker for offline support
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/sw.js')
            .then(reg => console.log('[SW] Registered:', reg.scope))
            .catch(err => console.log('[SW] Registration failed:', err));
    });
}

document.addEventListener('alpine:init', () => {
    Alpine.data('dashboard', () => ({
        initDone: false,

        firewall: { cpu_percent: null, mem_percent: null, sys_uptime: null, loading: false },
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
            analytics: 0,
            topstats: 0,
            security: 0,
            conversations: 0
        },
        heavyTTL: 60000, // 60s for heavy widgets
        mediumTTL: 30000, // 30s for conversations

        // Low Power mode
        lowPower: false,

        // Compact mode
        compactMode: false,

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
        maliciousPorts: { ports: [], loading: true },
        threats: { hits: [], loading: true },
        blocklist: { series: [], current_rate: null, total_matches: 0, loading: true },
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
        protoMix: { labels: [], bytes: [], percentages: [], colors: [], loading: true },
        netHealth: { indicators: [], health_score: 100, status: 'healthy', status_icon: '💚', loading: true },
        
        // Security Features
        securityScore: { score: 100, grade: 'A', status: 'excellent', reasons: [], loading: true, trend: null, prevScore: null },
        alertHistory: { alerts: [], total: 0, by_severity: {}, loading: true },
        threatsByCountry: { countries: [], loading: true },
        watchlist: { watchlist: [], count: 0, loading: true },
        watchlistInput: '',
        alertHistoryOpen: false,
        watchlistModalOpen: false,
        threatVelocity: { current: 0, trend: 0, total_24h: 0, peak: 0, loading: true },
        topThreatIPs: { ips: [], loading: true },
        riskIndex: { score: 0, max_score: 100, level: 'LOW', color: 'green', factors: [], loading: true },

        // New Security Widgets
        attackTimeline: { timeline: [], peak_hour: null, peak_count: 0, total_24h: 0, loading: true },
        mitreHeatmap: { techniques: [], by_tactic: {}, total_techniques: 0, loading: true },
        protocolAnomalies: { protocols: [], anomaly_count: 0, loading: true },
        
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

        // UI Labels for Widgets (only widgets that exist in HTML template)
        friendlyLabels: {
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
            talkers: 'Top Talkers',
            services: 'Top Services',
            hourlyTraffic: 'Traffic by Hour',
            flowStats: 'Flow Statistics',
            protoMix: 'Protocol Mix',
            netHealth: 'Network Health',
            insights: 'Traffic Insights',
            mitreHeatmap: 'MITRE ATT&CK Coverage',
            protocolAnomalies: 'Protocol Anomalies',
            attackTimeline: 'Attack Timeline'
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
            if (field === 'mem_used' || field === 'mem_total') return this.formatBytes(val * 1024);
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

        // World Map
        worldMap: { loading: false, sources: [], destinations: [], threats: [], source_countries: [], dest_countries: [], threat_countries: [], summary: null },
        worldMapLayers: { sources: true, destinations: true, threats: true },

        bwChartInstance: null,
        flagsChartInstance: null,
        pktSizeChartInstance: null,
        hourlyChartInstance: null,
        protoMixChartInstance: null,
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
            console.log('Neural Link Established.');
            console.log('[Init] vis-network available:', typeof vis !== 'undefined', 'vis.Network:', typeof vis !== 'undefined' && vis?.Network ? 'yes' : 'no');
            this.initDone = true;
            this.loadWidgetPreferences();
            this.loadCompactMode();
            this.startIntersectionObserver();
            this.loadAll();
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

            // Watchers
            this.$watch('timeRange', () => {
                this.loadAll();
            });
            this.$watch('refreshInterval', () => {
                 this.startTimer();
            });
            this.$watch('compactMode', (v) => {
                document.body.classList.toggle('compact-mode', v);
                localStorage.setItem('compactMode', v ? '1' : '0');
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
            
            // Render empty map on init (grid/background)
            this.$nextTick(() => setTimeout(() => this.renderWorldMap(), 500));
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

        // Helper to get CSS variable value
        getCssVar(name) {
             return getComputedStyle(document.body).getPropertyValue(name).trim();
        },

        get activeAlerts() {
            if (!this.alerts.alerts) return [];
            return this.alerts.alerts.filter(a => !this.dismissedAlerts.has(a.msg));
        },

        get groupedAlerts() {
            const groups = {};
            const order = ['critical', 'high', 'medium', 'low', 'info'];

            // Sort active alerts by order then group
            const sorted = this.activeAlerts.sort((a,b) => {
                return order.indexOf(a.severity) - order.indexOf(b.severity);
            });

            sorted.forEach(a => {
                const s = a.severity.toUpperCase();
                if(!groups[s]) groups[s] = [];
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
            if (elapsed < 120) return { text: `${Math.floor(elapsed/60)}m ago`, class: 'stale' };
            return { text: `${Math.floor(elapsed/60)}m ago`, class: 'error' };
        },

        setupKeyboardShortcuts() {
            document.addEventListener('keydown', (e) => {
                // Don't trigger if typing in input
                if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
                
                switch(e.key.toLowerCase()) {
                    case 'r':
                        e.preventDefault();
                        this.loadAll();
                        this.refreshCountdown = this.refreshInterval / 1000;
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
                        this.closeFullscreenChart();
                        break;
                    case '?':
                        if (e.shiftKey) {
                            e.preventDefault();
                            alert('Keyboard Shortcuts:\n\nR - Refresh data\nP - Pause/Resume\n1-6 - Time range (15m to 7d)\nESC - Close modals\n? - Show this help');
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
            switch(chartId) {
                case 'bwChart': return this.bwChartInstance;
                case 'flagsChart': return this.flagsChartInstance;
                case 'pktSizeChart': return this.pktSizeChartInstance;
                case 'hourlyChart': return this.hourlyChartInstance;
                case 'protoMixChart': return this.protoMixChartInstance;
                case 'countriesChart': return this.countriesChartInstance;
                case 'blocklistChart': return this.blocklistChartInstance;
                default: return null;
            }
        },

        // API Latency tracking helper
        async fetchWithLatency(url) {
            const start = performance.now();
            const res = await fetch(url);
            const latency = Math.round(performance.now() - start);
            this.apiLatency = latency;
            this.apiLatencyHistory.push(latency);
            if (this.apiLatencyHistory.length > 10) {
                this.apiLatencyHistory.shift();
            }
            return res;
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

        openThresholds() { this.thresholdsModalOpen = true; },

        async loadThresholds() {
            try {
                const res = await fetch('/api/thresholds');
                if (res.ok) {
                    const t = await res.json();
                    this.thresholds = { ...this.thresholds, ...t };
                }
            } catch(e) { console.error(e); }
        },

        async saveThresholds() {
            try {
                const res = await fetch('/api/thresholds', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(this.thresholds)
                });
                if (res.ok) {
                    const t = await res.json();
                    this.thresholds = { ...this.thresholds, ...t };
                    this.thresholdsModalOpen = false;
                }
            } catch(e) { console.error(e); }
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
            } catch(e) { console.error('Failed to load config:', e); }
            this.configLoading = false;
        },

        async saveConfig() {
            this.configSaving = true;
            try {
                const res = await fetch('/api/config', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
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
            } catch(e) {
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
            }
            if (sectionId === 'section-analytics') {
                if (now - this.lastFetch.analytics > this.heavyTTL) {
                    if (this.isVisible('flags')) this.fetchFlags();
                    if (this.isVisible('durations')) this.fetchDurations();
                    if (this.isVisible('packetSizes')) this.fetchPacketSizes();
                    if (this.isVisible('protocols')) this.fetchProtocols();
                    if (this.isVisible('flowStats')) this.fetchFlowStats();
                    if (this.isVisible('protoMix')) this.fetchProtoMix();
                    if (this.isVisible('netHealth')) this.fetchNetHealth();
                    this.lastFetch.analytics = now;
                }
            }
            if (sectionId === 'section-topstats') {
                if (now - this.lastFetch.topstats > this.heavyTTL) {
                    if (this.isVisible('asns')) this.fetchASNs();
                    if (this.isVisible('countries')) this.fetchCountries();
                    if (this.isVisible('talkers')) this.fetchTalkers();
                    if (this.isVisible('services')) this.fetchServices();
                    if (this.isVisible('hourlyTraffic')) this.fetchHourlyTraffic();
                    this.lastFetch.topstats = now;
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
                    this.fetchFeedHealth();
                    this.fetchWatchlist();
                    this.lastFetch.security = now;
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

            // Always fetch these (Core dashboard)
            this.fetchSummary();
            this.fetchBandwidth();
            this.fetchSources(); // Top 10 sources
            this.fetchDestinations(); // Top 10 dests
            this.fetchPorts();
            this.fetchThreats(); // Threat detections count
            this.fetchBlocklistRate();
            this.fetchAlerts(); // Alerts list
            if (!this.firewallStreamActive) this.fetchFirewall();

            // Smart Loading via Polling: Check if sections are visible AND stale

            if (this.isSectionVisible('section-worldmap') && (now - this.lastFetch.worldmap > this.heavyTTL)) {
                this.fetchWorldMap();
                this.lastFetch.worldmap = now;
            }

            if (this.isSectionVisible('section-analytics') && (now - this.lastFetch.analytics > this.heavyTTL)) {
                this.fetchFlags();
                this.fetchDurations();
                this.fetchPacketSizes();
                this.fetchProtocols();
                this.fetchFlowStats();
                this.fetchProtoMix();
                this.fetchNetHealth();
                this.lastFetch.analytics = now;
            }

            if (this.isSectionVisible('section-topstats') && (now - this.lastFetch.topstats > this.heavyTTL)) {
                this.fetchASNs();
                this.fetchCountries();
                this.fetchTalkers();
                this.fetchServices();
                this.fetchHourlyTraffic();
                this.lastFetch.topstats = now;
            }

            if (this.isSectionVisible('section-security') && (now - this.lastFetch.security > this.heavyTTL)) {
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
             if(this.searchQuery) {
                 const q = this.searchQuery.toLowerCase();
                 list = list.filter(s => s.key.includes(q) || (s.hostname && s.hostname.includes(q)));
             }
             return list.slice(0, 5);
        },

        get filteredDestinations() {
             let list = this.destinations.destinations;
             if(this.searchQuery) {
                 const q = this.searchQuery.toLowerCase();
                 list = list.filter(s => s.key.includes(q) || (s.hostname && s.hostname.includes(q)));
             }
             return list.slice(0, 5);
        },

        async fetchSummary() {
            this.summary.loading = true;
            try {
                const res = await this.fetchWithLatency(`/api/stats/summary?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.summary = { ...data, loading: false };
                    if(data.threat_status) this.threatStatus = data.threat_status;
                }
            } catch(e) { console.error(e); } finally { this.summary.loading = false; }
        },

        async fetchSources() {
            this.sources.loading = true;
            try {
                const res = await fetch(`/api/stats/sources?range=${this.timeRange}`);
                if(res.ok) this.sources = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.sources.loading = false; }
            // defer sparkline draw after DOM update
            this.$nextTick(() => this.renderSparklines('source'));
        },

        async fetchDestinations() {
            this.destinations.loading = true;
            try {
                const res = await fetch(`/api/stats/destinations?range=${this.timeRange}`);
                if(res.ok) this.destinations = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.destinations.loading = false; }
            this.$nextTick(() => this.renderSparklines('dest'));
        },

        async fetchPorts() {
            this.ports.loading = true;
            try {
                const res = await fetch(`/api/stats/ports?range=${this.timeRange}`);
                if(res.ok) this.ports = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.ports.loading = false; }
        },


        async fetchFirewall() {
            this.firewall.loading = true;
            try {
                const res = await fetch(`/api/stats/firewall?range=${this.timeRange}`);
                if(res.ok) this.firewall = { ...(await res.json()).firewall, loading: false };
            } catch(e) { console.error(e); } finally { this.firewall.loading = false; }
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
                    try { es.close(); } catch(_){}
                    this.firewallES = null;
                    // Retry after a delay
                    setTimeout(() => this.startFirewallStream(), 5000);
                };
            } catch(e) { console.error(e); }
        },

        async fetchProtocols() {
            this.protocols.loading = true;
            try {
                const res = await fetch(`/api/stats/protocols?range=${this.timeRange}`);
                if(res.ok) this.protocols = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.protocols.loading = false; }
        },

        // ----- New widget fetchers (Option B: threat-focused) -----
        async fetchMaliciousPorts() {
            this.maliciousPorts.loading = true;
            try {
                const res = await fetch(`/api/stats/malicious_ports?range=${this.timeRange}`);
                if (res.ok) {
                    this.maliciousPorts = { ...(await res.json()), loading: false };
                    return;
                }
            } catch (e) { /* ignore and fallback */ }
            finally { this.maliciousPorts.loading = false; }

            // Fallback: filter existing ports for suspicious flag
            const fallback = (this.ports.ports || []).filter(p => p.suspicious || p.threat).slice(0, 20).map(p => ({
                port: p.key || 'n/a',
                service: p.service || '',
                bytes: p.bytes || 0,
                bytes_fmt: p.bytes_fmt || this.fmtBytes(p.bytes || 0),
                hits: p.hits || p.flows || 0
            }));
            this.maliciousPorts.ports = fallback;
        },

        async fetchThreats() {
            this.threats.loading = true;
            try {
                const res = await fetch(`/api/stats/threats?range=${this.timeRange}`);
                if (res.ok) {
                    const d = await res.json();
                    this.threats = { ...(d), loading: false };
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
                
                const ctx = canvas.getContext('2d');
                if (this._attackTimelineChart) this._attackTimelineChart.destroy();
            
            const labels = this.attackTimeline.timeline.map(t => t.hour);
            const critical = this.attackTimeline.timeline.map(t => t.critical || 0);
            const high = this.attackTimeline.timeline.map(t => t.high || 0);
            const medium = this.attackTimeline.timeline.map(t => t.medium || 0);
            const low = this.attackTimeline.timeline.map(t => t.low || 0);
            
            const critColor = this.getCssVar('--neon-red') || 'rgba(255, 0, 60, 0.8)';

            this._attackTimelineChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels,
                    datasets: [
                        { label: 'Critical', data: critical, backgroundColor: critColor, stack: 'a' },
                        { label: 'High', data: high, backgroundColor: 'rgba(255, 165, 0, 0.8)', stack: 'a' },
                        { label: 'Medium', data: medium, backgroundColor: 'rgba(255, 255, 0, 0.7)', stack: 'a' },
                        { label: 'Low', data: low, backgroundColor: 'rgba(0, 255, 255, 0.5)', stack: 'a' }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: true, position: 'top', labels: { color: '#888', boxWidth: 12, padding: 8 } } },
                    scales: {
                        x: { stacked: true, grid: { display: false }, ticks: { color: '#666', maxRotation: 45 } },
                        y: { stacked: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#666' } }
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
            const labels = (series || []).map(s => new Date(s.ts).toLocaleTimeString());
            const values = (series || []).map(s => s.rate || 0);
            const color = this.getCssVar('--neon-red') || '#ff003c';
            if (this.blocklistChartInstance) {
                this.blocklistChartInstance.data.labels = labels;
                this.blocklistChartInstance.data.datasets[0].data = values;
                this.blocklistChartInstance.update();
            } else {
                this.blocklistChartInstance = new Chart(ctx, {
                    type: 'line',
                    data: { labels, datasets: [{ label: 'Match %', data: values, borderColor: color, backgroundColor: 'rgba(255,0,60,0.12)', fill: true, tension: 0.3 }] },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#888' }, grid: { color: '#333' } }, y: { ticks: { color: '#888' }, grid: { color: '#333' }, suggestedMin: 0, suggestedMax: 100 } } }
                });
            }
        },

        async fetchAlerts() {
            this.alerts.loading = true;
            try {
                const res = await fetch(`/api/alerts?range=${this.timeRange}`);
                if(res.ok) this.alerts = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.alerts.loading = false; }
        },

        async fetchConversations() {
            this.conversations.loading = true;
            try {
                const res = await fetch(`/api/conversations?range=${this.timeRange}`);
                if(res.ok) this.conversations = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.conversations.loading = false; }
        },

        async fetchFlags() {
            this.flags.loading = true;
            try {
                const res = await fetch(`/api/stats/flags?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.flags = { ...data, loading: false };
                    this.updateFlagsChart(data.flags);
                }
            } catch(e) { console.error(e); } finally { this.flags.loading = false; }
        },

        async fetchASNs() {
            this.asns.loading = true;
            try {
                const res = await fetch(`/api/stats/asns?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    // Calc max for bar chart
                    const max = Math.max(...data.asns.map(a => a.bytes));
                    this.asns = { ...data, maxBytes: max, loading: false };
                }
            } catch(e) { console.error(e); } finally { this.asns.loading = false; }
        },

        async fetchCountries() {
            this.countries.loading = true;
            try {
                const res = await fetch(`/api/stats/countries?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.countries = { ...data, loading: false };
                    this.updateCountriesChart(data);
                }
            } catch(e) { console.error(e); } finally { this.countries.loading = false; }
        },

        async fetchWorldMap() {
            this.worldMap.loading = true;
            try {
                const res = await fetch(`/api/stats/worldmap?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.worldMap = { ...data, loading: false };
                } else {
                    console.error('[WorldMap] API error:', res.status);
                }
            } catch(e) { console.error('[WorldMap] Fetch error:', e); } finally { 
                this.worldMap.loading = false;
                // Always render map after fetch (even with no data to show grid)
                this.$nextTick(() => this.renderWorldMap());
            }
        },

        renderWorldMap() {
            const container = document.getElementById('world-map-svg');
            if (!container) return;
            
            const sources = this.worldMapLayers.sources ? (this.worldMap.sources || []) : [];
            const dests = this.worldMapLayers.destinations ? (this.worldMap.destinations || []) : [];
            const threats = this.worldMapLayers.threats ? (this.worldMap.threats || []) : [];
            
            // Simple SVG world map with markers
            const width = container.clientWidth || 800;
            const height = Math.min(400, width * 0.5);
            
            // Convert lat/lng to x/y (simple Mercator projection)
            const latLngToXY = (lat, lng) => {
                const x = ((lng + 180) / 360) * width;
                const y = ((90 - lat) / 180) * height;
                return { x, y };
            };
            
            // Build SVG
            let svg = `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:100%;">`;
            
            // Background with grid
            svg += `<rect width="100%" height="100%" fill="rgba(0,20,40,0.5)"/>`;
            
            // Grid lines
            for (let i = 0; i <= 6; i++) {
                const y = (height / 6) * i;
                svg += `<line x1="0" y1="${y}" x2="${width}" y2="${y}" stroke="rgba(0,243,255,0.1)" stroke-width="0.5"/>`;
            }
            for (let i = 0; i <= 12; i++) {
                const x = (width / 12) * i;
                svg += `<line x1="${x}" y1="0" x2="${x}" y2="${height}" stroke="rgba(0,243,255,0.1)" stroke-width="0.5"/>`;
            }
            
            // Equator
            svg += `<line x1="0" y1="${height/2}" x2="${width}" y2="${height/2}" stroke="rgba(0,243,255,0.2)" stroke-width="1"/>`;
            
            // Prime Meridian
            svg += `<line x1="${width/2}" y1="0" x2="${width/2}" y2="${height}" stroke="rgba(0,243,255,0.15)" stroke-width="1"/>`;
            
            // Simplified world map outline (continental shapes)
            const worldPath = `
                M${0.12*width},${0.22*height} Q${0.18*width},${0.18*height} ${0.25*width},${0.25*height} 
                L${0.30*width},${0.38*height} L${0.25*width},${0.52*height} L${0.15*width},${0.65*height}
                L${0.08*width},${0.85*height} L${0.20*width},${0.95*height}
                M${0.35*width},${0.15*height} L${0.55*width},${0.12*height} L${0.48*width},${0.25*height}
                L${0.42*width},${0.35*height} L${0.38*width},${0.55*height} L${0.52*width},${0.85*height}
                M${0.55*width},${0.18*height} L${0.72*width},${0.15*height} L${0.75*width},${0.28*height}
                L${0.68*width},${0.42*height} L${0.58*width},${0.38*height} L${0.55*width},${0.52*height}
                M${0.72*width},${0.22*height} L${0.92*width},${0.25*height} L${0.95*width},${0.45*height}
                L${0.88*width},${0.55*height} L${0.78*width},${0.48*height}
                M${0.82*width},${0.65*height} L${0.95*width},${0.72*height} L${0.92*width},${0.88*height}
                L${0.78*width},${0.92*height} L${0.75*width},${0.78*height}
            `;
            svg += `<path d="${worldPath}" fill="none" stroke="rgba(0,243,255,0.25)" stroke-width="1.5" stroke-linecap="round"/>`;
            
            // Add continent labels
            const labels = [
                { x: 0.18, y: 0.45, name: 'Americas' },
                { x: 0.48, y: 0.32, name: 'Europe' },
                { x: 0.52, y: 0.55, name: 'Africa' },
                { x: 0.72, y: 0.35, name: 'Asia' },
                { x: 0.85, y: 0.78, name: 'Oceania' }
            ];
            labels.forEach(l => {
                svg += `<text x="${l.x*width}" y="${l.y*height}" fill="rgba(0,243,255,0.2)" font-size="10" text-anchor="middle">${l.name}</text>`;
            });
            // Draw destinations first (purple)
            dests.forEach(p => {
                const { x, y } = latLngToXY(p.lat, p.lng);
                const size = Math.min(12, Math.max(4, Math.log10(p.bytes + 1) * 2));
                svg += `<circle cx="${x}" cy="${y}" r="${size}" fill="rgba(188,19,254,0.6)" stroke="#bc13fe" stroke-width="1">
                    <title>${p.ip}\\n${p.city || ''}, ${p.country}\\n${p.bytes_fmt}</title>
                </circle>`;
            });
            
            // Draw sources (cyan)
            sources.forEach(p => {
                const { x, y } = latLngToXY(p.lat, p.lng);
                const size = Math.min(12, Math.max(4, Math.log10(p.bytes + 1) * 2));
                svg += `<circle cx="${x}" cy="${y}" r="${size}" fill="rgba(0,243,255,0.6)" stroke="#00f3ff" stroke-width="1">
                    <title>${p.ip}\\n${p.city || ''}, ${p.country}\\n${p.bytes_fmt}</title>
                </circle>`;
            });
            
            // Draw threats (red, pulsing)
            threats.forEach(p => {
                const { x, y } = latLngToXY(p.lat, p.lng);
                svg += `<circle cx="${x}" cy="${y}" r="6" fill="rgba(255,0,60,0.8)" stroke="#ff003c" stroke-width="2" class="threat-pulse">
                    <title>⚠️ THREAT: ${p.ip}\\n${p.city || ''}, ${p.country}</title>
                </circle>`;
            });
            
            svg += `</svg>`;
            container.innerHTML = svg;
        },

        async fetchDurations() {
            this.durations.loading = true;
            try {
                const res = await fetch(`/api/stats/durations?range=${this.timeRange}`);
                if(res.ok) this.durations = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.durations.loading = false; }
        },

        async fetchTalkers() {
            this.talkers.loading = true;
            try {
                const res = await fetch(`/api/stats/talkers?range=${this.timeRange}`);
                if(res.ok) this.talkers = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.talkers.loading = false; }
        },

        async fetchServices() {
            this.services.loading = true;
            try {
                const res = await fetch(`/api/stats/services?range=${this.timeRange}`);
                if(res.ok) this.services = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.services.loading = false; }
        },

        async fetchHourlyTraffic() {
            this.hourlyTraffic.loading = true;
            try {
                const res = await fetch(`/api/stats/hourly?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.hourlyTraffic = { ...data, loading: false };
                    this.updateHourlyChart(data);
                }
            } catch(e) { console.error(e); } finally { this.hourlyTraffic.loading = false; }
        },

        updateHourlyChart(data) {
            try {
                const ctx = document.getElementById('hourlyChart');
                if (!ctx || !data || !data.labels) return;
                
                const peakColor = this.getCssVar('--neon-green') || '#00ff88';
                const normColor = this.getCssVar('--neon-cyan') || '#00f3ff';

                if (this.hourlyChartInstance) {
                    this.hourlyChartInstance.data.labels = data.labels;
                    this.hourlyChartInstance.data.datasets[0].data = data.bytes;
                    this.hourlyChartInstance.update();
                } else {
                this.hourlyChartInstance = new Chart(ctx, {
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
            }
            } catch (e) {
                console.error('Chart render error:', e);
            }
        },

        async fetchFlowStats() {
            this.flowStats.loading = true;
            try {
                const res = await fetch(`/api/stats/flow_stats?range=${this.timeRange}`);
                if(res.ok) this.flowStats = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.flowStats.loading = false; }
        },

        async fetchProtoMix() {
            this.protoMix.loading = true;
            try {
                const res = await fetch(`/api/stats/proto_mix?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.protoMix = { ...data, loading: false };
                    this.updateProtoMixChart(data);
                }
            } catch(e) { console.error(e); } finally { this.protoMix.loading = false; }
        },

        updateProtoMixChart(data) {
            try {
                const ctx = document.getElementById('protoMixChart');
                if (!ctx || !data || !data.labels) return;

                if (this.protoMixChartInstance) {
                    this.protoMixChartInstance.data.labels = data.labels;
                    this.protoMixChartInstance.data.datasets[0].data = data.bytes;
                    this.protoMixChartInstance.update();
                } else {
                this.protoMixChartInstance = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            data: data.bytes,
                            backgroundColor: data.colors || ['#00f3ff', '#bc13fe', '#00ff88', '#ffff00', '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4'],
                            borderColor: 'rgba(0,0,0,0.3)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: true,
                                position: 'right',
                                labels: { color: '#aaa', font: { size: 10 }, boxWidth: 12 }
                            }
                        }
                    }
                });
            }
            } catch (e) {
                console.error('Chart render error:', e);
            }
        },

        async fetchNetHealth() {
            this.netHealth.loading = true;
            try {
                const res = await fetch(`/api/stats/net_health?range=${this.timeRange}`);
                if(res.ok) this.netHealth = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.netHealth.loading = false; }
        },

        async fetchBandwidth() {
            this.bandwidth.loading = true;
            try {
                const res = await fetch(`/api/bandwidth?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.bandwidth = { ...data, loading: false };
                    this.updateBwChart(data);
                }
            } catch(e) { console.error(e); } finally { this.bandwidth.loading = false; }
        },

        updateBwChart(data) {
            try {
                const ctx = document.getElementById('bwChart');
                if (!ctx || !data || !data.labels) return;

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
                if(res.ok) {
                    const data = await res.json();
                    this.packetSizes = { ...data, loading: false };
                    this.updatePktSizeChart(data);
                }
            } catch(e) { console.error(e); } finally { this.packetSizes.loading = false; }
        },

        updatePktSizeChart(data) {
            try {
                const ctx = document.getElementById('pktSizeChart');
                if (!ctx || !data || !data.labels) return;

                // Cyberpunk palette
                const colors = ['#bc13fe', '#00f3ff', '#0aff0a', '#ffff00', '#ff003c'];

                if (this.pktSizeChartInstance) {
                    this.pktSizeChartInstance.data.labels = data.labels;
                    this.pktSizeChartInstance.data.datasets[0].data = data.data;
                    this.pktSizeChartInstance.update();
                } else {
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
            } catch (e) {
                console.error('Chart render error:', e);
            }
        },

        updateCountriesChart(data) {
            try {
                const ctx = document.getElementById('countriesChart');
                if (!ctx || !data) return;
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

                const labels = flagsData.map(f => f.flag);
                const data = flagsData.map(f => f.count);
                // Cyberpunk palette
                const colors = ['#00f3ff', '#bc13fe', '#0aff0a', '#ff003c', '#ffff00', '#ffffff'];

                if (this.flagsChartInstance) {
                    this.flagsChartInstance.data.labels = labels;
                    this.flagsChartInstance.data.datasets[0].data = data;
                    this.flagsChartInstance.update();
                } else {
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
                            plugins: {
                                legend: { position: 'right', labels: { color: '#e0e0e0', boxWidth: 12 } }
                            }
                        }
                    });
                }
            } catch (e) {
                console.error('Chart render error:', e);
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
            } catch(e) { console.error(e); }
        },

        async toggleNotify(target) {
            try {
                const currentState = target === 'email' ? this.notify.email : this.notify.webhook;
                const res = await fetch('/api/notify_toggle', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ target: target, state: !currentState })
                });
                if (res.ok) this.loadNotifyStatus();
            } catch(e) { console.error(e); }
        },

        async muteAlerts() {
            try {
                const body = this.notify.muted ? { mute: false } : { mute: true, minutes: 60 };
                const res = await fetch('/api/notify_mute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(body)
                });
                if(res.ok) this.loadNotifyStatus();
            } catch(e) { console.error(e); }
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
            if (card.getAttribute('draggable') === 'true') return;
            card.setAttribute('draggable', 'true');
            if (!card.dataset.widgetId) card.dataset.widgetId = this.computeWidgetId(card, gridId);
            card.addEventListener('dragstart', () => { card.classList.add('dragging'); });
            card.addEventListener('dragend', () => {
                card.classList.remove('dragging');
                const grid = card.closest('.grid[data-grid-id]');
                if (grid) {
                    const gid = grid.getAttribute('data-grid-id');
                    this.saveGridOrder(grid, gid);
                }
            });
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
            try { localStorage.setItem('gridOrder:' + gridId, JSON.stringify(ids)); } catch(e) { console.error(e); }
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
            } catch(e) { console.error(e); }
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
             fetch('/api/test_alert').then(r=>r.json()).then(()=> {
                 // Trigger refresh immediately to show it
                 this.fetchAlerts();
             }).catch(console.error);
        },

        async refreshFeed() {
             fetch('/api/threat_refresh', {method:'POST'}).then(r=>r.json()).then(d => {
                 if(d.threat_status) this.threatStatus = d.threat_status;
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

        // Helpers
        fmtBytes(bytes) {
             if (bytes >= 1024**3) return (bytes / 1024**3).toFixed(2) + ' GB';
             if (bytes >= 1024**2) return (bytes / 1024**2).toFixed(2) + ' MB';
             if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
             return bytes + ' B';
        },

        flagFromIso(iso) {
            if (!iso || iso.length !== 2) return '🌐';
            return String.fromCodePoint(...[...iso.toUpperCase()].map(c => c.charCodeAt(0) + 127397));
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

        // Widget Management Methods
        loadWidgetPreferences() {
            // Merge saved prefs with defaults; default everything to visible for safety
            // Only include widgets that actually exist in the HTML template
            const defaults = {
                summary: true,
                bandwidth: true,
                firewall: true,
                analytics: true,
                topstats: true,
                flags: true,
                asns: true,
                countries: true,
                durations: true,
                packetSizes: true,
                sources: true,
                destinations: true,
                ports: true,
                protocols: true,
                threats: true,
                maliciousPorts: true,
                blocklist: true,
                feedHealth: true,
                securityScore: true,
                alertHistory: true,
                threatsByCountry: true,
                threatVelocity: true,
                topThreatIPs: true,
                conversations: true
            };
            try {
                const saved = JSON.parse(localStorage.getItem('widgetVisibility') || '{}');
                // Only apply saved preferences for widgets that exist in defaults
                // This filters out stale keys from previous versions
                const filteredSaved = {};
                for (const key of Object.keys(defaults)) {
                    if (key in saved) {
                        filteredSaved[key] = saved[key];
                    }
                }
                this.widgetVisibility = { ...defaults, ...filteredSaved };
            } catch (e) {
                console.error('widget prefs parse error', e);
                this.widgetVisibility = { ...defaults };
            }
            this.saveWidgetPreferences();
        },

        saveWidgetPreferences() {
            localStorage.setItem('widgetVisibility', JSON.stringify(this.widgetVisibility));
        },

        toggleWidget(widgetId) {
            this.widgetVisibility[widgetId] = !this.widgetVisibility[widgetId];
            this.saveWidgetPreferences();
        },

        toggleMinimize(widgetId) {
            if (this.minimizedWidgets.has(widgetId)) {
                this.minimizedWidgets.delete(widgetId);
            } else {
                this.minimizedWidgets.add(widgetId);
            }
            localStorage.setItem('minimizedWidgets', JSON.stringify([...this.minimizedWidgets]));
            this.$nextTick(() => {
                // Trigger chart redraw if needed
                if (widgetId === 'bandwidth' && this.bwChartInstance) {
                    this.bwChartInstance.resize();
                }
            });
        },

        isMinimized(widgetId) {
            return this.minimizedWidgets.has(widgetId);
        },

        isVisible(widgetId) {
            return this.widgetVisibility[widgetId] !== false;
        },

        getWidgetLabel(widgetId) {
            return this.friendlyLabels[widgetId] || widgetId;
        },

        resetWidgetPreferences() {
            if (confirm('Reset all widget settings to default?')) {
                // Clear all saved preferences first
                this.minimizedWidgets.clear();
                localStorage.removeItem('minimizedWidgets');
                localStorage.removeItem('widgetVisibility');
                // Reload defaults from scratch
                this.loadWidgetPreferences();
            }
        },

        async openIPModal(ip) {
            this.selectedIP = ip;
            this.modalOpen = true;
            this.ipLoading = true;
            this.ipDetails = null;
            try {
                const res = await fetch(`/api/ip_detail/${ip}`);
                if (res.ok) this.ipDetails = await res.json();
            } catch(e) { console.error(e); }
            this.ipLoading = false;
        },

        applyFilter(ip) {
            this.openIPModal(ip);
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
                'conversations': 'Recent Conversations (Top 100)'
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
            console.log('[Graph] openNetworkGraph called');
            console.log('[Graph] vis available:', typeof vis !== 'undefined', 'vis.Network:', typeof vis !== 'undefined' && vis?.Network ? 'yes' : 'no');
            this.networkGraphOpen = true;
            // Wait for modal transition
            setTimeout(() => {
                console.log('[Graph] Calling renderNetworkGraph after modal open');
                this.renderNetworkGraph();
            }, 100);
        },

        async renderNetworkGraph() {
            const container = document.getElementById('network-graph-container');
            if (!container) {
                console.error('[Graph] Container not found');
                return;
            }

            // Log container dimensions
            const rect = container.getBoundingClientRect();
            console.log('[Graph] Container dimensions:', rect.width, 'x', rect.height);

            // Check if vis library is loaded
            if (typeof vis === 'undefined' || !vis.Network) {
                console.error('[Graph] vis-network library not loaded');
                container.innerHTML = '<div style="color:var(--neon-red); text-align:center; padding-top:50px">vis-network library not loaded. Check console.</div>';
                return;
            }

            // Ensure container has dimensions (vis-network needs explicit size)
            if (rect.height < 100) {
                console.log('[Graph] Container too small, setting explicit height');
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
                        if(nodes.get(c.src).group === 'dest') nodes.get(c.src).group = 'both';
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
                        if(nodes.get(c.dst).group === 'source') nodes.get(c.dst).group = 'both';
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
                
                console.log('[Graph] Creating network with', data.nodes.length, 'nodes and', data.edges.length, 'edges');
                this.networkGraphInstance = new vis.Network(container, data, options);

                // Click handler
                this.networkGraphInstance.on("click", (params) => {
                    if (params.nodes.length > 0) {
                        const nodeId = params.nodes[0];
                        this.openIPModal(nodeId);
                    }
                });
                
                console.log('[Graph] Network created successfully');

            } catch (e) {
                console.error('[Graph] Error:', e);
                container.innerHTML = '<div style="color:var(--neon-red); text-align:center; padding-top:50px">Failed to load graph: ' + e.message + '</div>';
            }
        },

        // ----- Sparklines -----
        async renderSparklines(kind) {
            try {
                const canvases = Array.from(document.querySelectorAll(`canvas.spark[data-kind="${kind}"]`));
                if (!canvases.length) return;
                const range = (this.timeRange === '24h') ? '24h' : (this.timeRange === '6h' ? '6h' : '6h');
                for (const c of canvases) {
                    const ip = c.getAttribute('data-ip');
                    if (!ip) continue;
                    const cacheKey = `${kind}:${ip}:${range}`;
                    const now = Date.now();
                    const cached = this.sparkCache[cacheKey];
                    if (cached && (now - cached.ts) < this.sparkTTL) {
                        this.drawSparkline(c, cached.bytes);
                        continue;
                    }
                    // Fetch trend
                    const url = kind === 'source' ? `/api/trends/source/${ip}?range=${range}` : `/api/trends/dest/${ip}?range=${range}`;
                    fetch(url).then(r => r.json()).then(data => {
                        const arr = Array.isArray(data.bytes) ? data.bytes : [];
                        this.sparkCache[cacheKey] = { ts: now, bytes: arr };
                        this.drawSparkline(c, arr);
                    }).catch(()=>{});
                }
            } catch(e) { console.error(e); }
        },

        drawSparkline(canvas, values) {
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            const w = canvas.width, h = canvas.height;
            ctx.clearRect(0,0,w,h);
            if (!values || values.length === 0) return;
            const max = Math.max(...values, 1);
            const step = w / Math.max(values.length - 1, 1);
            // Gradient neon line
            const grad = ctx.createLinearGradient(0,0,w,0);
            grad.addColorStop(0, '#00f3ff');
            grad.addColorStop(1, '#bc13fe');
            ctx.strokeStyle = grad;
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            for (let i=0;i<values.length;i++) {
                const x = i * step;
                const y = h - (values[i]/max) * (h-2) - 1;
                if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
            }
            ctx.stroke();

                // Click to open trend modal
                if (!canvas._trendBound) {
                    canvas.addEventListener('click', (e) => {
                        e.stopPropagation();
                        const ip = canvas.getAttribute('data-ip');
                        const kind = canvas.getAttribute('data-kind') || 'source';
                        if (ip) this.openTrendModal(kind, ip);
                    });
                    canvas._trendBound = true;
                }
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
            } catch(e) { console.error(e); }
        },

        updateTrendChart(data) {
            const ctx = document.getElementById('ipTrendChart');
            if (!ctx || !data) return;
            const labels = data.labels || [];
            const values = data.bytes || [];
            const lineColor = '#00f3ff';
            if (this.trendChartInstance) {
                this.trendChartInstance.data.labels = labels;
                this.trendChartInstance.data.datasets[0].data = values;
                this.trendChartInstance.update();
            } else {
                this.trendChartInstance = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [{
                            label: 'Bytes (per 5 min)',
                            data: values,
                            borderColor: lineColor,
                            backgroundColor: 'rgba(0,243,255,0.15)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { labels: { color: '#e0e0e0' } } },
                        scales: {
                            x: { ticks: { color: '#888' }, grid: { color: '#333' } },
                            y: { ticks: { color: '#888' }, grid: { color: '#333' } }
                        }
                    }
                });
            }
        }
    }))

    // Scroll Spy Navigation Component
    Alpine.data('scrollSpy', () => ({
        sections: [
            { id: 'section-summary', label: 'Summary' },
            { id: 'section-worldmap', label: 'World Map' },
            { id: 'section-analytics', label: 'Analytics' },
            { id: 'section-topstats', label: 'Top Stats' },
            { id: 'section-security', label: 'Security' },
            { id: 'section-conversations', label: 'Conversations' }
        ],
        activeSection: 'section-summary',
        scrollProgress: 0,
        showScrollSpy: false,
        
        init() {
            // Debounced scroll handler
            let scrollTimeout;
            const handleScroll = () => {
                clearTimeout(scrollTimeout);
                scrollTimeout = setTimeout(() => this.updateScrollState(), 50);
            };
            
            window.addEventListener('scroll', handleScroll, { passive: true });
            
            // Initial state
            setTimeout(() => this.updateScrollState(), 100);
        },
        
        updateScrollState() {
            const scrollTop = window.scrollY;
            const docHeight = document.documentElement.scrollHeight - window.innerHeight;
            
            // Update progress
            this.scrollProgress = Math.min(100, (scrollTop / docHeight) * 100);
            
            // Show/hide based on scroll position
            this.showScrollSpy = scrollTop > 300;
            
            // Find active section
            let current = 'section-summary';
            for (const section of this.sections) {
                const el = document.getElementById(section.id);
                if (el) {
                    const rect = el.getBoundingClientRect();
                    if (rect.top <= 150) {
                        current = section.id;
                    }
                }
            }
            this.activeSection = current;
        },
        
        scrollToSection(sectionId) {
            const el = document.getElementById(sectionId);
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
    }));});