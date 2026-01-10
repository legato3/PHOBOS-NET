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
        searchQuery: '',

        // Refresh countdown
        refreshCountdown: 30,
        countdownTimer: null,

        // Fetch cadence control
        lastHeavyFetch: 0,
        heavyTTL: 60000, // 60s for heavy widgets
        lastMediumFetch: 0,
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
        durations: { durations: [], loading: true },
        packetSizes: { labels: [], data: [], loading: true },
        feedHealth: { feeds: [], summary: { total: 0, ok: 0, error: 0, total_ips: 0 }, loading: true },
        
        // Security Features
        securityScore: { score: 100, grade: 'A', status: 'excellent', reasons: [], loading: true },
        alertHistory: { alerts: [], total: 0, by_severity: {}, loading: true },
        threatsByCountry: { countries: [], loading: true },
        watchlist: { watchlist: [], count: 0, loading: true },
        watchlistInput: '',
        alertHistoryOpen: false,
        watchlistModalOpen: false,
        threatVelocity: { current: 0, trend: 0, total_24h: 0, peak: 0, loading: true },
        topThreatIPs: { ips: [], loading: true },
        riskIndex: { score: 0, max_score: 100, level: 'LOW', color: 'green', factors: [], loading: true },

        // Settings / Status
        notify: { email: true, webhook: true, muted: false },
        threatStatus: { status: '', last_ok: 0 },
        dismissedAlerts: new Set(JSON.parse(localStorage.getItem('dismissedAlerts') || '[]')),
        
        // Widget Management
        widgetVisibility: {},
        minimizedWidgets: new Set(JSON.parse(localStorage.getItem('minimizedWidgets') || '[]')),
        widgetManagerOpen: false,

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
            conversations: 'Recent Conversations'
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

        bwChartInstance: null,
        flagsChartInstance: null,
        pktSizeChartInstance: null,
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
            this.initDone = true;
            this.loadWidgetPreferences();
            this.loadCompactMode();
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

        async loadAll() {
            this.lastUpdate = new Date().toLocaleTimeString();

            // Parallel Requests
            // Light endpoints (frequent)
            this.fetchSummary();
            this.fetchBandwidth();
            this.fetchSources();
            this.fetchDestinations();
            this.fetchPorts();
            this.fetchProtocols();
            this.fetchMaliciousPorts();
            this.fetchThreats();
            this.fetchBlocklistRate();
            this.fetchAlerts();
            if (!this.firewallStreamActive) this.fetchFirewall();

            // Medium endpoint cadence (e.g., conversations, feed health, security)
            const now = Date.now();
            if (now - this.lastMediumFetch > this.mediumTTL) {
                this.lastMediumFetch = now;
                this.fetchConversations();
                this.fetchFeedHealth();
                this.fetchSecurityScore();
                this.fetchAlertHistory();
                this.fetchThreatsByCountry();
                this.fetchWatchlist();
                this.fetchThreatVelocity();
                this.fetchTopThreatIPs();
                this.fetchRiskIndex();
            }

            // New Features
            if (now - this.lastHeavyFetch > this.heavyTTL) {
                this.lastHeavyFetch = now;
                // Stagger heavy calls slightly to avoid spikes
                setTimeout(() => this.fetchFlags(), 0);
                setTimeout(() => this.fetchASNs(), 150);
                setTimeout(() => this.fetchDurations(), 300);
                setTimeout(() => this.fetchCountries(), 375);
                setTimeout(() => this.fetchPacketSizes(), 450);
            }

            // Render sparklines for top IPs (throttled via sparkTTL)
            this.renderSparklines('source');
            this.renderSparklines('dest');

            this.loadNotifyStatus();
        },

        get filteredSources() {
             if(!this.searchQuery) return this.sources.sources;
             const q = this.searchQuery.toLowerCase();
             return this.sources.sources.filter(s => s.key.includes(q) || (s.hostname && s.hostname.includes(q)));
        },

        get filteredDestinations() {
             if(!this.searchQuery) return this.destinations.destinations;
             const q = this.searchQuery.toLowerCase();
             return this.destinations.destinations.filter(s => s.key.includes(q) || (s.hostname && s.hostname.includes(q)));
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
            const color = '#ff003c';
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

        async fetchDurations() {
            this.durations.loading = true;
            try {
                const res = await fetch(`/api/stats/durations?range=${this.timeRange}`);
                if(res.ok) this.durations = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.durations.loading = false; }
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
            const ctx = document.getElementById('bwChart');
            if (!ctx) return;

            const colorArea = 'rgba(0, 243, 255, 0.2)';
            const colorLine = '#00f3ff';
            const colorFlows = '#bc13fe';

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
            const ctx = document.getElementById('pktSizeChart');
            if (!ctx) return;

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
        },

        updateCountriesChart(data) {
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
        },

        updateFlagsChart(flagsData) {
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
            this.networkGraphOpen = true;
            // Wait for modal transition
            setTimeout(() => this.renderNetworkGraph(), 100);
        },

        async renderNetworkGraph() {
            const container = document.getElementById('network-graph-container');
            if (!container) return;

            // Clear previous
            container.innerHTML = '<div class="spinner" style="margin: 50px auto;"></div>';

            try {
                // Fetch top conversations
                const res = await fetch(`/api/conversations?range=${this.timeRange}&limit=100`);
                if (!res.ok) throw new Error("Failed to fetch graph data");
                const json = await res.json();
                const convs = json.conversations || [];

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
                this.networkGraphInstance = new vis.Network(container, data, options);

                // Click handler
                this.networkGraphInstance.on("click", (params) => {
                    if (params.nodes.length > 0) {
                        const nodeId = params.nodes[0];
                        // Optional: Open IP details on click?
                        // this.openIPModal(nodeId);
                        // Just highlighting for now is enough
                    }
                });

            } catch (e) {
                console.error(e);
                container.innerHTML = '<div style="color:var(--neon-red); text-align:center; padding-top:50px">Failed to load graph data</div>';
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
});
