document.addEventListener('alpine:init', () => {
    Alpine.data('dashboard', () => ({
        initDone: false,
        timeRange: '1h',
        refreshInterval: 30000,
        refreshTimer: null,
        paused: false,
        lastUpdate: '-',
        searchQuery: '',

        // Data Stores
        summary: { totals: { bytes_fmt: '...', flows: 0, avg_packet_size: 0 }, loading: true },
        sources: { sources: [], loading: true },
        destinations: { destinations: [], loading: true },
        ports: { ports: [], loading: true },
        protocols: { protocols: [], loading: true },
        alerts: { alerts: [], loading: true },
        bandwidth: { labels: [], bandwidth: [], flows: [], loading: true },
        conversations: { conversations: [], loading: true },

        // Settings / Status
        notify: { email: true, webhook: true, muted: false },
        threatStatus: { status: '', last_ok: 0 },

        // Modal
        modalOpen: false,
        selectedIP: null,
        ipDetails: null,
        ipLoading: false,

        chartInstance: null,

        init() {
            console.log('Neural Link Established.');
            this.initDone = true;
            this.loadAll();
            this.loadNotifyStatus();
            this.startTimer();

            // Watchers
            this.$watch('timeRange', () => {
                this.loadAll();
            });
            this.$watch('refreshInterval', () => {
                 this.startTimer();
            });
        },

        startTimer() {
            if (this.refreshTimer) clearInterval(this.refreshTimer);
            this.refreshTimer = setInterval(() => {
                if (!this.paused) this.loadAll();
            }, this.refreshInterval);
        },

        togglePause() {
            this.paused = !this.paused;
        },

        async loadAll() {
            this.lastUpdate = new Date().toLocaleTimeString();

            // Parallel Requests
            this.fetchSummary(); // Contains notify/threat status too usually, but split now.
            this.fetchBandwidth(); // Updates chart
            this.fetchSources();
            this.fetchDestinations();
            this.fetchPorts();
            this.fetchProtocols();
            this.fetchAlerts();
            this.fetchConversations();

            // Also refresh notify status occasionally
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
                const res = await fetch(`/api/stats/summary?range=${this.timeRange}`);
                if(res.ok) {
                    const data = await res.json();
                    this.summary = { ...data, loading: false };
                    if(data.threat_status) this.threatStatus = data.threat_status;
                }
            } catch(e) { console.error(e); }
        },

        async fetchSources() {
            this.sources.loading = true;
            try {
                const res = await fetch(`/api/stats/sources?range=${this.timeRange}`);
                if(res.ok) this.sources = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); }
        },

        async fetchDestinations() {
            this.destinations.loading = true;
            try {
                const res = await fetch(`/api/stats/destinations?range=${this.timeRange}`);
                if(res.ok) this.destinations = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); }
        },

        async fetchPorts() {
            this.ports.loading = true;
            try {
                const res = await fetch(`/api/stats/ports?range=${this.timeRange}`);
                if(res.ok) this.ports = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); }
        },

        async fetchProtocols() {
            this.protocols.loading = true;
            try {
                const res = await fetch(`/api/stats/protocols?range=${this.timeRange}`);
                if(res.ok) this.protocols = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); }
        },

        async fetchAlerts() {
            this.alerts.loading = true;
            try {
                const res = await fetch(`/api/alerts?range=${this.timeRange}`);
                if(res.ok) this.alerts = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); }
        },

        async fetchConversations() {
            this.conversations.loading = true;
            try {
                const res = await fetch(`/api/conversations`); // Uses fixed 1h usually
                if(res.ok) this.conversations = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); }
        },

        async fetchBandwidth() {
            this.bandwidth.loading = true;
            try {
                const res = await fetch(`/api/bandwidth`);
                if(res.ok) {
                    const data = await res.json();
                    this.bandwidth = { ...data, loading: false };
                    this.updateChart(data);
                }
            } catch(e) { console.error(e); }
        },

        updateChart(data) {
            const ctx = document.getElementById('bwChart');
            if (!ctx) return;

            // Cyberpunk Colors
            const colorArea = 'rgba(0, 243, 255, 0.2)'; // Cyan transparent
            const colorLine = '#00f3ff'; // Neon Cyan
            const colorFlows = '#bc13fe'; // Neon Purple

            if (this.chartInstance) {
                this.chartInstance.data.labels = data.labels;
                this.chartInstance.data.datasets[0].data = data.bandwidth;
                this.chartInstance.data.datasets[1].data = data.flows;
                this.chartInstance.update();
            } else {
                this.chartInstance = new Chart(ctx, {
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
                                fill: true, // Filled area
                                tension: 0.4,
                                yAxisID: 'y'
                            },
                            {
                                label: 'Flows/s',
                                data: data.flows,
                                borderColor: colorFlows,
                                backgroundColor: 'transparent', // Keep flows as line
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
                        plugins: {
                            legend: { labels: { color: '#e0e0e0' } }
                        },
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

        // --- Controls Logic ---

        async loadNotifyStatus() {
            try {
                const res = await fetch('/api/notify_status');
                if (res.ok) {
                    const d = await res.json();
                    // d = { email: bool, webhook: bool, mute_until: float }
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

        async sendTestAlert() {
             fetch('/api/test_alert').then(r=>r.json()).then(()=>alert('Test alert sent')).catch(console.error);
        },

        async refreshFeed() {
             fetch('/api/threat_refresh', {method:'POST'}).then(r=>r.json()).then(d => {
                 if(d.threat_status) this.threatStatus = d.threat_status;
                 alert('Feed refresh: ' + d.status);
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
        }
    }))
});
