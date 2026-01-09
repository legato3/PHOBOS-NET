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

        // New Features Stores
        flags: { flags: [], loading: true },
        asns: { asns: [], loading: true },
        durations: { durations: [], loading: true },
        packetSizes: { labels: [], data: [], loading: true },

        // Settings / Status
        notify: { email: true, webhook: true, muted: false },
        threatStatus: { status: '', last_ok: 0 },
        dismissedAlerts: new Set(JSON.parse(localStorage.getItem('dismissedAlerts') || '[]')),

        // Modal
        modalOpen: false,
        selectedIP: null,
        ipDetails: null,
        ipLoading: false,

        bwChartInstance: null,
        flagsChartInstance: null,
        pktSizeChartInstance: null,

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
        },

        togglePause() {
            this.paused = !this.paused;
        },

        async loadAll() {
            this.lastUpdate = new Date().toLocaleTimeString();

            // Parallel Requests
            this.fetchSummary();
            this.fetchBandwidth();
            this.fetchSources();
            this.fetchDestinations();
            this.fetchPorts();
            this.fetchProtocols();
            this.fetchAlerts();
            this.fetchConversations();

            // New Features
            this.fetchFlags();
            this.fetchASNs();
            this.fetchDurations();
            this.fetchPacketSizes();

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
            } catch(e) { console.error(e); } finally { this.summary.loading = false; }
        },

        async fetchSources() {
            this.sources.loading = true;
            try {
                const res = await fetch(`/api/stats/sources?range=${this.timeRange}`);
                if(res.ok) this.sources = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.sources.loading = false; }
        },

        async fetchDestinations() {
            this.destinations.loading = true;
            try {
                const res = await fetch(`/api/stats/destinations?range=${this.timeRange}`);
                if(res.ok) this.destinations = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.destinations.loading = false; }
        },

        async fetchPorts() {
            this.ports.loading = true;
            try {
                const res = await fetch(`/api/stats/ports?range=${this.timeRange}`);
                if(res.ok) this.ports = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.ports.loading = false; }
        },

        async fetchProtocols() {
            this.protocols.loading = true;
            try {
                const res = await fetch(`/api/stats/protocols?range=${this.timeRange}`);
                if(res.ok) this.protocols = { ...(await res.json()), loading: false };
            } catch(e) { console.error(e); } finally { this.protocols.loading = false; }
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
        }
    }))
});
