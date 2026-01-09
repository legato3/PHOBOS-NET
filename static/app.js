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

        // Fetch cadence control
        lastHeavyFetch: 0,
        heavyTTL: 60000, // 60s for heavy widgets
        lastMediumFetch: 0,
        mediumTTL: 30000, // 30s for conversations

        // Low Power mode
        lowPower: false,

        // Sparkline cache
        sparkCache: {}, // { key: { ts, labels, bytes } }
        sparkTTL: 120000, // 2 minutes

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

        bwChartInstance: null,
        flagsChartInstance: null,
        pktSizeChartInstance: null,

        init() {
            console.log('Neural Link Established.');
            this.initDone = true;
            this.loadAll();
            this.loadNotifyStatus();
            this.loadThresholds();
            // Initialize drag-and-drop after DOM paints
            this.$nextTick(() => this.setupDragAndDrop());
            this.startTimer();

            // Start real-time firewall stream (SSE) if supported
            this.startFirewallStream();

            // Watchers
            this.$watch('timeRange', () => {
                this.loadAll();
            });
            this.$watch('refreshInterval', () => {
                 this.startTimer();
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
        },

        togglePause() {
            this.paused = !this.paused;
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
            this.fetchAlerts();
            if (!this.firewallStreamActive) this.fetchFirewall();

            // Medium endpoint cadence (e.g., conversations)
            const now = Date.now();
            if (now - this.lastMediumFetch > this.mediumTTL) {
                this.lastMediumFetch = now;
                this.fetchConversations();
            }

            // New Features
            if (now - this.lastHeavyFetch > this.heavyTTL) {
                this.lastHeavyFetch = now;
                // Stagger heavy calls slightly to avoid spikes
                setTimeout(() => this.fetchFlags(), 0);
                setTimeout(() => this.fetchASNs(), 150);
                setTimeout(() => this.fetchDurations(), 300);
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
        }
    }))
});
