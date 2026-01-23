// Chart Management Module
// Assumes Chart.js is loaded globally via script tag (as it is currently)

export const Charts = {
    sparkCache: {},
    sparkTTL: 120000, // 2 minutes

    // Render sparklines on canvases
    renderSparklines(canvases, timeRange, fetchMetadataFn) {
        try {
            if (!canvases.length) return;
            const range = (timeRange === '24h') ? '24h' : (timeRange === '6h' ? '6h' : '6h');
            const now = Date.now();

            canvases.forEach(c => {
                const ip = c.getAttribute('data-ip');
                if (!ip) return;

                const kind = c.getAttribute('data-kind');
                const cacheKey = `${kind}:${ip}:${range}`;

                const cached = this.sparkCache[cacheKey];
                if (cached && (now - cached.ts) < this.sparkTTL) {
                    this.drawSparkline(c, cached.bytes, fetchMetadataFn);
                    return;
                }

                // Fetch trend
                const url = kind === 'source' ? `/api/trends/source/${ip}?range=${range}` : `/api/trends/dest/${ip}?range=${range}`;
                fetch(url).then(r => r.json()).then(data => {
                    const arr = Array.isArray(data.bytes) ? data.bytes : [];
                    this.sparkCache[cacheKey] = { ts: now, bytes: arr };
                    this.drawSparkline(c, arr, fetchMetadataFn);
                }).catch(() => { });
            });
        } catch (e) { console.error(e); }
    },

    drawSparkline(canvas, values, clickCallback) {
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width, h = canvas.height;
        ctx.clearRect(0, 0, w, h);
        if (!values || values.length === 0) return;

        const max = Math.max(...values, 1);
        const step = w / Math.max(values.length - 1, 1);

        // Gradient neon line
        const grad = ctx.createLinearGradient(0, 0, w, 0);
        grad.addColorStop(0, '#00f3ff');
        grad.addColorStop(1, '#bc13fe');

        ctx.strokeStyle = grad;
        ctx.lineWidth = 1.5;
        ctx.beginPath();

        for (let i = 0; i < values.length; i++) {
            const x = i * step;
            const y = h - (values[i] / max) * (h - 2) - 1;
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        }
        ctx.stroke();

        // Click handler
        if (!canvas._clickBound && clickCallback) {
            canvas.addEventListener('click', (e) => {
                e.stopPropagation();
                const ip = canvas.getAttribute('data-ip');
                const kind = canvas.getAttribute('data-kind') || 'source';
                if (ip) clickCallback(kind, ip);
            });
            canvas._clickBound = true;
        }
    },

    // Simple Sparkline (for Resource History)
    drawSimpleSparkline(canvas, values, color = '#00f3ff') {
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width, h = canvas.height;
        ctx.clearRect(0, 0, w, h);
        if (!values || values.length === 0) return;

        const max = Math.max(...values, 100); // Assume percentage 0-100 for resources
        const step = w / Math.max(values.length - 1, 1);

        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.beginPath();

        for (let i = 0; i < values.length; i++) {
            const x = i * step;
            const y = h - (values[i] / max) * (h - 2) - 1;
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        }
        ctx.stroke();
    },

    // Fullscreen Chart
    openFullscreen(chartInstance, title) {
        if (!chartInstance) return null;

        // We return the config to be used by the caller to create a new Chart instance
        const config = JSON.parse(JSON.stringify(chartInstance.config));
        config.options = config.options || {};
        config.options.responsive = true;
        config.options.maintainAspectRatio = false;

        return config;
    },

    // Update Trend Chart
    updateTrendChart(ctx, chartInstance, data) {
        if (!ctx || !data) return null;
        const labels = data.labels || [];
        const values = data.bytes || [];
        const lineColor = '#00f3ff';

        if (chartInstance) {
            chartInstance.data.labels = labels;
            chartInstance.data.datasets[0].data = values;
            chartInstance.update();
            return chartInstance;
        } else {
            return new Chart(ctx, {
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
};
