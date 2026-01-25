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
        if (!canvas || !canvas.getContext) return;

        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();

        // Update canvas resolution for maximum sharpness
        if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
        }

        const width = rect.width;
        const height = rect.height;

        ctx.resetTransform();
        ctx.scale(dpr, dpr);
        ctx.clearRect(0, 0, width, height);

        const validValues = values.filter(v => v !== null && v !== undefined);
        const max = 100;
        const range = max;

        // --- 1. DRAWER GRID (High Precision) ---
        ctx.lineWidth = 0.5;

        // Horizontal lines (Magnitude divisions)
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
        ctx.beginPath();
        for (let i = 1; i < 10; i++) { // More granular grid (every 10%)
            const y = Math.floor(height * (i / 10)) + 0.5;
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
        }
        ctx.stroke();

        // Major Horizontal lines (25%, 50%, 75%)
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
        ctx.beginPath();
        for (let i = 1; i < 4; i++) {
            const y = Math.floor(height * (i / 4)) + 0.5;
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
        }
        ctx.stroke();

        // Vertical lines (Time divisions - every 10m)
        ctx.setLineDash([1, 2]);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
        ctx.beginPath();
        for (let i = 1; i < 6; i++) {
            const x = Math.floor(width * (i / 6)) + 0.5;
            ctx.moveTo(x, 0);
            ctx.lineTo(x, height);
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // --- 2. LABELS (Technical Detail) ---
        ctx.fillStyle = 'rgba(255, 255, 255, 0.35)';
        ctx.font = '7px "JetBrains Mono", monospace';

        // Y-Axis Labels
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        ctx.fillText('100%', width - 4, 6);
        ctx.fillText('50%', width - 4, height / 2);
        ctx.fillText('0%', width - 4, height - 6);

        // X-Axis Labels
        ctx.textAlign = 'left';
        ctx.fillText('1h ago', 4, height - 4);
        ctx.textAlign = 'center';
        ctx.fillText('30m', width / 2, height - 4);
        ctx.textAlign = 'right';
        ctx.fillText('NOW', width - 4, height - 4);

        if (validValues.length < 2) return;

        // --- 3. DATA RENDERING ---
        const totalPoints = values.length;
        const getY = (v) => height - (v / range) * height;
        const points = values.map((v, i) => {
            if (v === null || v === undefined) return null;
            return {
                x: (i / Math.max(1, totalPoints - 1)) * width,
                y: getY(v)
            };
        }).filter(p => p !== null);

        // A. Area Fill (Gradient)
        ctx.beginPath();
        ctx.moveTo(points[0].x, height);
        points.forEach(p => ctx.lineTo(p.x, p.y));
        ctx.lineTo(points[points.length - 1].x, height);
        ctx.closePath();

        const gradient = ctx.createLinearGradient(0, 0, 0, height);
        gradient.addColorStop(0, color + '25'); // Subtle top glow
        gradient.addColorStop(0.5, color + '08');
        gradient.addColorStop(1, color + '00');
        ctx.fillStyle = gradient;
        ctx.fill();

        // B. Main Stroke
        ctx.beginPath();
        points.forEach((p, i) => {
            if (i === 0) ctx.moveTo(p.x, p.y);
            else ctx.lineTo(p.x, p.y);
        });
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.6;
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';

        // Precise glow
        ctx.shadowColor = color;
        ctx.shadowBlur = 4;
        ctx.stroke();
        ctx.shadowBlur = 0;

        // C. Latest Value Indicator
        const last = points[points.length - 1];
        if (last) {
            // Draw crosshair or point
            ctx.beginPath();
            ctx.arc(last.x, last.y, 2.5, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 0.8;
            ctx.stroke();

            // Floating value (More Info)
            ctx.fillStyle = '#fff';
            ctx.font = 'bold 10px "JetBrains Mono", monospace';
            ctx.textAlign = 'right';
            const val = validValues[validValues.length - 1];
            ctx.fillText(val.toFixed(1) + '%', width - 4, last.y - 8);
        }
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
