import { safeFetch } from './utils.js';

export const API = {
    latencyHistory: [],

    get avgLatency() {
        if (this.latencyHistory.length === 0) return null;
        return Math.round(this.latencyHistory.reduce((a, b) => a + b, 0) / this.latencyHistory.length);
    },

    async fetchWithLatency(url, options = {}) {
        const start = performance.now();
        try {
            const res = await safeFetch(url, { ...options, timeout: options.timeout || 30000 });
            const latency = Math.round(performance.now() - start);
            this.pushLatency(latency);
            return res;
        } catch (error) {
            const latency = Math.round(performance.now() - start);
            this.pushLatency(latency);
            throw error;
        }
    },

    pushLatency(latency) {
        this.latencyHistory.push(latency);
        if (this.latencyHistory.length > 10) {
            this.latencyHistory.shift();
        }
    },

    // API Endpoints
    async getPerformanceMetrics() {
        const res = await this.fetchWithLatency('/api/performance/metrics');
        return await res.json();
    },

    async getThresholds() {
        const res = await this.fetchWithLatency('/api/thresholds');
        return await res.json();
    },

    async saveThresholds(thresholds) {
        const res = await this.fetchWithLatency('/api/thresholds', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(thresholds)
        });
        return res.ok;
    },

    // Stats API
    async getStats(type, range, limit = 100) {
        const url = `/api/stats/${type}?range=${range}&limit=${limit}`;
        const res = await this.fetchWithLatency(url);
        return await res.json();
    }
};
