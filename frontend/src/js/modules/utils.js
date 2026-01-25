/**
 * Utility Functions
 * Pure utility functions used throughout the application
 */

// Format bytes to human-readable string
function fmtBytes(bytes) {
    if (bytes >= 1024 ** 3) return (bytes / 1024 ** 3).toFixed(2) + ' GB';
    if (bytes >= 1024 ** 2) return (bytes / 1024 ** 2).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return bytes + ' B';
}

// Format bytes (alias for compatibility)
function formatBytes(bytes) {
    return fmtBytes(bytes);
}

// Get time ago string from timestamp
function timeAgo(ts) {
    if (!ts || isNaN(ts)) return '—';
    const diff = Math.max(0, (Date.now() / 1000) - ts);
    if (isNaN(diff)) return '—';
    if (diff < 60) return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
}

// Convert ISO country code to flag emoji
function flagFromIso(iso) {
    if (!iso || iso.length !== 2) return '🌐';
    return String.fromCodePoint(...[...iso.toUpperCase()].map(c => c.charCodeAt(0) + 127397));
}

// Get CSS variable value
function getCssVar(name) {
    return getComputedStyle(document.body).getPropertyValue(name).trim();
}

// Compute statistics for recent firewall blocks
function computeRecentBlockStats(logs = []) {
    const stats = {
        total: logs.length,
        actions: { block: 0, reject: 0, pass: 0 },
        threats: 0,
        unique_src: 0,
        unique_dst: 0,
        blocks_last_hour: 0,
        passes_last_hour: 0
    };

    const cutoff = (Date.now() / 1000) - 3600;
    const srcSet = new Set();
    const dstSet = new Set();

    logs.forEach((log) => {
        const action = log.action;
        const ts = log.timestamp_ts || 0;
        if (stats.actions[action] !== undefined) stats.actions[action] += 1;
        if (log.is_threat) stats.threats += 1;
        if (log.src_ip) srcSet.add(log.src_ip);
        if (log.dst_ip) dstSet.add(log.dst_ip);
        if (ts >= cutoff) {
            if (action === 'pass') stats.passes_last_hour += 1;
            if (action === 'block' || action === 'reject') stats.blocks_last_hour += 1;
        }
    });

    stats.unique_src = srcSet.size;
    stats.unique_dst = dstSet.size;
    return stats;
}

// Enhanced error handling utilities
function getErrorMessage(error, defaultMessage = 'An error occurred') {
    if (!error) return defaultMessage;
    if (typeof error === 'string') return error;
    if (error.message) return error.message;
    if (error.error) return typeof error.error === 'string' ? error.error : defaultMessage;
    return defaultMessage;
}

function getUserFriendlyError(error, context = '') {
    const message = getErrorMessage(error);

    // Network errors
    if (message.includes('Failed to fetch') || message.includes('NetworkError')) {
        return context ? `Network error: Unable to ${context}. Please check your connection.` : 'Network error: Please check your connection.';
    }

    // Timeout errors
    if (message.includes('timeout') || message.includes('Timeout')) {
        return context ? `Request timeout: ${context} took too long. Please try again.` : 'Request timeout: Please try again.';
    }

    // 404 errors
    if (message.includes('404') || message.includes('Not Found')) {
        return context ? `Not found: ${context} is not available.` : 'Resource not found.';
    }

    // 500 errors
    if (message.includes('500') || message.includes('Internal Server Error')) {
        return context ? `Server error: ${context} failed. Please try again later.` : 'Server error: Please try again later.';
    }

    // Rate limiting
    if (message.includes('429') || message.includes('Rate limit')) {
        return 'Too many requests. Please wait a moment and try again.';
    }

    // Generic error
    return context ? `${context}: ${message}` : message;
}

// Request deduplication: track in-flight requests to prevent duplicates
const _inFlightRequests = new Map();

// Safe fetch with enhanced error handling and request deduplication
async function safeFetch(url, options = {}) {
    // Create request key for deduplication (URL + method)
    const requestKey = `${options.method || 'GET'}:${url}`;

    // If same request is already in flight, reuse the promise
    if (_inFlightRequests.has(requestKey)) {
        const cachedResponse = await _inFlightRequests.get(requestKey);
        // Return a fresh clone for each caller
        return cachedResponse.clone();
    }

    // Create new request promise
    const fetchPromise = (async () => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), options.timeout || 30000);

            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // Clone before reading body for error
                const errorClone = response.clone();
                let errorData;
                try {
                    errorData = await errorClone.json();
                } catch {
                    errorData = { error: `HTTP ${response.status}: ${response.statusText}` };
                }
                throw errorData;
            }

            // Return response (will be cloned when retrieved from cache)
            return response;
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('Request timeout: The request took too long to complete.');
            }
            throw error;
        } finally {
            // Remove from in-flight map when done (success or error)
            _inFlightRequests.delete(requestKey);
        }
    })();

    // Store in-flight request
    _inFlightRequests.set(requestKey, fetchPromise);

    return fetchPromise;
}

// Export utilities
export {
    fmtBytes,
    formatBytes,
    timeAgo,
    flagFromIso,
    getCssVar,
    computeRecentBlockStats,
    getErrorMessage,
    getUserFriendlyError,
    safeFetch
};

// Statistical Utilities
export function calculateAvg(history, key) {
    if (!history || !history.length) return '—';
    const valid = history.filter(h => h[key] !== null && h[key] !== undefined);
    if (!valid.length) return '—';
    const sum = valid.reduce((acc, curr) => acc + curr[key], 0);
    return (sum / valid.length).toFixed(1);
}

export function calculateMin(history, key) {
    if (!history || !history.length) return '—';
    const valid = history.filter(h => h[key] !== null && h[key] !== undefined);
    if (!valid.length) return '—';
    return Math.min(...valid.map(h => h[key])).toFixed(1);
}

