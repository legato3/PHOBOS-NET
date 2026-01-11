/**
 * Utility Functions
 * Pure utility functions used throughout the application
 */

// Format bytes to human-readable string
function fmtBytes(bytes) {
    if (bytes >= 1024**3) return (bytes / 1024**3).toFixed(2) + ' GB';
    if (bytes >= 1024**2) return (bytes / 1024**2).toFixed(2) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return bytes + ' B';
}

// Format bytes (alias for compatibility)
function formatBytes(bytes) {
    return fmtBytes(bytes);
}

// Get time ago string from timestamp
function timeAgo(ts) {
    if (!ts) return '';
    const diff = Math.max(0, (Date.now() / 1000) - ts);
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

// Export utilities to global namespace
window.DashboardUtils = {
    fmtBytes,
    formatBytes,
    timeAgo,
    flagFromIso,
    getCssVar,
    computeRecentBlockStats
};
