/**
 * Widget Management Module
 * Handles widget visibility, minimization, and preferences
 */

window.DashboardWidgets = {
    // Default widget visibility settings
    defaultVisibility: {
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
        conversations: true,
        worldmap: true,
        recentBlocks: true
    },

    // Friendly labels for widgets
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
        attackTimeline: 'Attack Timeline',
        recentBlocks: 'Firewall Logs'
    },

    // Load widget preferences from localStorage
    loadPreferences(context) {
        try {
            const saved = JSON.parse(localStorage.getItem('widgetVisibility') || '{}');
            const filteredSaved = {};
            for (const key of Object.keys(this.defaultVisibility)) {
                if (key in saved) {
                    filteredSaved[key] = saved[key];
                }
            }
            context.widgetVisibility = { ...this.defaultVisibility, ...filteredSaved };
        } catch (e) {
            console.error('widget prefs parse error', e);
            context.widgetVisibility = { ...this.defaultVisibility };
        }
        this.savePreferences(context);
    },

    // Save widget preferences to localStorage
    savePreferences(context) {
        localStorage.setItem('widgetVisibility', JSON.stringify(context.widgetVisibility));
    },

    // Toggle widget visibility
    toggleWidget(context, widgetId) {
        context.widgetVisibility[widgetId] = !context.widgetVisibility[widgetId];
        this.savePreferences(context);
    },

    // Toggle widget minimization
    toggleMinimize(context, widgetId) {
        if (context.minimizedWidgets.has(widgetId)) {
            context.minimizedWidgets.delete(widgetId);
        } else {
            context.minimizedWidgets.add(widgetId);
        }
        localStorage.setItem('minimizedWidgets', JSON.stringify([...context.minimizedWidgets]));
        // Trigger chart redraw if needed (using $nextTick if available)
        if (context.$nextTick) {
            context.$nextTick(() => {
                if (widgetId === 'bandwidth' && context.bwChartInstance) {
                    context.bwChartInstance.resize();
                }
            });
        } else {
            // Fallback if $nextTick not available
            setTimeout(() => {
                if (widgetId === 'bandwidth' && context.bwChartInstance) {
                    context.bwChartInstance.resize();
                }
            }, 0);
        }
    },

    // Check if widget is minimized
    isMinimized(context, widgetId) {
        return context.minimizedWidgets.has(widgetId);
    },

    // Check if widget is visible
    isVisible(context, widgetId) {
        return context.widgetVisibility[widgetId] !== false;
    },

    // Get widget label
    getWidgetLabel(context, widgetId) {
        return this.friendlyLabels[widgetId] || widgetId;
    },

    // Reset widget preferences to defaults
    resetPreferences(context) {
        if (confirm('Reset all widget settings to default?')) {
            context.minimizedWidgets.clear();
            localStorage.removeItem('minimizedWidgets');
            localStorage.removeItem('widgetVisibility');
            this.loadPreferences(context);
        }
    }
};
