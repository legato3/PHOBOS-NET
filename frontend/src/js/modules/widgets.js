/**
 * Widget Management Module
 * Handles widget visibility, minimization, and preferences
 */

export const DashboardWidgets = {
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
        securityObservability: true,
        alertHistory: true,
        threatsByCountry: true,
        threatVelocity: true,
        topThreatIPs: true,
        compromisedHosts: true,
        flows: true,
        worldmap: true,
        recentBlocks: true,
        ipInvestigation: true,
        flowSearch: true,
        alertCorrelation: true,
        // Removed: riskIndex: true, // Replaced with predictiveRisk in securityObservability
        mitreHeatmap: true,
        protocolAnomalies: true,
        attackTimeline: true,
        flowStats: true,
        protoMix: true,
        protocolHierarchy: true,
        trafficScatter: true,
        netHealth: true,
        talkers: true,
        services: true,
        hourlyTraffic: true,
        insights: true,
        serverHealth: true,
        server_cpu: true,
        server_memory: true,
        server_disk: true,
        server_netflow: true,
        server_syslog: true,
        server_database: true,
        server_system: true,
        server_process: true,
        server_network: true,
        server_cache: true
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
        securityObservability: 'Security Observability',
        alertHistory: 'Alert History',
        threatsByCountry: 'Threats by Country',
        threatVelocity: 'Threat Velocity',
        topThreatIPs: 'Top Threat IPs',
        compromisedHosts: 'At-Risk Internal Hosts',
        // Removed: riskIndex: 'Network Risk Index', // Replaced with predictiveRisk in securityObservability
        flows: 'Active Flows',
        talkers: 'Top Talkers',
        services: 'Top Services',
        hourlyTraffic: 'Traffic by Hour',
        flowStats: 'Flow Statistics',
        protoMix: 'Protocol Mix',
        protocolHierarchy: 'Protocol Hierarchy',
        trafficScatter: 'Traffic Distribution',
        netHealth: 'Network Health',
        insights: 'Traffic Insights',
        mitreHeatmap: 'MITRE ATT&CK Coverage',
        protocolAnomalies: 'Protocol Anomalies',
        attackTimeline: 'Attack Timeline',
        recentBlocks: 'Firewall Logs',
        ipInvestigation: 'IP Deep Dive',
        flowSearch: 'Advanced Flow Search',
        alertCorrelation: 'Alert Correlation',
        alertCorrelation: 'Alert Correlation',
        serverHealth: 'Server Health',
        server_cpu: 'CPU',
        server_memory: 'Memory',
        server_disk: 'Disk',
        server_netflow: 'NetFlow Status',
        server_syslog: 'Syslog Status',
        server_database: 'Database Status',
        server_system: 'System Info',
        server_process: 'Process Info',
        server_network: 'Network Info',
        server_cache: 'Cache Info'
    },

    // Load widget preferences from localStorage
    loadPreferences(context) {
        try {
            const saved = JSON.parse(localStorage.getItem('widgetVisibility') || '{}');
            const filteredSaved = {};
            // Merge: start with defaults, then apply saved preferences
            // But ensure new widgets are visible by default (if not explicitly hidden)
            context.widgetVisibility = { ...this.defaultVisibility };
            for (const key of Object.keys(this.defaultVisibility)) {
                if (key in saved) {
                    // Only apply saved preference if it exists
                    context.widgetVisibility[key] = saved[key];
                }
            }
            // Ensure new firewall widgets are visible if not in saved prefs
            const newWidgets = ['ipInvestigation', 'flowSearch', 'alertCorrelation'];
            newWidgets.forEach(widget => {
                if (!(widget in saved)) {
                    context.widgetVisibility[widget] = true;
                }
            });
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
        // Trigger chart redraw if needed (using $nextTick if available)
        const triggerResize = () => {
            if (widgetId === 'bandwidth' && context.bwChartInstance) {
                context.bwChartInstance.resize();
            } else if (widgetId === 'worldmap' && context.renderWorldMap) {
                // World map needs explicit render/invalidateSize when becoming visible
                context.renderWorldMap();
            } else if (['hourlyTraffic', 'flags', 'packetSizes'].includes(widgetId)) {
                // Resize generic charts if they exist
                const chartMap = {
                    'hourlyTraffic': 'hourlyChartInstance',
                    'flags': 'flagsChartInstance',
                    'packetSizes': 'pktSizeChartInstance'
                };
                const instanceName = chartMap[widgetId];
                if (context[instanceName]) context[instanceName].resize();
            }
        };

        if (context.$nextTick) {
            context.$nextTick(triggerResize);
        } else {
            // Fallback if $nextTick not available
            setTimeout(triggerResize, 50);
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
