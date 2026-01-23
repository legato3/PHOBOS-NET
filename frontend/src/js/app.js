import { Store } from './store/index.js?v=3.0.15';
import * as DashboardUtils from './modules/utils.js?v=3.0.4';
import { DashboardWidgets } from './modules/widgets.js?v=3.0.4';
import { Charts } from './modules/charts.js?v=3.0.4';

const initApp = () => {
    // Make DashboardUtils available globally for templates
    window.DashboardUtils = DashboardUtils;

    // Expose Charts for inline sparklines (Used by server.html resource history)
    window.renderSparkline = (canvas, values, color) => {
        Charts.drawSimpleSparkline(canvas, values, color);
    };

    // Register main dashboard store
    Alpine.data('dashboard', Store);
};

if (window.Alpine) {
    initApp();
} else {
    document.addEventListener('alpine:init', initApp);
}