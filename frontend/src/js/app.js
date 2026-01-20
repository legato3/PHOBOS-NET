import { Store } from './store/index.js?v=3.0.13';
import * as DashboardUtils from './modules/utils.js?v=3.0.3';
import { DashboardWidgets } from './modules/widgets.js?v=3.0.4';

const initApp = () => {
    // Make DashboardUtils available globally for templates
    window.DashboardUtils = DashboardUtils;

    // Register main dashboard store
    Alpine.data('dashboard', Store);
};

if (window.Alpine) {
    initApp();
} else {
    document.addEventListener('alpine:init', initApp);
}