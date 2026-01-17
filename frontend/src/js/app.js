import { Store } from './store/index.js?v=3.0.12';
import * as DashboardUtils from './modules/utils.js?v=3.0.3';
import { DashboardWidgets } from './modules/widgets.js?v=3.0.3';

const registerStore = () => {
    // Make DashboardUtils available globally for templates
    window.DashboardUtils = DashboardUtils;

    // Register main dashboard store
    Alpine.data('dashboard', Store);
};

// Robust initialization: Handle both race conditions
// 1. If Alpine is already loaded (script ran before module), register immediately
if (window.Alpine) {
    registerStore();
} else {
    // 2. If Alpine is not yet loaded, wait for init event
    document.addEventListener('alpine:init', registerStore);
}
