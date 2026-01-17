import { Store } from './js/store.js?v=3.0.12';
import * as DashboardUtils from './js/utils.js?v=3.0.3';
import { DashboardWidgets } from './js/widgets.js?v=3.0.4';

document.addEventListener('alpine:init', () => {
    // Make DashboardUtils available globally for templates
    window.DashboardUtils = DashboardUtils;
    
    // Register main dashboard store
    Alpine.data('dashboard', Store);
});