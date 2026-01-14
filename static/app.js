import { Store } from './js/store.js?v=3.0.11';
import * as DashboardUtils from './js/utils.js?v=3.0.3';
import { DashboardWidgets } from './js/widgets.js?v=3.0.3';

document.addEventListener('alpine:init', () => {
    // Register main dashboard store
    Alpine.data('dashboard', Store);
});