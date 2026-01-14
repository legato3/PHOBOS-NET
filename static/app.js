import { Store } from './js/store.js?v=3.0.11';
import * as DashboardUtils from './js/utils.js?v=3.0.3';
import { DashboardWidgets } from './js/widgets.js?v=3.0.3';
import ScrollSpy from './js/components/scroll-spy.js?v=3.0.3';

// Expose globals for potential legacy script compatibility
window.DashboardUtils = DashboardUtils;
window.DashboardWidgets = DashboardWidgets;

// Register Service Worker for offline support
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/sw.js')
            .then(registration => {
                console.log('[SW] Service Worker registered:', registration.scope);
            })
            .catch(error => {
                console.warn('[SW] Service Worker registration failed:', error);
            });
    });
}

document.addEventListener('alpine:init', () => {
    // Register main dashboard store
    Alpine.data('dashboard', Store);

    // Scroll Spy Navigation Component
    Alpine.data('scrollSpy', ScrollSpy);
});