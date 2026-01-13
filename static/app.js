import { Store } from './js/store.js';
import * as DashboardUtils from './js/utils.js';
import { DashboardWidgets } from './js/widgets.js';

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
    Alpine.data('scrollSpy', () => ({
        sections: [
            { id: 'section-summary', label: 'Summary' },
            { id: 'section-worldmap', label: 'World Map' },
            { id: 'section-network', label: 'Network' },
            { id: 'section-security', label: 'Security' },
            { id: 'section-conversations', label: 'Conversations' }
        ],
        activeSection: 'section-summary',
        scrollProgress: 0,
        showScrollSpy: false,

        init() {
            // Debounced scroll handler
            let scrollTimeout;
            const handleScroll = () => {
                clearTimeout(scrollTimeout);
                scrollTimeout = setTimeout(() => this.updateScrollState(), 50);
            };

            window.addEventListener('scroll', handleScroll, { passive: true });

            // Initial state
            setTimeout(() => this.updateScrollState(), 100);
        },

        updateScrollState() {
            const scrollTop = window.scrollY;
            const docHeight = document.documentElement.scrollHeight - window.innerHeight;

            // Update progress
            this.scrollProgress = Math.min(100, (scrollTop / docHeight) * 100);

            // Show/hide based on scroll position
            this.showScrollSpy = scrollTop > 300;

            // Find active section
            let current = 'section-summary';
            for (const section of this.sections) {
                const el = document.getElementById(section.id);
                if (el) {
                    const rect = el.getBoundingClientRect();
                    if (rect.top <= 150) {
                        current = section.id;
                    }
                }
            }
            this.activeSection = current;
        },

        scrollToSection(sectionId) {
            const el = document.getElementById(sectionId);
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
    }));
});