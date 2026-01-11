/**
 * Lazy Loading Module for Charts and Maps
 * Uses IntersectionObserver to load heavy visualizations only when visible
 */

window.LazyLoader = {
    observers: new Map(),
    
    /**
     * Initialize lazy loading for a chart container
     * @param {string} containerId - ID of the chart container element
     * @param {Function} loadCallback - Function to call when element becomes visible
     * @param {Object} options - IntersectionObserver options
     */
    observe(containerId, loadCallback, options = {}) {
        const defaultOptions = {
            root: null,
            rootMargin: '50px', // Start loading 50px before visible
            threshold: 0.01
        };
        
        const observerOptions = { ...defaultOptions, ...options };
        
        // Clean up existing observer if present
        this.unobserve(containerId);
        
        const element = document.getElementById(containerId);
        if (!element) {
            console.warn(`[LazyLoader] Container ${containerId} not found`);
            return;
        }
        
        // Mark as not loaded
        element.dataset.lazyLoaded = 'false';
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting && entry.target.dataset.lazyLoaded === 'false') {
                    entry.target.dataset.lazyLoaded = 'true';
                    
                    // Add loading class for styling
                    entry.target.classList.add('lazy-loading');
                    
                    // Call the load callback
                    if (typeof loadCallback === 'function') {
                        loadCallback();
                    }
                    
                    // Stop observing once loaded
                    observer.unobserve(entry.target);
                    this.observers.delete(containerId);
                }
            });
        }, observerOptions);
        
        observer.observe(element);
        this.observers.set(containerId, observer);
    },
    
    /**
     * Stop observing an element
     */
    unobserve(containerId) {
        const observer = this.observers.get(containerId);
        if (observer) {
            const element = document.getElementById(containerId);
            if (element) {
                observer.unobserve(element);
            }
            this.observers.delete(containerId);
        }
    },
    
    /**
     * Clean up all observers
     */
    cleanup() {
        this.observers.forEach((observer, containerId) => {
            const element = document.getElementById(containerId);
            if (element) {
                observer.unobserve(element);
            }
        });
        this.observers.clear();
    }
};
