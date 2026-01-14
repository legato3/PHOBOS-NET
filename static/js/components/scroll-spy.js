export default () => ({
    sections: [
        { id: 'section-summary', label: 'Summary' },
        { id: 'section-worldmap', label: 'World Map' },
        { id: 'section-network', label: 'Network' },
        { id: 'section-security', label: 'Security' },
        { id: 'section-flows', label: 'Active Flows' }
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
});
