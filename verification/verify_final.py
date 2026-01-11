from playwright.sync_api import sync_playwright

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_viewport_size({"width": 1600, "height": 1200})

        print("Navigating...")
        page.goto("http://localhost:8080/templates/index.html")

        # Inject CSS to show Network tab and hide others
        page.add_style_tag(content="""
            .loading-screen { display: none !important; }
            .container { display: block !important; opacity: 1 !important; }
            div[x-show="activeTab === 'overview'"] { display: none !important; }
            div[x-show="activeTab === 'security'"] { display: none !important; }
            div[x-show="activeTab === 'forensics'"] { display: none !important; }
            div[x-show="activeTab === 'network'"] { display: block !important; }
        """)

        # Mock Alpine to prevent errors and show widgets
        try:
            page.wait_for_function("() => window.Alpine !== undefined", timeout=2000)
            page.evaluate("""
                document.addEventListener('alpine:init', () => {
                    Alpine.data('dashboard', () => ({
                        initDone: true,
                        activeTab: 'network',
                        widgetVisibility: { sources: true, destinations: true, ports: true, asns: true, countries: true, talkers: true, services: true, hourlyTraffic: true, flags: true, durations: true, packetSizes: true, protocols: true, insights: true, flowStats: true, protoMix: true, netHealth: true },
                        minimizedWidgets: new Set(),
                        loading: false,
                        // Mock data objects
                        sources: { loading: false, sources: [] },
                        destinations: { loading: false, destinations: [] },
                        ports: { loading: false, ports: [] },
                        asns: { loading: false, asns: [] },
                        countries: { loading: false, labels: [], bytes: [] },
                        talkers: { loading: false, talkers: [] },
                        services: { loading: false, services: [] },
                        hourlyTraffic: { loading: false, labels: [], bytes: [] },
                        flags: { loading: false, flags: [] },
                        durations: { loading: false, durations: [] },
                        packetSizes: { loading: false, labels: [], data: [] },
                        protocols: { loading: false, protocols: [] },
                        flowStats: { loading: false, duration_dist: {} },
                        protoMix: { loading: false, labels: [], bytes: [] },
                        netHealth: { loading: false, indicators: [] },

                        isVisible(w) { return true; },
                        isMinimized(w) { return false; },
                        getWidgetLabel(w) { return w; },
                        openExpandedTable() {},
                        toggleMinimize() {},
                        openIPModal() {},
                        applyFilter() {},
                        openFullscreenChart() {}
                    }));
                });
            """)
        except:
            print("Alpine mock failed or timed out")

        page.screenshot(path="verification/final_layout.png", full_page=True)
        print("Screenshot saved")
        browser.close()

if __name__ == "__main__":
    run()
