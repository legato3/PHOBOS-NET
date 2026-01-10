import time
from playwright.sync_api import sync_playwright

def verify_layout():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={'width': 1280, 'height': 1024})
        page = context.new_page()

        try:
            print("Navigating to dashboard...")
            page.goto("http://localhost:8080")

            page.add_style_tag(content="""
                .loading-screen { display: none !important; }
                .container { display: block !important; opacity: 1 !important; visibility: visible !important; }
            """)

            time.sleep(2)

            # 1. Overview Tab
            print("Capturing Overview Tab...")
            page.screenshot(path="verification/tab_overview.png")

            # 2. Security Tab
            print("Switching to Security Tab...")
            # Use get_by_role to target the button specifically
            page.get_by_role("button", name="Security", exact=True).click()
            time.sleep(1)
            page.screenshot(path="verification/tab_security.png")

            # 3. Network Tab
            print("Switching to Network Tab...")
            page.get_by_role("button", name="Network", exact=True).click()
            time.sleep(1)
            page.screenshot(path="verification/tab_network.png")

            # 4. Forensics Tab
            print("Switching to Forensics Tab...")
            page.get_by_role("button", name="Forensics", exact=True).click()
            time.sleep(1)
            page.screenshot(path="verification/tab_forensics.png")

            print("Verification complete.")

        except Exception as e:
            print(f"Error during verification: {e}")
            page.screenshot(path="verification/error_state.png")
        finally:
            browser.close()

if __name__ == "__main__":
    verify_layout()
