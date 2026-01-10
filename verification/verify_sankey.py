from playwright.sync_api import sync_playwright
import time
import os

def run():
    if not os.path.exists('verification'):
        os.makedirs('verification')

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_viewport_size({"width": 1920, "height": 1080})

        try:
            print("Navigating to dashboard...")
            page.goto("http://localhost:8080")

            # Helper: Force UI state ready
            page.add_style_tag(content="""
                .loading-screen { display: none !important; }
                .container { display: block !important; opacity: 1 !important; }
            """)

            print("Switching to Forensics tab...")
            page.click("button:has-text('Forensics')")
            time.sleep(1)

            print("Toggling Flow view...")
            # Use the ID we added
            page.click("#btn-view-flow")
            time.sleep(1)

            print("Checking canvas visibility...")
            # Check if canvas is visible
            is_visible = page.is_visible("#sankeyChart")

            if is_visible:
                print("SUCCESS: Sankey chart canvas is visible.")
            else:
                print("FAILURE: Sankey chart canvas not visible.")
                exit(1)

            page.screenshot(path="verification/sankey_final.png")
            print("Screenshot saved to verification/sankey_final.png")

        except Exception as e:
            print(f"Error: {e}")
            page.screenshot(path="verification/error_final.png")
            exit(1)
        finally:
            browser.close()

if __name__ == "__main__":
    run()
