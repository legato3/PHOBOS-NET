from playwright.sync_api import sync_playwright
import time

def verify_map():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Navigate to dashboard
        print("Navigating to dashboard...")
        page.goto("http://127.0.0.1:8080")

        # Wait for initialization
        print("Waiting for dashboard init...")
        page.wait_for_selector(".container", state="visible", timeout=10000)

        # Wait for map container
        print("Waiting for map container...")
        page.wait_for_selector("#world-map-svg", state="visible")

        # Check for Leaflet class (proof of initialization)
        print("Checking for Leaflet initialization...")
        try:
            page.wait_for_selector(".leaflet-container", state="attached", timeout=5000)
            print("SUCCESS: Leaflet container found.")
        except:
            print("ERROR: Leaflet container NOT found.")
            # Verify if SVG logic is still there (should not be)
            if "leaflet" in page.content().lower():
                print("Leaflet scripts are present in HTML.")
            else:
                print("Leaflet scripts NOT found in HTML.")

        # Take screenshot
        print("Taking screenshot...")
        page.screenshot(path="verification_map.png")

        browser.close()

if __name__ == "__main__":
    verify_map()
