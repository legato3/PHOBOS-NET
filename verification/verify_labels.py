import os
import time
import requests
from playwright.sync_api import sync_playwright, expect

def verify_labels():
    base_url = "http://localhost:3434"

    print("Launching Playwright...")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Set viewport large enough for desktop
        context = browser.new_context(viewport={'width': 1280, 'height': 800})

        # Ensure sidebar is expanded
        context.add_init_script("localStorage.setItem('sidebarCollapsed', '0');")

        page = context.new_page()

        # Go to home page
        print(f"Navigating to {base_url}")
        page.goto(base_url)

        # Wait for "Network" tab button and click it
        print("Clicking Network tab...")
        # Now sidebar text should be visible.
        # Use explicit locator to be safe
        page.locator(".sidebar-item-text", has_text="Network").click()

        # Wait for content to be visible
        page.wait_for_timeout(2000)

        print("Verifying labels...")

        # Verify "System Status" label
        if page.get_by_text("System Status").count() > 0:
            print("Verified: System Status")
        else:
            print("FAILED: System Status not found")

        # Verify "Traffic Volume (Top 5k Flows)"
        if page.get_by_text("Traffic Volume (Top 5k Flows)").count() > 0:
            print("Verified: Traffic Volume (Top 5k Flows)")
        else:
            print("FAILED: Traffic Volume (Top 5k Flows) not found")

        # Verify "TCP Flags (Sampled)"
        if page.get_by_text("TCP Flags (Sampled)").count() > 0:
            print("Verified: TCP Flags (Sampled)")
        else:
            print("FAILED: TCP Flags (Sampled) not found")

        # Verify "Network Intelligence (Sampled)"
        if page.get_by_text("Network Intelligence (Sampled)").count() > 0:
            print("Verified: Network Intelligence (Sampled)")
        else:
            print("FAILED: Network Intelligence (Sampled) not found")

        # Verify "Packet Sizes (Sampled)"
        if page.get_by_text("Packet Sizes (Sampled)").count() > 0:
            print("Verified: Packet Sizes (Sampled)")
        else:
            print("FAILED: Packet Sizes (Sampled) not found")

        # Verify "External Connections (Est.)"
        if page.get_by_text("External Connections (Est.)").count() > 0:
            print("Verified: External Connections (Est.)")
        else:
            print("FAILED: External Connections (Est.) not found")

        # Take screenshot
        os.makedirs("verification", exist_ok=True)
        page.screenshot(path="verification/network_labels.png", full_page=True)
        print("Screenshot saved to verification/network_labels.png")

        browser.close()

if __name__ == "__main__":
    verify_labels()
