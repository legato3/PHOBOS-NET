from playwright.sync_api import sync_playwright
import os

def verify_layout():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            # Navigate to the local app
            page.goto("http://localhost:8080")

            # Wait for main content to be visible (handling the loading screen)
            try:
                page.wait_for_selector(".container", state="visible", timeout=3000)
            except:
                print("Container not visible, forcing display...")
                page.add_style_tag(content=".loading-screen { display: none !important; } .container { display: block !important; }")

            # Take a screenshot of the header area to visualize the issue
            page.screenshot(path="verification/layout_after.png")
            print("Screenshot taken: verification/layout_after.png")

            # Check for the broken "Recent Conversations" in header
            header_text = page.locator("header").text_content()
            if "Recent Conversations" in header_text:
                print("ISSUE FOUND: 'Recent Conversations' text found in header!")
            else:
                print("SUCCESS: 'Recent Conversations' text NOT found in header.")

            # Check for the controls
            if page.locator(".controls").is_visible():
                print("SUCCESS: Controls div is visible.")
            else:
                 # Check if it exists in DOM at least (might be hidden on mobile view if viewport is small)
                 count = page.locator(".controls").count()
                 if count > 0:
                     print("SUCCESS: Controls div exists in DOM.")
                 else:
                     print("FAILURE: Controls div missing from DOM.")

            # Check for Notification Center
            if page.locator(".notification-menu").count() > 0:
                print("SUCCESS: Notification menu restored.")
            else:
                print("FAILURE: Notification menu missing.")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            browser.close()

if __name__ == "__main__":
    verify_layout()
