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
            # We inject style to force show content if needed, but let's try natural wait first
            try:
                page.wait_for_selector(".container", state="visible", timeout=3000)
            except:
                print("Container not visible, forcing display...")
                page.add_style_tag(content=".loading-screen { display: none !important; } .container { display: block !important; }")

            # Take a screenshot of the header area to visualize the issue
            page.screenshot(path="verification/layout_before.png")
            print("Screenshot taken: verification/layout_before.png")

            # Check for the broken "Recent Conversations" in header
            # It shouldn't be there. If it is, it's a bug.
            header_text = page.locator("header").text_content()
            if "Recent Conversations" in header_text:
                print("ISSUE FOUND: 'Recent Conversations' text found in header!")
            else:
                print("Header text looks okay (or issue not detected via text).")

            # Check for stray alert template text
            if "severity" in header_text: # x-text="severity" might not render text, but let's see
                print("ISSUE FOUND: Stray 'severity' text/logic potentially visible.")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            browser.close()

if __name__ == "__main__":
    verify_layout()
