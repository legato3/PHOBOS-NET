
from playwright.sync_api import sync_playwright
import os

def run():
    # Get the absolute path to the templates/index.html file
    cwd = os.getcwd()
    template_path = os.path.join(cwd, 'templates', 'index.html')

    # We will use file:// protocol to load the local HTML since we modified it heavily
    # However, Alpine JS and other assets are loaded relative to /static/
    # So we might need to serve it or rely on the fact that file:// resolution of /static might fail or need help.
    # Actually, simpler to just run the python backend if possible, or serve static.
    # Given the memory instructions, I should try to run the app.
    # But wait, running the app might be complex with deps.
    # Let's try to serve the current directory with python http.server

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Access via localhost (assuming I start the server)
        try:
            page.goto('http://localhost:8080')

            # Inject CSS to force display since Alpine might not init without backend data
            page.add_style_tag(content=".loading-screen { display: none !important; } .container { display: block !important; opacity: 1 !important; }")

            # Wait for tabs to appear
            page.wait_for_selector('.tabs', timeout=5000)

            # Take screenshot of Overview
            page.screenshot(path='verification/overview_tab.png', full_page=True)

            # Click Security Tab
            page.click('button:has-text("Security")')
            page.wait_for_timeout(500)
            page.screenshot(path='verification/security_tab.png', full_page=True)

            # Click Network Tab
            page.click('button:has-text("Network")')
            page.wait_for_timeout(500)
            page.screenshot(path='verification/network_tab.png', full_page=True)

            # Click Forensics Tab and Toggle Sankey
            page.click('button:has-text("Forensics")')
            page.wait_for_timeout(500)
            # Find the Sankey toggle button (icon-btn-small with specific path or title)
            # Using title 'Sankey Flow' if I added it? The HTML has title='Sankey Flow'
            page.click('button[title="Sankey Flow"]')
            page.wait_for_timeout(1000) # Wait for canvas render
            page.screenshot(path='verification/forensics_sankey.png', full_page=True)

        except Exception as e:
            print(f'Error: {e}')
            # Fallback screenshot
            page.screenshot(path='verification/error.png')
        finally:
            browser.close()

if __name__ == '__main__':
    run()
