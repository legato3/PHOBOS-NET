
from playwright.sync_api import sync_playwright, expect

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("http://localhost:8080")

    # Wait for init
    page.wait_for_selector(".container", state="visible", timeout=10000)

    # Dismiss welcome modal if present
    try:
        # Wait a bit for modal to potentially appear
        page.wait_for_timeout(2000)
        if page.is_visible("text=Skip for Now"):
            page.click("text=Skip for Now")
            # Wait for modal to disappear
            page.wait_for_function("() => !document.querySelector('.modal[x-show=\"welcomeModalOpen\"]').style.display || document.querySelector('.modal[x-show=\"welcomeModalOpen\"]').style.display === 'none'")
    except Exception as e:
        print(f"Modal dismissal warning: {e}")

    # Click Network tab
    page.click("#network-tab-btn")

    # Wait for Network tab content
    page.wait_for_selector("#network-tab", state="visible")

    # Verify "Network Health" label (was System Status)
    # The label is: <div class="label">Network Health <span ...>
    # We can use text locator
    expect(page.locator("div.label").filter(has_text="Network Health").first).to_be_visible()

    # Verify "Total Flows" (was Active Flows)
    expect(page.locator("div.label").filter(has_text="Total Flows").first).to_be_visible()

    # Verify "Top Conversations" (was Top Talkers)
    # Top Conversations is a widget header h2 > span
    # Widget macro structure: <div class="card ..."> <div class="widget-header"> <h2> ... <span>Title</span> ...
    expect(page.locator("h2 span").filter(has_text="Top Conversations").first).to_be_visible()

    # Verify "Hourly Traffic" (was Traffic Volume)
    expect(page.locator("h2 span").filter(has_text="Hourly Traffic").first).to_be_visible()

    # Take screenshot
    page.screenshot(path="verification/verification.png")

    browser.close()

if __name__ == "__main__":
    with sync_playwright() as p:
        run(p)
