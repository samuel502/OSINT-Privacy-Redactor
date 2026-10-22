"""Throwaway diagnostic: what does fingerprint.to actually do after a search?"""
import sys

from playwright.sync_api import sync_playwright

EMAIL = sys.argv[1]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=False)
    page = browser.new_page(viewport={"width": 1440, "height": 1100}, user_agent=UA)
    page.goto("https://fingerprint.to/email-search", wait_until="domcontentloaded", timeout=45000)
    page.wait_for_selector('input[inputmode="email"]', timeout=25000)

    print("BEFORE  url:", page.url,
          "| cards:", len(page.query_selector_all('[data-platform-card-root="true"]')),
          "| rows:", len(page.query_selector_all("tbody tr")))

    page.fill('input[inputmode="email"]', EMAIL)
    page.click('button[type="submit"]')

    for i in range(6):
        page.wait_for_timeout(5000)
        print(f"t+{(i + 1) * 5:>2}s  url:", page.url,
              "| cards:", len(page.query_selector_all('[data-platform-card-root="true"]')),
              "| rows:", len(page.query_selector_all("tbody tr")),
              "| body has 'verify':", "verify" in page.inner_text("body").lower())

    input("\nWindow stays open. Look at it, then press Enter to close.")
    browser.close()
