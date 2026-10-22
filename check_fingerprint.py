"""Throwaway diagnostic 2: why doesn't the search submit?"""
import sys

from playwright.sync_api import sync_playwright

EMAIL = sys.argv[1]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=False)
    page = browser.new_page(viewport={"width": 1440, "height": 1100}, user_agent=UA)
    page.goto("https://fingerprint.to/email-search", wait_until="load", timeout=45000)
    page.wait_for_timeout(4000)                      # let React hydrate

    print("--- inputs ---")
    for el in page.query_selector_all("input"):
        print("   type=", el.get_attribute("type"),
              "inputmode=", el.get_attribute("inputmode"),
              "placeholder=", repr(el.get_attribute("placeholder")),
              "visible=", el.is_visible())

    box = page.query_selector('input[inputmode="email"]')
    print("chosen input visible:", box.is_visible() if box else None)
    if box:
        box.click()
        box.type(EMAIL, delay=40)                    # real keystrokes
        print("value after typing:", repr(box.input_value()))

    print("--- buttons ---")
    for el in page.query_selector_all("button")[:12]:
        print("   ", repr((el.inner_text() or "").strip()[:30]),
              "type=", el.get_attribute("type"), "visible=", el.is_visible())

    print("--- pressing Enter ---")
    page.keyboard.press("Enter")
    for i in range(5):
        page.wait_for_timeout(4000)
        print(f"t+{(i + 1) * 4:>2}s url:", page.url,
              "| cards:", len(page.query_selector_all('[data-platform-card-root="true"]')),
              "| rows:", len(page.query_selector_all("tbody tr")),
              "| body chars:", len(page.inner_text("body")))

    input("\nWindow stays open — look at it, then press Enter.")
    browser.close()
