"""
scripts/record_full_demo.py
----------------------------
Records a ~90 second video of the REAL Streamlit dashboard running.
Shows the actual app UI, clicks buttons, runs scenarios, shows live verdicts.

Output: assets/sentinel_full_demo.webm

Run:
    py -3.13 scripts/record_full_demo.py
"""

import asyncio
import glob
import os
import shutil
import subprocess
import sys
import time
import urllib.request

THIS_DIR   = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR   = os.path.dirname(THIS_DIR)
ASSETS_DIR = os.path.join(ROOT_DIR, "assets")
DASH_PATH  = os.path.join(ROOT_DIR, "dashboard.py")
URL        = "http://localhost:8502"   # use 8502 to avoid conflict with any running instance
TMP_DIR    = os.path.join(ASSETS_DIR, "_video_full_tmp")


def wait_for_streamlit(url, timeout=45):
    print("  Waiting for Streamlit to start...")
    for i in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=2)
            print(f"  Ready after {i+1}s")
            return True
        except Exception:
            time.sleep(1)
    return False


async def safe_click_button(page, text_fragment, timeout=8000):
    """Click the first button whose text contains text_fragment."""
    try:
        btn = page.locator(f"button:has-text('{text_fragment}')").first
        await btn.wait_for(state="visible", timeout=timeout)
        await btn.scroll_into_view_if_needed()
        await btn.click()
        return True
    except Exception as e:
        print(f"    Warning: could not click '{text_fragment}': {e}")
        return False


async def safe_select_option(page, option_text, timeout=8000):
    """Select an option from the Streamlit selectbox."""
    try:
        # Click the selectbox to open it
        selectbox = page.locator('[data-testid="stSelectbox"]').first
        await selectbox.wait_for(state="visible", timeout=timeout)
        await selectbox.click()
        await page.wait_for_timeout(600)

        # Click the matching option
        option = page.locator(f'[role="option"]:has-text("{option_text}")').first
        await option.wait_for(state="visible", timeout=4000)
        await option.click()
        await page.wait_for_timeout(400)
        return True
    except Exception as e:
        print(f"    Warning: could not select '{option_text}': {e}")
        return False


async def click_tab(page, tab_name, timeout=8000):
    """Click a Streamlit tab by name."""
    try:
        tab = page.get_by_role("tab", name=tab_name).first
        await tab.wait_for(state="visible", timeout=timeout)
        await tab.click()
        await page.wait_for_timeout(800)
        return True
    except Exception as e:
        print(f"    Warning: could not click tab '{tab_name}': {e}")
        return False


async def wait_for_results(page, timeout=20000):
    """Wait for Sentinel verdict cards to appear."""
    try:
        await page.wait_for_function(
            "document.body.innerText.includes('ALLOW') || "
            "document.body.innerText.includes('BLOCK') || "
            "document.body.innerText.includes('AUTH') || "
            "document.body.innerText.includes('TAINTED')",
            timeout=timeout
        )
        return True
    except Exception:
        # Try waiting for spinner to disappear
        try:
            await page.wait_for_selector('[data-testid="stSpinner"]', state="hidden", timeout=timeout)
        except Exception:
            pass
        return False


async def record_full_demo():
    from playwright.async_api import async_playwright

    os.makedirs(TMP_DIR, exist_ok=True)

    # ── Start Streamlit ──────────────────────────────────────────────────────
    print("Starting Streamlit dashboard on port 8502...")
    env = os.environ.copy()
    env["STREAMLIT_SERVER_HEADLESS"] = "true"
    env["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"

    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", DASH_PATH,
         "--server.headless=true",
         "--server.port=8502",
         "--server.address=localhost",
         "--browser.gatherUsageStats=false"],
        cwd=ROOT_DIR, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    if not wait_for_streamlit(URL):
        print("ERROR: Streamlit failed to start")
        proc.terminate()
        return

    time.sleep(3)  # extra settle

    # ── Record ───────────────────────────────────────────────────────────────
    print("Starting Playwright video recording...")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--disable-web-security", "--no-sandbox"]
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            color_scheme="dark",
            record_video_dir=TMP_DIR,
            record_video_size={"width": 1280, "height": 720},
        )
        page = await context.new_page()

        # ── 1. Load dashboard (show hero / landing page) ─────────────────────
        print("  [1/7] Loading dashboard landing page...")
        await page.goto(URL, wait_until="networkidle", timeout=30000)
        await page.wait_for_timeout(4000)   # show the landing page

        # ── 2. Architecture tab ───────────────────────────────────────────────
        print("  [2/7] Clicking Architecture tab...")
        clicked = await click_tab(page, "Architecture")
        if not clicked:
            # Try finding any tab-like element containing "Architecture"
            await safe_click_button(page, "Architecture")
        await page.wait_for_timeout(5000)   # show architecture diagram

        # ── 3. Navigate to Demo tab ───────────────────────────────────────────
        print("  [3/7] Clicking Live Demo tab...")
        clicked = await click_tab(page, "Live Demo")
        if not clicked:
            await click_tab(page, "Demo")
        await page.wait_for_timeout(2000)

        # ── 4. Financial Fraud scenario ───────────────────────────────────────
        print("  [4/7] Running Financial Fraud scenario...")
        await safe_select_option(page, "Financial Fraud")
        await page.wait_for_timeout(1500)   # show the selected scenario description

        await safe_click_button(page, "Run Demo")
        await page.wait_for_timeout(500)
        print("    Waiting for BLOCK verdict...")
        await wait_for_results(page, timeout=15000)
        await page.wait_for_timeout(5000)   # show the BLOCK verdict clearly

        # ── 5. Payment Approval (HITL) scenario ──────────────────────────────
        print("  [5/7] Running Payment Approval (HITL) scenario...")
        await safe_select_option(page, "Payment Approval")
        await page.wait_for_timeout(1500)

        await safe_click_button(page, "Run Demo")
        await page.wait_for_timeout(500)
        print("    Waiting for AUTH verdict...")
        await wait_for_results(page, timeout=15000)
        await page.wait_for_timeout(3000)   # show the HITL approval panel

        # Click the Approve button if visible
        print("    Clicking Approve...")
        await safe_click_button(page, "Approve")
        await page.wait_for_timeout(500)
        await wait_for_results(page, timeout=10000)
        await page.wait_for_timeout(3000)   # show approved result

        # ── 6. Prompt Injection scenario ──────────────────────────────────────
        print("  [6/7] Running Prompt Injection scenario...")
        await safe_select_option(page, "Prompt Injection")
        await page.wait_for_timeout(1000)

        await safe_click_button(page, "Run Demo")
        await page.wait_for_timeout(500)
        await wait_for_results(page, timeout=15000)
        await page.wait_for_timeout(4000)   # show TAINTED + BLOCK

        # ── 7. Show Data Exfiltration scenario quickly ────────────────────────
        print("  [7/7] Running Data Exfiltration scenario...")
        await safe_select_option(page, "Data Exfiltration")
        await page.wait_for_timeout(800)

        await safe_click_button(page, "Run Demo")
        await page.wait_for_timeout(500)
        await wait_for_results(page, timeout=15000)
        await page.wait_for_timeout(4000)   # show BLOCK

        # ── Close and save ────────────────────────────────────────────────────
        print("  Closing context and saving video...")
        await context.close()
        await browser.close()

    proc.terminate()
    print("Streamlit stopped.")

    # Find and move the .webm file
    webm_files = glob.glob(os.path.join(TMP_DIR, "*.webm"))
    if webm_files:
        src  = webm_files[0]
        dest = os.path.join(ASSETS_DIR, "sentinel_full_demo.webm")
        shutil.move(src, dest)
        shutil.rmtree(TMP_DIR, ignore_errors=True)
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        print(f"\nVideo saved: assets/sentinel_full_demo.webm ({size_mb:.1f} MB)")
        print("Upload to YouTube as Unlisted, then add the link to Kaggle.")
    else:
        print("ERROR: no .webm found in", TMP_DIR)
        print("Files in tmp:", os.listdir(TMP_DIR) if os.path.exists(TMP_DIR) else "dir missing")


if __name__ == "__main__":
    print("Recording full Streamlit demo video...")
    asyncio.run(record_full_demo())
