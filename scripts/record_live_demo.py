"""
scripts/record_live_demo.py
----------------------------
Records a high-quality demo video of the REAL Streamlit dashboard
running with a live Gemini API key — the LLM actually decides tool calls.

Usage:
    set GOOGLE_API_KEY=AIza...
    py -3.13 scripts/record_live_demo.py

Output: assets/sentinel_live_demo.webm
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
PORT       = 8503
URL        = f"http://localhost:{PORT}"
TMP_DIR    = os.path.join(ASSETS_DIR, "_live_video_tmp")


def wait_for_streamlit(url, timeout=60):
    print("  Waiting for Streamlit to start...")
    for i in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=2)
            print(f"  Ready after {i+1}s")
            return True
        except Exception:
            time.sleep(1)
    return False


async def wait_for_text(page, *texts, timeout=60000):
    """Wait until any of the given text strings appear on the page."""
    conditions = " || ".join(
        f'document.body.innerText.includes("{t}")' for t in texts
    )
    try:
        await page.wait_for_function(conditions, timeout=timeout)
        return True
    except Exception:
        return False


SCROLL_JS = """
(function(px) {{
    // Streamlit renders inside its own overflow container — target it directly
    const selectors = [
        '[data-testid="stAppViewContainer"]',
        '[data-testid="stMain"]',
        '.main',
        'section.main',
        'div.block-container',
    ];
    let el = null;
    for (const s of selectors) {{
        const found = document.querySelector(s);
        if (found && found.scrollHeight > found.clientHeight) {{
            el = found;
            break;
        }}
    }}
    if (el) {{
        el.scrollBy({{top: px, behavior: 'smooth'}});
    }} else {{
        window.scrollBy({{top: px, behavior: 'smooth'}});
    }}
}})({px});
"""

async def smooth_scroll_down(page, total_px=900, steps=20, delay_ms=70):
    """Smoothly scroll down inside Streamlit's scrollable container."""
    step_px = total_px // steps
    for _ in range(steps):
        await page.evaluate(SCROLL_JS.format(px=step_px))
        await page.wait_for_timeout(delay_ms)
    await page.wait_for_timeout(700)


async def smooth_scroll_top(page, steps=12, delay_ms=55):
    """Smoothly scroll back to the top of Streamlit's container."""
    for _ in range(steps):
        await page.evaluate(SCROLL_JS.format(px=-200))
        await page.wait_for_timeout(delay_ms)
    # Force back to very top
    await page.evaluate("""
        const selectors = [
            '[data-testid="stAppViewContainer"]',
            '[data-testid="stMain"]',
            '.main', 'section.main', 'div.block-container'
        ];
        for (const s of selectors) {
            const el = document.querySelector(s);
            if (el) { el.scrollTo({top: 0, behavior: 'smooth'}); break; }
        }
        window.scrollTo({top: 0, behavior: 'smooth'});
    """)
    await page.wait_for_timeout(600)


async def click_button(page, text, timeout=10000):
    try:
        btn = page.locator(f"button:has-text('{text}')").first
        await btn.wait_for(state="visible", timeout=timeout)
        await btn.scroll_into_view_if_needed()
        await btn.click()
        print(f"    clicked: '{text}'")
        return True
    except Exception as e:
        print(f"    warning: could not click '{text}': {e}")
        return False


async def select_scenario(page, option_text, timeout=10000):
    try:
        sb = page.locator('[data-testid="stSelectbox"]').first
        await sb.wait_for(state="visible", timeout=timeout)
        await sb.click()
        await page.wait_for_timeout(600)
        opt = page.locator(f'[role="option"]:has-text("{option_text}")').first
        await opt.wait_for(state="visible", timeout=4000)
        await opt.click()
        await page.wait_for_timeout(500)
        print(f"    selected: '{option_text}'")
        return True
    except Exception as e:
        print(f"    warning: could not select '{option_text}': {e}")
        return False


async def click_tab(page, name, timeout=8000):
    try:
        tab = page.get_by_role("tab", name=name).first
        await tab.wait_for(state="visible", timeout=timeout)
        await tab.click()
        await page.wait_for_timeout(1000)
        return True
    except Exception as e:
        print(f"    warning: could not click tab '{name}': {e}")
        return False


async def disable_demo_mode(page):
    """Turn off the Demo Mode toggle so Live Mode is active."""
    try:
        # Streamlit toggle has data-testid="stCheckbox" or label text
        toggle = page.locator('label:has-text("Demo Mode")').first
        await toggle.wait_for(state="visible", timeout=5000)
        # Check if it's currently ON by looking for checked state
        checkbox = page.locator('[data-testid="stCheckbox"] input[type="checkbox"]').first
        is_checked = await checkbox.is_checked()
        if is_checked:
            await toggle.click()
            await page.wait_for_timeout(800)
            print("    Demo Mode turned OFF (Live Mode active)")
        else:
            print("    Demo Mode already OFF (Live Mode active)")
    except Exception as e:
        print(f"    warning: could not toggle demo mode: {e}")


async def type_api_key(page, api_key):
    """Enter the API key into the Streamlit text input."""
    try:
        # Find the API key input (password type)
        inp = page.locator('input[type="password"]').first
        await inp.wait_for(state="visible", timeout=8000)
        await inp.click()
        await inp.fill(api_key)
        await page.wait_for_timeout(800)
        print("    API key entered")
        return True
    except Exception as e:
        print(f"    warning: could not type API key: {e}")
        return False


async def record_live_demo(api_key: str):
    from playwright.async_api import async_playwright

    os.makedirs(TMP_DIR, exist_ok=True)

    # ── Start Streamlit with the API key in environment ──────────────────────
    print(f"Starting Streamlit on port {PORT}...")
    env = os.environ.copy()
    env["GOOGLE_API_KEY"]                     = api_key
    env["STREAMLIT_SERVER_HEADLESS"]          = "true"
    env["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"

    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", DASH_PATH,
         f"--server.port={PORT}",
         "--server.headless=true",
         "--server.address=localhost",
         "--browser.gatherUsageStats=false"],
        cwd=ROOT_DIR, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    if not wait_for_streamlit(URL):
        print("ERROR: Streamlit failed to start")
        proc.terminate()
        return

    time.sleep(4)

    # ── Record ───────────────────────────────────────────────────────────────
    print("Starting Playwright recording (1280x720)...")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            color_scheme="dark",
            record_video_dir=TMP_DIR,
            record_video_size={"width": 1280, "height": 720},
        )
        page = await context.new_page()

        # ── SCENE 1: Landing page ─────────────────────────────────────────────
        print("\n[Scene 1] Dashboard landing page...")
        await page.goto(URL, wait_until="networkidle", timeout=40000)
        await page.wait_for_timeout(5000)          # hold on landing page

        # ── SCENE 2: Enter API key + disable Demo Mode ────────────────────────
        print("[Scene 2] Entering API key and enabling Live Mode...")
        await type_api_key(page, api_key)
        await page.wait_for_timeout(1000)
        await disable_demo_mode(page)
        await page.wait_for_timeout(2000)

        # ── SCENE 3: Architecture tab ─────────────────────────────────────────
        print("[Scene 3] Architecture tab...")
        await click_tab(page, "Architecture")
        await page.wait_for_timeout(6000)          # show diagram

        # ── SCENE 4: Demo tab — Financial Fraud (MOST IMPORTANT) ─────────────
        print("[Scene 4] Financial Fraud scenario (live LLM)...")
        await click_tab(page, "Live Demo")
        await page.wait_for_timeout(1500)

        await select_scenario(page, "Financial Fraud")
        await page.wait_for_timeout(2000)          # show attack description

        await click_button(page, "Run Live Demo")
        await page.wait_for_timeout(500)
        print("    Waiting for LLM + Sentinel verdict (up to 60s)...")
        found = await wait_for_text(page, "BLOCK", "ALLOW", "TAINTED", "blocked_by_sentinel",
                                    "503", "429", timeout=90000)
        await page.wait_for_timeout(2000)          # brief pause before scroll
        await smooth_scroll_down(page, total_px=800)  # scroll to show all verdict cards
        await page.wait_for_timeout(4000)          # hold on BLOCK verdict
        await smooth_scroll_top(page)              # back to top for next scenario

        # ── SCENE 5: Payment Approval — HITL (second most important) ─────────
        print("[Scene 5] Payment Approval HITL scenario (live LLM)...")
        await select_scenario(page, "Payment Approval")
        await page.wait_for_timeout(2000)

        await click_button(page, "Run Live Demo")
        await page.wait_for_timeout(500)
        print("    Waiting for HITL AUTH verdict (up to 60s)...")
        found = await wait_for_text(page, "AUTH", "AWAITING", "Approve", "BLOCK", "ALLOW",
                                    timeout=90000)
        await page.wait_for_timeout(1500)
        await smooth_scroll_down(page, total_px=600)  # scroll to show AUTH card
        await page.wait_for_timeout(2000)          # hold on AUTH verdict

        # Try clicking Approve if the panel appeared
        approved = await click_button(page, "Approve")
        if approved:
            await page.wait_for_timeout(500)
            print("    Waiting for approved result...")
            await wait_for_text(page, "ALLOW", "approved", "executed", timeout=60000)
            await smooth_scroll_down(page, total_px=400)  # scroll to show approved result
            await page.wait_for_timeout(4000)      # hold on approved result
        await smooth_scroll_top(page)

        # ── SCENE 6: Prompt Injection ──────────────────────────────────────────
        print("[Scene 6] Prompt Injection scenario (live LLM)...")
        await select_scenario(page, "Prompt Injection")
        await page.wait_for_timeout(1500)

        await click_button(page, "Run Live Demo")
        await page.wait_for_timeout(500)
        print("    Waiting for TAINTED + BLOCK verdict (up to 60s)...")
        await wait_for_text(page, "TAINTED", "BLOCK", "ALLOW", timeout=90000)
        await page.wait_for_timeout(1500)
        await smooth_scroll_down(page, total_px=900)  # scroll to show taint alert + block
        await page.wait_for_timeout(4000)          # hold so viewer can read
        await smooth_scroll_top(page)

        # ── SCENE 7: Data Exfiltration ─────────────────────────────────────────
        print("[Scene 7] Data Exfiltration scenario (live LLM)...")
        await select_scenario(page, "Data Exfiltration")
        await page.wait_for_timeout(1500)

        await click_button(page, "Run Live Demo")
        await page.wait_for_timeout(500)
        print("    Waiting for BLOCK verdict (up to 60s)...")
        await wait_for_text(page, "BLOCK", "ALLOW", timeout=90000)
        await page.wait_for_timeout(1500)
        await smooth_scroll_down(page, total_px=800)  # scroll to show block verdict
        await page.wait_for_timeout(4000)          # hold on final verdict

        # ── Close ──────────────────────────────────────────────────────────────
        print("\nClosing and saving video...")
        await context.close()
        await browser.close()

    proc.terminate()
    print("Streamlit stopped.")

    # Move the video
    webm_files = glob.glob(os.path.join(TMP_DIR, "*.webm"))
    if webm_files:
        dest = os.path.join(ASSETS_DIR, "sentinel_live_demo.webm")
        shutil.move(webm_files[0], dest)
        shutil.rmtree(TMP_DIR, ignore_errors=True)
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        print(f"\nVideo saved: assets/sentinel_live_demo.webm ({size_mb:.1f} MB)")
        print("Upload to YouTube (Unlisted) and add the link to Kaggle.")
    else:
        print("ERROR: no .webm found. Check", TMP_DIR)


if __name__ == "__main__":
    api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    if not api_key:
        print("ERROR: Set your API key first:")
        print("  $env:GOOGLE_API_KEY = 'AIza...'")
        print("  py -3.13 scripts/record_live_demo.py")
        sys.exit(1)
    print(f"Using API key: {api_key[:8]}...{api_key[-4:]}")
    asyncio.run(record_live_demo(api_key))
