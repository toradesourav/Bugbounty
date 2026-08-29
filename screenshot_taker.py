#!/usr/bin/env python3
"""
Screenshot Taker
------------------
Visits a list of URLs with a headless browser and saves a screenshot
of each — the classic "visual recon" step for triaging a large list
of subdomains/hosts quickly (spot login pages, admin panels, default
install pages, error pages, etc. without opening each one by hand).

Requires Playwright + a browser binary:
    pip install playwright
    playwright install chromium

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python screenshot_taker.py --url https://target.com
    python screenshot_taker.py --url-list urls.txt --outdir shots/ --concurrency 5
"""

import argparse
import asyncio
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[!] Playwright not installed. Run:\n    pip install playwright\n    playwright install chromium", file=sys.stderr)
    sys.exit(1)


def safe_filename(url):
    parsed = urlparse(url)
    name = f"{parsed.netloc}{parsed.path}".strip("/")
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", name) or "root"
    return name[:150] + ".png"


async def capture(browser, url, outdir, timeout_ms, full_page):
    filename = safe_filename(url)
    outpath = outdir / filename
    page = await browser.new_page(viewport={"width": 1280, "height": 800})
    result = {"url": url, "file": None, "error": None, "status": None, "title": None}
    try:
        resp = await page.goto(url, timeout=timeout_ms, wait_until="networkidle")
        result["status"] = resp.status if resp else None
        result["title"] = await page.title()
        await page.screenshot(path=str(outpath), full_page=full_page)
        result["file"] = str(outpath)
    except Exception as e:
        result["error"] = str(e)
    finally:
        await page.close()
    return result


async def run(urls, outdir, concurrency, timeout_ms, full_page):
    outdir.mkdir(parents=True, exist_ok=True)
    results = []
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        semaphore = asyncio.Semaphore(concurrency)

        async def bound_capture(url):
            async with semaphore:
                return await capture(browser, url, outdir, timeout_ms, full_page)

        results = await asyncio.gather(*(bound_capture(u) for u in urls))
        await browser.close()
    return results


def load_urls(args):
    if args.url:
        return [args.url]
    try:
        with open(args.url_list, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Could not read --url-list: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Take screenshots of one or more target URLs for visual recon.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Single URL to screenshot")
    group.add_argument("--url-list", help="File with one URL per line")
    parser.add_argument("--outdir", default="screenshots", help="Output directory (default: ./screenshots)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent browser tabs (default: 5)")
    parser.add_argument("--timeout", type=int, default=15000, help="Per-page timeout in milliseconds (default: 15000)")
    parser.add_argument("--full-page", action="store_true", help="Capture the full scrollable page instead of just the viewport")
    args = parser.parse_args()

    urls = load_urls(args)
    outdir = Path(args.outdir)

    print(f"[*] Screenshotting {len(urls)} URL(s) -> {outdir}/  (concurrency: {args.concurrency})")
    print("-" * 60)

    results = asyncio.run(run(urls, outdir, args.concurrency, args.timeout, args.full_page))

    ok = 0
    for r in results:
        if r["error"]:
            print(f"[FAIL] {r['url']:<45} {r['error']}")
        else:
            ok += 1
            title = f' "{r["title"]}"' if r["title"] else ""
            print(f"[ OK ] {r['url']:<45} status={r['status']}{title} -> {r['file']}")

    print("-" * 60)
    print(f"[*] {ok}/{len(results)} screenshots saved to {outdir}/")


if __name__ == "__main__":
    main()
