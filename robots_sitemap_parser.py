#!/usr/bin/env python3
"""
Robots.txt & Sitemap Parser
------------------------------
Fetches and parses a site's robots.txt and sitemap.xml — a classic
recon step, since Disallow entries often point at admin panels,
staging areas, or internal tools that the site owner didn't want
indexed (but which are still perfectly reachable if you just request
them directly), and sitemaps enumerate the site's structure for free.

Usage:
    python robots_sitemap_parser.py --url https://target.com
"""

import argparse
import re
import sys
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import requests

INTERESTING_KEYWORDS = [
    "admin", "wp-admin", "login", "internal", "staging", "test", "dev",
    "backup", "config", "private", "secret", "api", "debug", "manage",
    "dashboard", "console", "portal", "secure",
]


def fetch(url, timeout):
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            return resp.text
        return None
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def parse_robots_txt(content):
    disallowed = []
    allowed = []
    sitemaps = []
    current_agent = "*"

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            current_agent = value
        elif key == "disallow" and value:
            disallowed.append((current_agent, value))
        elif key == "allow" and value:
            allowed.append((current_agent, value))
        elif key == "sitemap":
            sitemaps.append(value)

    return disallowed, allowed, sitemaps


def flag_interesting(path):
    lower = path.lower()
    return [kw for kw in INTERESTING_KEYWORDS if kw in lower]


def parse_sitemap_xml(content, base_url, timeout, depth=0, max_depth=2):
    urls = []
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as e:
        print(f"[!] Could not parse sitemap XML: {e}", file=sys.stderr)
        return urls

    # Namespace-agnostic tag matching (sitemap XML typically uses a namespace)
    tag = lambda el: el.tag.rsplit("}", 1)[-1]

    for child in root:
        if tag(child) == "sitemap" and depth < max_depth:
            # Sitemap index file — recurse into nested sitemaps
            loc_el = next((c for c in child if tag(c) == "loc"), None)
            if loc_el is not None and loc_el.text:
                nested_content = fetch(loc_el.text.strip(), timeout)
                if nested_content:
                    urls.extend(parse_sitemap_xml(nested_content, base_url, timeout, depth + 1, max_depth))
        elif tag(child) == "url":
            loc_el = next((c for c in child if tag(c) == "loc"), None)
            if loc_el is not None and loc_el.text:
                urls.append(loc_el.text.strip())

    return urls


def main():
    parser = argparse.ArgumentParser(description="Parse a site's robots.txt and sitemap.xml for recon.")
    parser.add_argument("--url", required=True, help="Base site URL, e.g. https://target.com")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--sitemap-only", action="store_true", help="Skip robots.txt, only fetch/parse sitemap.xml")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    sitemap_urls_to_try = [urljoin(base + "/", "sitemap.xml")]

    if not args.sitemap_only:
        robots_url = urljoin(base + "/", "robots.txt")
        print(f"[*] Fetching {robots_url}")
        robots_content = fetch(robots_url, args.timeout)

        if robots_content is None:
            print("[*] No robots.txt found (or fetch failed).")
        else:
            disallowed, allowed, sitemaps = parse_robots_txt(robots_content)
            sitemap_urls_to_try = sitemaps if sitemaps else sitemap_urls_to_try

            print(f"[*] {len(disallowed)} Disallow entries, {len(allowed)} Allow entries, {len(sitemaps)} Sitemap reference(s)")
            print("-" * 60)

            for agent, path in disallowed:
                hits = flag_interesting(path)
                flag = f"  <-- interesting: {', '.join(hits)}" if hits else ""
                print(f"[Disallow] ({agent}) {path}{flag}")

            if sitemaps:
                print()
                for s in sitemaps:
                    print(f"[Sitemap ref] {s}")

    print()
    print("[*] Fetching sitemap(s)...")
    all_urls = []
    for sitemap_url in sitemap_urls_to_try:
        content = fetch(sitemap_url, args.timeout)
        if content is None:
            continue
        urls = parse_sitemap_xml(content, base, args.timeout)
        print(f"    {sitemap_url} -> {len(urls)} URL(s)")
        all_urls.extend(urls)

    if all_urls:
        print("-" * 60)
        print(f"[*] {len(all_urls)} total URL(s) found in sitemap(s):")
        for u in all_urls[:50]:
            print(f"    {u}")
        if len(all_urls) > 50:
            print(f"    ... and {len(all_urls) - 50} more")
    else:
        print("[*] No sitemap URLs found or sitemap unavailable.")


if __name__ == "__main__":
    main()
