#!/usr/bin/env python3
"""
Email Harvester
----------------
Extracts email addresses from a page (and optionally same-domain
linked pages, one level deep) for OSINT/recon purposes — e.g. building
a target list for an authorized phishing-simulation engagement, or
checking what internal addresses are publicly exposed.

Intended for use ONLY against systems you own or are explicitly
authorized to test, and only for lawful purposes.

Usage:
    python email_harvest.py --url https://target.com/about
    python email_harvest.py --url https://target.com --crawl --domain-filter target.com
"""

import argparse
import re
import sys
from urllib.parse import urljoin, urlparse

import requests

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

# Common obfuscation patterns seen on public pages
DEOBFUSCATE_PATTERNS = [
    (re.compile(r"\s*\[at\]\s*|\s*\(at\)\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s*\[dot\]\s*|\s*\(dot\)\s*", re.IGNORECASE), "."),
]


def deobfuscate(text):
    for pattern, replacement in DEOBFUSCATE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def fetch(url, timeout):
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def extract_emails(text):
    return set(EMAIL_RE.findall(deobfuscate(text)))


def extract_links(html, base_url, domain_filter):
    links = set()
    for match in LINK_RE.finditer(html):
        link = urljoin(base_url, match.group(1))
        if domain_filter and domain_filter not in urlparse(link).netloc:
            continue
        if urlparse(link).scheme in ("http", "https"):
            links.add(link.split("#")[0])
    return links


def main():
    parser = argparse.ArgumentParser(description="Harvest email addresses from a page (optionally crawling one level deep).")
    parser.add_argument("--url", required=True, help="Starting URL")
    parser.add_argument("--crawl", action="store_true", help="Also fetch same-domain links found on the page, one level deep")
    parser.add_argument("--domain-filter", help="Restrict crawling to links containing this domain (recommended with --crawl)")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to fetch when crawling (default: 20)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    parser.add_argument("--output", help="Write found emails to this file, one per line")
    args = parser.parse_args()

    if args.crawl and not args.domain_filter:
        print("[!] --crawl without --domain-filter can wander off-site. "
              "Add --domain-filter target.com to stay scoped.", file=sys.stderr)

    to_visit = [args.url]
    visited = set()
    all_emails = set()

    while to_visit and len(visited) < args.max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        html = fetch(url, args.timeout)
        if html is None:
            continue

        found = extract_emails(html)
        new = found - all_emails
        all_emails |= found
        if new:
            print(f"[*] {url} — {len(new)} new email(s)")
            for e in sorted(new):
                print(f"    {e}")

        if args.crawl:
            for link in extract_links(html, url, args.domain_filter):
                if link not in visited:
                    to_visit.append(link)

    print("-" * 60)
    print(f"[*] Pages visited: {len(visited)}")
    print(f"[*] Unique emails found: {len(all_emails)}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(all_emails)) + ("\n" if all_emails else ""))
            print(f"[*] Saved to {args.output}")
        except OSError as e:
            print(f"[!] Could not write output file: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
