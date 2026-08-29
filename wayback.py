#!/usr/bin/env python3
"""
Wayback URL Harvester
-----------------------
Pulls historical URLs for a domain from the Wayback Machine's CDX API.
Useful for recon: finding old/forgotten endpoints, parameters,
JS files, and admin panels that may still be live but unlinked.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python wayback.py --domain target.com
    python wayback.py --domain target.com --ext js --output js_urls.txt
    python wayback.py --domain target.com --keyword admin
"""

import argparse
import sys
from urllib.parse import urlencode

import requests

CDX_ENDPOINT = "http://web.archive.org/cdx/search/cdx"


def fetch_urls(domain, timeout, subdomains=True):
    match_type = "domain" if subdomains else "prefix"
    match_value = domain if subdomains else f"{domain.rstrip('/')}"
    params = {
        "url": match_value,
        "matchType": match_type,
        "output": "text",
        "fl": "original",
        "collapse": "urlkey",
    }
    query_url = f"{CDX_ENDPOINT}?{urlencode(params)}"
    try:
        resp = requests.get(query_url, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Request to Wayback CDX API failed: {e}", file=sys.stderr)
        sys.exit(1)

    lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
    return lines


def filter_urls(urls, ext=None, keyword=None):
    filtered = urls
    if ext:
        suffix = ext if ext.startswith(".") else f".{ext}"
        filtered = [u for u in filtered if u.lower().split("?")[0].endswith(suffix.lower())]
    if keyword:
        filtered = [u for u in filtered if keyword.lower() in u.lower()]
    return filtered


def main():
    parser = argparse.ArgumentParser(description="Harvest historical URLs for a domain from the Wayback Machine.")
    parser.add_argument("--domain", required=True, help="Target domain, e.g. target.com")
    parser.add_argument("--ext", help="Only show URLs ending in this extension, e.g. js, php, env")
    parser.add_argument("--keyword", help="Only show URLs containing this substring, e.g. admin, api, backup")
    parser.add_argument("--no-subdomains", action="store_true", help="Restrict to the exact domain, exclude subdomains")
    parser.add_argument("--output", help="Write results to this file, one URL per line")
    parser.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds (default: 30)")
    args = parser.parse_args()

    print(f"[*] Querying Wayback CDX API for: {args.domain}")
    urls = fetch_urls(args.domain, args.timeout, subdomains=not args.no_subdomains)
    print(f"[*] Retrieved {len(urls)} archived URLs")

    if args.ext or args.keyword:
        urls = filter_urls(urls, ext=args.ext, keyword=args.keyword)
        print(f"[*] {len(urls)} URLs after filtering")

    print("-" * 60)
    for u in urls:
        print(u)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(urls) + ("\n" if urls else ""))
            print(f"\n[*] Saved {len(urls)} URLs to {args.output}", file=sys.stderr)
        except OSError as e:
            print(f"[!] Could not write output file: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
