#!/usr/bin/env python3
"""
Shodan API Tool
-----------------
A thin wrapper around the Shodan REST API for recon: look up
everything Shodan knows about a specific IP (open ports, banners,
vulns, org, location), or run a search query across Shodan's index.

Requires a Shodan API key (free tier available at https://shodan.io —
100 query credits/month on the free plan as of this writing, but
check Shodan's own pricing page since this changes).

Set your key via --api-key or the SHODAN_API_KEY environment variable
(preferred, so it doesn't end up in shell history).

Usage:
    export SHODAN_API_KEY="your_key_here"
    python shodan_tool.py host 1.2.3.4
    python shodan_tool.py search "apache country:IN"
    python shodan_tool.py search "product:MySQL port:3306" --limit 20
"""

import argparse
import os
import sys

import requests

BASE_URL = "https://api.shodan.io"


def get_api_key(cli_key):
    key = cli_key or os.environ.get("SHODAN_API_KEY")
    if not key:
        print("[!] No API key provided. Use --api-key or set the SHODAN_API_KEY environment variable.", file=sys.stderr)
        print("    Get a free key at https://account.shodan.io/register", file=sys.stderr)
        sys.exit(1)
    return key


def handle_api_error(resp):
    if resp.status_code == 401:
        print("[!] 401 Unauthorized — invalid API key.", file=sys.stderr)
    elif resp.status_code == 403:
        print("[!] 403 Forbidden — your API plan may not support this endpoint (e.g. search requires a paid/upgraded key on some plans).", file=sys.stderr)
    elif resp.status_code == 429:
        print("[!] 429 — rate limited or out of query credits for this period.", file=sys.stderr)
    else:
        print(f"[!] API returned HTTP {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
    sys.exit(1)


def cmd_host(args, api_key):
    url = f"{BASE_URL}/shodan/host/{args.ip}"
    try:
        resp = requests.get(url, params={"key": api_key}, timeout=args.timeout)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        handle_api_error(resp)

    data = resp.json()
    print(f"[*] IP: {data.get('ip_str')}")
    print(f"    Org: {data.get('org', 'N/A')}")
    print(f"    ISP: {data.get('isp', 'N/A')}")
    print(f"    Country: {data.get('country_name', 'N/A')}")
    print(f"    City: {data.get('city', 'N/A')}")
    print(f"    Open ports: {sorted(data.get('ports', []))}")

    hostnames = data.get("hostnames", [])
    if hostnames:
        print(f"    Hostnames: {', '.join(hostnames)}")

    vulns = data.get("vulns", [])
    if vulns:
        print(f"    [!] Known vulnerabilities (CVE): {', '.join(sorted(vulns))}")

    print()
    print("[*] Service banners:")
    for item in data.get("data", []):
        port = item.get("port")
        transport = item.get("transport", "tcp")
        product = item.get("product", "")
        version = item.get("version", "")
        banner_summary = f"{product} {version}".strip() or "(no product identified)"
        print(f"    {port}/{transport}  {banner_summary}")
        if args.show_banners:
            raw = (item.get("data") or "").strip()
            if raw:
                snippet = raw[:200] + ("..." if len(raw) > 200 else "")
                print(f"        {snippet}")


def cmd_search(args, api_key):
    url = f"{BASE_URL}/shodan/host/search"
    try:
        resp = requests.get(url, params={"key": api_key, "query": args.query, "limit": args.limit}, timeout=args.timeout)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        handle_api_error(resp)

    data = resp.json()
    total = data.get("total", 0)
    matches = data.get("matches", [])

    print(f"[*] Query: {args.query}")
    print(f"[*] Total results on Shodan: {total} (showing {len(matches)})")
    print("-" * 60)

    for m in matches:
        ip = m.get("ip_str", "?")
        port = m.get("port", "?")
        org = m.get("org", "N/A")
        product = m.get("product", "")
        location = f"{m.get('location', {}).get('country_name', '')}"
        print(f"{ip:<16} :{port:<6} {product:<20} {org:<25} {location}")


def main():
    parser = argparse.ArgumentParser(description="Query the Shodan API for host info or search results.")
    parser.add_argument("--api-key", help="Shodan API key (or set SHODAN_API_KEY env var, preferred)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")

    subparsers = parser.add_subparsers(dest="command", required=True)

    host_parser = subparsers.add_parser("host", help="Look up everything Shodan knows about a specific IP")
    host_parser.add_argument("ip", help="IP address to look up")
    host_parser.add_argument("--show-banners", action="store_true", help="Show raw service banner snippets")

    search_parser = subparsers.add_parser("search", help="Run a Shodan search query")
    search_parser.add_argument("query", help='Shodan search query, e.g. "apache country:IN"')
    search_parser.add_argument("--limit", type=int, default=10, help="Max results to show (default: 10)")

    args = parser.parse_args()
    api_key = get_api_key(args.api_key)

    if args.command == "host":
        cmd_host(args, api_key)
    elif args.command == "search":
        cmd_search(args, api_key)


if __name__ == "__main__":
    main()
