#!/usr/bin/env python3
"""
IP Geolocation + ASN Lookup
------------------------------
Looks up geolocation and ASN (Autonomous System Number) info for an
IP address using ip-api.com's free endpoint (no API key required,
45 requests/minute rate limit on the free tier as of this writing —
check ip-api.com's docs since this can change).

Useful for recon: identifying hosting providers/cloud regions,
spotting CDN-fronted IPs, and building a picture of a target's
infrastructure footprint across multiple discovered IPs.

Usage:
    python ip_geolocation.py --ip 8.8.8.8
    python ip_geolocation.py --ip-list ips.txt
"""

import argparse
import sys
import time

import requests

API_URL = "http://ip-api.com/json/{ip}"
FIELDS = "status,message,country,regionName,city,zip,lat,lon,isp,org,as,asname,query"


def lookup_ip(ip, timeout):
    url = API_URL.format(ip=ip) + f"?fields={FIELDS}"
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"status": "fail", "message": str(e), "query": ip}


def print_result(data):
    ip = data.get("query", "?")
    if data.get("status") != "success":
        print(f"[!] {ip}: lookup failed — {data.get('message', 'unknown error')}")
        return

    print(f"[*] {ip}")
    print(f"    Location: {data.get('city', 'N/A')}, {data.get('regionName', 'N/A')}, {data.get('country', 'N/A')} ({data.get('zip', 'N/A')})")
    print(f"    Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
    print(f"    ISP: {data.get('isp', 'N/A')}")
    print(f"    Org: {data.get('org', 'N/A')}")
    print(f"    ASN: {data.get('as', 'N/A')} ({data.get('asname', 'N/A')})")


def main():
    parser = argparse.ArgumentParser(description="Look up geolocation and ASN info for one or more IPs (via ip-api.com, no key needed).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP address to look up")
    group.add_argument("--ip-list", help="File with one IP per line")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=1.5, help="Delay between requests in seconds when using --ip-list, to respect the free-tier rate limit (default: 1.5)")
    args = parser.parse_args()

    if args.ip:
        ips = [args.ip]
    else:
        try:
            with open(args.ip_list, "r", encoding="utf-8", errors="ignore") as f:
                ips = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"[!] Could not read --ip-list: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"[*] Looking up {len(ips)} IP(s)")
    print("-" * 60)

    for i, ip in enumerate(ips):
        data = lookup_ip(ip, args.timeout)
        print_result(data)
        print()
        if i < len(ips) - 1:
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
