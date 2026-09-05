#!/usr/bin/env python3
"""
Reverse IP Lookup
-------------------
Finds other domains hosted on the same IP address — useful recon for
shared-hosting targets, since a vulnerability in one site on a shared
IP sometimes provides a foothold, and it can reveal a company's other
properties that share infrastructure. Uses HackerTarget's free
reverse-IP API (no key required, rate-limited on the free tier).

Usage:
    python reverse_ip_lookup.py --ip 93.184.216.34
    python reverse_ip_lookup.py --domain target.com
"""

import argparse
import socket
import sys

import requests

API_URL = "https://api.hackertarget.com/reverseiplookup/?q={target}"


def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"[!] Could not resolve {domain}: {e}", file=sys.stderr)
        sys.exit(1)


def reverse_lookup(ip, timeout):
    url = API_URL.format(target=ip)
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    text = resp.text.strip()

    # HackerTarget returns plain-text error messages (not JSON) for failure cases
    if "error" in text.lower() or "API count exceeded" in text:
        return None, text

    domains = [line.strip() for line in text.splitlines() if line.strip()]
    return domains, None


def main():
    parser = argparse.ArgumentParser(description="Find other domains hosted on the same IP (via HackerTarget's free API).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="IP address to look up")
    group.add_argument("--domain", help="Domain to resolve first, then reverse-look-up its IP")
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds")
    args = parser.parse_args()

    if args.domain:
        ip = resolve_domain_to_ip(args.domain)
        print(f"[*] {args.domain} resolves to {ip}")
    else:
        ip = args.ip

    print(f"[*] Reverse IP lookup for {ip}...")
    domains, error = reverse_lookup(ip, args.timeout)

    if error:
        print(f"[!] Lookup failed: {error}", file=sys.stderr)
        sys.exit(1)

    print("-" * 60)
    if not domains:
        print("[*] No other domains found on this IP (or it's a dedicated/single-tenant host).")
        return

    print(f"[*] {len(domains)} domain(s) found sharing this IP:")
    for d in domains:
        print(f"    {d}")

    if len(domains) > 1:
        print()
        print("[*] Multiple domains on one IP suggests shared hosting — a vulnerability")
        print("    in any one of these sites could potentially provide a foothold on the")
        print("    same underlying server, depending on the hosting provider's isolation.")


if __name__ == "__main__":
    main()
