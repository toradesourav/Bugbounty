#!/usr/bin/env python3
"""
Subdomain Finder
------------------
Finds subdomains for a target domain using two complementary methods:
  1. Certificate Transparency logs (crt.sh) — passive, finds real
     subdomains that have ever had a TLS cert issued, no guessing.
  2. Wordlist brute-force via DNS resolution — active, catches
     subdomains that never got a public cert (internal-only services,
     newly created hosts, etc.)

Results are merged and deduplicated, then each is checked for live
DNS resolution.

Usage:
    python subdomain_finder.py --domain target.com
    python subdomain_finder.py --domain target.com --wordlist subdomains.txt
    python subdomain_finder.py --domain target.com --no-crtsh
"""

import argparse
import concurrent.futures
import socket
import sys

import requests

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "api", "dev", "staging", "test", "admin", "portal", "vpn",
    "remote", "app", "apps", "cdn", "static", "assets", "media",
    "blog", "shop", "store", "support", "help", "docs", "status",
    "monitor", "grafana", "kibana", "jenkins", "gitlab", "git",
    "jira", "confluence", "wiki", "internal", "intranet", "dashboard",
    "auth", "sso", "login", "accounts", "secure", "payments", "pay",
    "beta", "demo", "sandbox", "uat", "qa", "preprod", "old", "legacy",
    "m", "mobile", "cpanel", "webdisk", "autodiscover", "ws", "ws2",
]

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def query_crtsh(domain, timeout):
    url = CRTSH_URL.format(domain=domain)
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "subdomain-finder"})
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[!] crt.sh query failed: {e}", file=sys.stderr)
        return set()

    names = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(domain):
                names.add(name)
    return names


def load_wordlist(path):
    if not path:
        return list(DEFAULT_WORDLIST)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Could not read wordlist: {e}", file=sys.stderr)
        sys.exit(1)


def resolve(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return hostname, ip
    except socket.gaierror:
        return hostname, None


def main():
    parser = argparse.ArgumentParser(description="Find subdomains via crt.sh (passive) and wordlist brute-force (active).")
    parser.add_argument("--domain", required=True, help="Target domain, e.g. target.com")
    parser.add_argument("--wordlist", help="Path to a custom subdomain wordlist (default: 60 common built-in names)")
    parser.add_argument("--no-crtsh", action="store_true", help="Skip the crt.sh certificate-transparency lookup")
    parser.add_argument("--no-bruteforce", action="store_true", help="Skip the wordlist brute-force, crt.sh only")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent DNS resolutions (default: 20)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request/resolution timeout in seconds")
    parser.add_argument("--output", help="Write live subdomains to this file, one per line")
    args = parser.parse_args()

    candidates = set()

    if not args.no_crtsh:
        print(f"[*] Querying crt.sh for {args.domain}...")
        crt_names = query_crtsh(args.domain, args.timeout)
        print(f"[*] crt.sh returned {len(crt_names)} unique name(s)")
        candidates |= crt_names

    if not args.no_bruteforce:
        wordlist = load_wordlist(args.wordlist)
        brute_candidates = {f"{word}.{args.domain}" for word in wordlist}
        print(f"[*] Adding {len(brute_candidates)} wordlist-based candidate(s)")
        candidates |= brute_candidates

    candidates.add(args.domain)  # always check the root domain too

    print(f"[*] Resolving {len(candidates)} total candidate(s)...")
    print("-" * 60)

    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        for hostname, ip in pool.map(resolve, sorted(candidates)):
            if ip:
                live.append((hostname, ip))
                print(f"[LIVE] {hostname:<40} -> {ip}")

    print("-" * 60)
    print(f"[*] {len(live)}/{len(candidates)} subdomain(s) resolved live.")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(h for h, _ in live) + ("\n" if live else ""))
            print(f"[*] Saved to {args.output}")
        except OSError as e:
            print(f"[!] Could not write output file: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
