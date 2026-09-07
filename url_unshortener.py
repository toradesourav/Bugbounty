#!/usr/bin/env python3
"""
URL Unshortener + Threat Check
---------------------------------
Follows redirects to reveal what a shortened URL (bit.ly, tinyurl,
t.co, etc.) actually points to, without letting your browser visit it
first. Also applies basic heuristic checks on the final destination:
suspicious TLDs, IP-address-as-hostname, excessive subdomain nesting,
and lookalike/typosquat patterns against common brand names.

This does NOT query a live threat-intelligence database (VirusTotal,
Google Safe Browsing, etc.) — it's a fast, offline-heuristic first
pass. Pair with a real threat-intel API for a authoritative verdict.

Usage:
    python url_unshortener.py --url https://bit.ly/somelink
"""

import argparse
import re
import sys
from urllib.parse import urlparse

import requests

SUSPICIOUS_TLDS = [
    ".zip", ".mov", ".xyz", ".top", ".gq", ".tk", ".ml", ".ga", ".cf",
    ".click", ".link", ".work", ".loan", ".win",
]

COMMON_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase", "instagram",
    "whatsapp", "outlook", "office365", "dropbox",
]

IP_HOSTNAME_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def unshorten(url, timeout, max_redirects):
    session = requests.Session()
    session.max_redirects = max_redirects
    chain = [url]
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        for hist in resp.history:
            chain.append(hist.headers.get("Location", hist.url))
        final_url = resp.url
        if final_url not in chain:
            chain.append(final_url)
        return chain, resp.status_code, None
    except requests.TooManyRedirects:
        return chain, None, "Too many redirects"
    except requests.RequestException as e:
        return chain, None, str(e)


def check_heuristics(final_url):
    findings = []
    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            findings.append(f"Suspicious/cheap TLD: {tld} (commonly used in phishing/spam campaigns)")
            break

    if IP_HOSTNAME_RE.match(hostname):
        findings.append(f"Destination is a raw IP address ({hostname}) rather than a domain name — unusual for legitimate links")

    subdomain_count = hostname.count(".")
    if subdomain_count >= 4:
        findings.append(f"Excessive subdomain nesting ({subdomain_count} dots) — sometimes used to bury the real domain visually")

    for brand in COMMON_BRANDS:
        if brand in hostname.lower() and not hostname.lower().endswith(f"{brand}.com"):
            findings.append(f"Contains brand name '{brand}' but doesn't end with the expected '{brand}.com' — possible lookalike/typosquat")

    if "@" in final_url.split("://", 1)[-1].split("/")[0]:
        findings.append("URL contains '@' before the hostname — classic trick to disguise the real destination (browsers ignore everything before '@')")

    return findings


def main():
    parser = argparse.ArgumentParser(description="Expand a shortened URL and apply basic suspicion heuristics to the destination.")
    parser.add_argument("--url", required=True, help="Shortened URL to expand")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--max-redirects", type=int, default=15, help="Maximum redirect hops to follow (default: 15)")
    args = parser.parse_args()

    print(f"[*] Expanding: {args.url}")
    print("-" * 60)

    chain, status, error = unshorten(args.url, args.timeout, args.max_redirects)

    for i, hop in enumerate(chain):
        marker = "  <-- final destination" if i == len(chain) - 1 else ""
        print(f"[{i+1}] {hop}{marker}")

    if error:
        print(f"\n[!] {error}")
        sys.exit(1)

    final_url = chain[-1]
    print(f"\n[*] Final status: {status}")
    print("-" * 60)

    findings = check_heuristics(final_url)
    if findings:
        print("[!] Suspicious indicators found:")
        for f in findings:
            print(f"    - {f}")
        print()
        print("[*] These are heuristic signals, not proof of malice. Cross-check the final")
        print("    URL against a real threat-intel source (VirusTotal, Google Safe Browsing)")
        print("    before treating it as confirmed malicious.")
    else:
        print("[*] No obvious suspicious indicators in the destination URL.")
        print("    (This doesn't guarantee safety — check a real threat-intel source for")
        print("    a definitive verdict.)")


if __name__ == "__main__":
    main()
