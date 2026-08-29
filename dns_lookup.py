#!/usr/bin/env python3
"""
DNS Lookup Tool
-----------------
Looks up DNS records for a domain. Uses dnspython for full record-type
support (A, AAAA, MX, TXT, NS, CNAME, SOA) when installed, and
transparently falls back to Python's stdlib `socket` module (A record
+ reverse hostname only) if dnspython isn't available — so the tool
still works with zero dependencies, just with less detail.

Usage:
    python dns_lookup.py target.com
    python dns_lookup.py target.com --types A AAAA MX TXT NS
"""

import argparse
import socket
import sys

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

DEFAULT_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def lookup_with_dnspython(domain, record_types, timeout):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results = {}
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            print(f"[!] {domain} does not exist (NXDOMAIN).", file=sys.stderr)
            sys.exit(1)
        except dns.exception.DNSException as e:
            results[rtype] = [f"<error: {e}>"]
    return results


def lookup_with_socket(domain):
    """Fallback with zero external dependencies — A records only."""
    results = {}
    try:
        hostname, aliases, addresses = socket.gethostbyname_ex(domain)
        results["A"] = addresses
        if aliases:
            results["CNAME"] = aliases
    except socket.gaierror as e:
        print(f"[!] Could not resolve {domain}: {e}", file=sys.stderr)
        sys.exit(1)
    return results


def main():
    parser = argparse.ArgumentParser(description="Look up DNS records for a domain.")
    parser.add_argument("domain", help="Domain to look up, e.g. target.com")
    parser.add_argument("--types", nargs="+", default=DEFAULT_TYPES,
                         help=f"Record types to query (default: {' '.join(DEFAULT_TYPES)}). "
                              f"Ignored in fallback mode (dnspython not installed).")
    parser.add_argument("--timeout", type=float, default=5.0, help="Query timeout in seconds (default: 5)")
    args = parser.parse_args()

    print(f"[*] DNS lookup for: {args.domain}")

    if HAVE_DNSPYTHON:
        print(f"[*] Querying record types: {', '.join(args.types)}")
        results = lookup_with_dnspython(args.domain, args.types, args.timeout)
    else:
        print("[*] dnspython not installed — using stdlib socket fallback (A/CNAME only).")
        print("[*] For full record-type support: pip install dnspython")
        results = lookup_with_socket(args.domain)

    print("-" * 60)
    any_found = False
    for rtype, values in results.items():
        if not values:
            continue
        any_found = True
        print(f"[{rtype}]")
        for v in values:
            print(f"    {v}")

    if not any_found:
        print("[*] No records found for the queried types.")


if __name__ == "__main__":
    main()
