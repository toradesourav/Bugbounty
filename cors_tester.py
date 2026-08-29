#!/usr/bin/env python3
"""
CORS Checker
------------
Probes a target endpoint with a series of crafted Origin headers to
detect common CORS misconfigurations:
  - Reflecting arbitrary Origins in Access-Control-Allow-Origin
  - Allowing credentials (cookies) alongside a reflected/wildcard Origin
  - Trusting null Origin
  - Weak suffix/prefix matching on the allowed-origin logic

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python cors_check.py --url https://target.com/api/data
    python cors_check.py --url https://target.com/api/data --origin https://evil.com
"""

import argparse
import sys

import requests

DEFAULT_TEST_ORIGINS = [
    "https://evil-attacker.com",
    "null",
    "https://target.com.evil-attacker.com",   # suffix-match trick
    "https://evilattacker.com",
    "http://localhost",
]


def probe(session, url, origin, timeout):
    try:
        resp = session.get(url, headers={"Origin": origin}, timeout=timeout)
    except requests.RequestException as e:
        return {"origin": origin, "error": str(e)}

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    return {
        "origin": origin,
        "status": resp.status_code,
        "acao": acao,
        "acac": acac,
        "vulnerable": bool(
            acao and (acao == origin or acao == "*") and
            (acac.lower() == "true" or acao == origin)
        ),
    }


def classify(result):
    if result.get("error"):
        return f"[ERR ] {result['origin']:<40} {result['error']}"

    acao = result["acao"]
    acac = result["acac"]
    origin = result["origin"]

    if acao is None:
        return f"[ OK ] {origin:<40} no CORS headers returned"

    flag = ""
    if acao == origin and acac.lower() == "true":
        flag = "  <-- CRITICAL: reflects Origin + allows credentials"
    elif acao == origin:
        flag = "  <-- reflects arbitrary Origin (no credentials)"
    elif acao == "*" and acac.lower() == "true":
        flag = "  <-- INVALID CONFIG: wildcard + credentials (browsers reject this, but worth reporting)"
    elif acao == "*":
        flag = "  (wildcard, no credentials — usually fine for public APIs)"

    return f"[{result['status']:>3}] {origin:<40} ACAO={acao!r:<25} ACAC={acac or '-':<6}{flag}"


def main():
    parser = argparse.ArgumentParser(description="Check an endpoint for CORS misconfigurations.")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--origin", action="append", help="Additional Origin value to test, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--only-custom", action="store_true", help="Skip the default origin list, only test --origin values")
    args = parser.parse_args()

    origins = [] if args.only_custom else list(DEFAULT_TEST_ORIGINS)
    if args.origin:
        origins.extend(args.origin)

    if not origins:
        print("[!] No origins to test.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Target: {args.url}")
    print(f"[*] Testing {len(origins)} Origin values")
    print("-" * 60)

    any_vuln = False
    with requests.Session() as session:
        for origin in origins:
            result = probe(session, args.url, origin, args.timeout)
            print(classify(result))
            if result.get("vulnerable"):
                any_vuln = True

    print("-" * 60)
    if any_vuln:
        print("[!] Potential CORS misconfiguration(s) found — review flagged lines above.")
    else:
        print("[*] No obvious CORS misconfiguration detected with these origins.")


if __name__ == "__main__":
    main()
