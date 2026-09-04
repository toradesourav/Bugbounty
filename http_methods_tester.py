#!/usr/bin/env python3
"""
HTTP Methods Tester
----------------------
Checks which HTTP methods an endpoint accepts. Dangerous methods left
enabled (PUT, DELETE, TRACE) can allow file upload/overwrite, resource
deletion, or cross-site tracing (XST) attacks depending on server
configuration. Also checks the OPTIONS response's Allow header, since
that alone often reveals more than any single probing request would.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python http_methods_tester.py --url https://target.com/api/resource/1
"""

import argparse
import sys

import requests

METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD", "CONNECT"]

RISK_NOTES = {
    "PUT": "Can allow file upload/overwrite if the server maps it to a writable path.",
    "DELETE": "Can allow resource deletion without additional authorization checks.",
    "TRACE": "Enables Cross-Site Tracing (XST) — can help bypass HttpOnly cookie protections in older browsers.",
    "CONNECT": "Normally only relevant on proxies — unexpected on an origin server.",
}


def test_method(session, url, method, timeout):
    try:
        resp = session.request(method, url, timeout=timeout, allow_redirects=False)
        return resp.status_code, None
    except requests.RequestException as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(description="Check which HTTP methods an endpoint accepts.")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    print(f"[*] Target: {args.url}")
    print("-" * 60)

    with requests.Session() as session:
        # OPTIONS first — its Allow header is often the most informative single signal
        try:
            options_resp = session.options(args.url, timeout=args.timeout)
            allow_header = options_resp.headers.get("Allow")
            if allow_header:
                print(f"[OPTIONS Allow header] {allow_header}")
            else:
                print("[OPTIONS] No Allow header returned")
        except requests.RequestException as e:
            print(f"[OPTIONS] request failed: {e}")

        print("-" * 60)

        enabled = []
        for method in METHODS_TO_TEST:
            status, error = test_method(session, args.url, method, args.timeout)
            if error:
                print(f"[{method:<8}] ERROR: {error}")
                continue

            # A 2xx/3xx (or a 401/403 that at least acknowledges the method exists,
            # vs. a 404/405 meaning the method itself isn't routed/allowed) is "enabled"
            is_enabled = status not in (404, 405, 501)
            if is_enabled:
                enabled.append(method)
                note = f"  -- {RISK_NOTES[method]}" if method in RISK_NOTES else ""
                print(f"[{method:<8}] status={status}  <-- enabled{note}")
            else:
                print(f"[{method:<8}] status={status}")

    print("-" * 60)
    risky_enabled = [m for m in enabled if m in RISK_NOTES]
    if risky_enabled:
        print(f"[!] Potentially risky methods enabled: {', '.join(risky_enabled)}")
        print("    Confirm actual impact manually — a method responding doesn't always mean")
        print("    it's exploitable (the app layer may still enforce its own checks).")
    else:
        print("[*] No high-risk methods (PUT/DELETE/TRACE) appear enabled beyond GET/POST/HEAD/OPTIONS.")


if __name__ == "__main__":
    main()
