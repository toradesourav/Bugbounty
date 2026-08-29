#!/usr/bin/env python3
"""
HTTP Header Analyzer
-----------------------
Fetches a URL and grades its HTTP security headers: checks for
missing protections (HSTS, CSP, X-Frame-Options, etc.), flags
information-disclosure headers (Server/X-Powered-By version strings),
and reports cookie flag issues (missing Secure/HttpOnly/SameSite).

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python header_analyzer.py --url https://target.com
"""

import argparse
import sys

import requests

# (header name, why it matters)
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS, prevents SSL-stripping / downgrade attacks",
    "Content-Security-Policy": "Mitigates XSS and data-injection attacks",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding",
    "X-Content-Type-Options": "Prevents MIME-sniffing based attacks (should be 'nosniff')",
    "Referrer-Policy": "Controls how much referrer info leaks to other sites",
    "Permissions-Policy": "Restricts access to browser features (camera, geolocation, etc.)",
    "Cross-Origin-Opener-Policy": "Isolates browsing context, mitigates Spectre-style attacks",
    "Cross-Origin-Resource-Policy": "Controls cross-origin resource loading",
}

# Headers that leak implementation details, useful for fingerprinting an attacker's next move
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def analyze_headers(headers):
    missing = []
    present = []
    for name, reason in SECURITY_HEADERS.items():
        if name in headers:
            present.append((name, headers[name]))
        else:
            missing.append((name, reason))
    return present, missing


def analyze_disclosure(headers):
    findings = []
    for name in DISCLOSURE_HEADERS:
        if name in headers:
            findings.append((name, headers[name]))
    return findings


def analyze_cookies(response):
    issues = []
    # requests' response.headers collapses multiple Set-Cookie headers into
    # one comma-joined string; the underlying urllib3 HTTPHeaderDict exposes
    # getlist() to get them individually.
    try:
        set_cookie_headers = response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        set_cookie_headers = [response.headers["Set-Cookie"]] if "Set-Cookie" in response.headers else []

    for raw_cookie in set_cookie_headers:
        cookie_name = raw_cookie.split("=")[0].strip()
        flags = raw_cookie.lower()
        cookie_issues = []
        if "secure" not in flags:
            cookie_issues.append("missing Secure flag")
        if "httponly" not in flags:
            cookie_issues.append("missing HttpOnly flag")
        if "samesite" not in flags:
            cookie_issues.append("missing SameSite flag")
        if cookie_issues:
            issues.append((cookie_name, cookie_issues))
    return issues, len(set_cookie_headers)


def main():
    parser = argparse.ArgumentParser(description="Analyze a URL's HTTP security headers.")
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://target.com")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (self-signed test targets)")
    args = parser.parse_args()

    try:
        resp = requests.get(args.url, timeout=args.timeout, verify=not args.insecure)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] {args.url} -> HTTP {resp.status_code}")
    print("=" * 60)

    present, missing = analyze_headers(resp.headers)
    print(f"[SECURITY HEADERS] {len(present)}/{len(SECURITY_HEADERS)} present\n")
    for name, value in present:
        print(f"  [OK]      {name}: {value}")
    for name, reason in missing:
        print(f"  [MISSING] {name}  -- {reason}")

    print()
    disclosure = analyze_disclosure(resp.headers)
    if disclosure:
        print("[INFO DISCLOSURE]")
        for name, value in disclosure:
            print(f"  [LEAK]    {name}: {value}")
    else:
        print("[INFO DISCLOSURE] none of the common fingerprinting headers found")

    print()
    cookie_issues, cookie_count = analyze_cookies(resp)
    print(f"[COOKIES] {cookie_count} Set-Cookie header(s) found")
    for cookie_name, issues in cookie_issues:
        print(f"  [WEAK]    {cookie_name}: {', '.join(issues)}")
    if cookie_count and not cookie_issues:
        print("  [OK]      all cookies have Secure/HttpOnly/SameSite set")

    print("=" * 60)
    score = len(present)
    total = len(SECURITY_HEADERS)
    print(f"[*] Security header score: {score}/{total}")


if __name__ == "__main__":
    main()
