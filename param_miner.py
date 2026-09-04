#!/usr/bin/env python3
"""
Param Miner
-------------
Discovers hidden/undocumented parameters by sending a baseline
request, then adding candidate parameter names one at a time (from a
built-in wordlist or a custom one) and comparing the response against
the baseline. A parameter that changes the response — different
status code, meaningfully different length, or a new error message —
is likely a real parameter the app reads, even if it's undocumented
(debug flags, feature toggles, admin overrides, etc. are classic
finds this way).

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python param_miner.py --url https://target.com/api/user
    python param_miner.py --url https://target.com/page --wordlist params.txt --method POST
"""

import argparse
import sys

import requests

DEFAULT_PARAM_WORDLIST = [
    "debug", "test", "admin", "internal", "beta", "preview", "draft",
    "format", "output", "callback", "jsonp", "redirect", "return_url",
    "next", "url", "path", "file", "template", "view", "mode",
    "role", "user_id", "userid", "uid", "id", "account", "impersonate",
    "override", "force", "bypass", "skip_validation", "no_cache",
    "cache", "version", "api_version", "v", "lang", "locale",
    "sort", "order", "filter", "limit", "offset", "page", "per_page",
    "include", "exclude", "fields", "expand", "verbose", "raw",
    "source", "ref", "token", "key", "secret", "access", "level",
]

TEST_VALUE = "1"


def send_request(session, url, method, param, value, timeout, base_params):
    params = dict(base_params)
    if value is not None:
        params[param] = value
    try:
        resp = session.request(method, url, params=params, timeout=timeout)
        return resp
    except requests.RequestException:
        return None


def responses_differ(baseline, candidate):
    if candidate is None:
        return False, "request failed"

    if candidate.status_code != baseline.status_code:
        return True, f"status changed: {baseline.status_code} -> {candidate.status_code}"

    len_diff = abs(len(candidate.content) - len(baseline.content))
    if len_diff > max(20, len(baseline.content) * 0.05):
        return True, f"length changed: {len(baseline.content)} -> {len(candidate.content)} (diff {len_diff})"

    return False, None


def main():
    parser = argparse.ArgumentParser(description="Discover hidden parameters via wordlist injection and response diffing.")
    parser.add_argument("--url", required=True, help="Target URL (existing query params, if any, are preserved as the baseline)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    parser.add_argument("--wordlist", help="Path to a custom parameter-name wordlist (default: 55 common built-in names)")
    parser.add_argument("--value", default=TEST_VALUE, help=f"Value to send for each candidate parameter (default: '{TEST_VALUE}')")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                param_names = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"[!] Could not read --wordlist: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        param_names = DEFAULT_PARAM_WORDLIST

    print(f"[*] Target: {args.url}")
    print(f"[*] Establishing baseline ({args.method})...")

    with requests.Session() as session:
        baseline = send_request(session, args.url, args.method, None, None, args.timeout, {})
        if baseline is None:
            print("[!] Baseline request failed — check the URL/connectivity.", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Baseline: status={baseline.status_code}, length={len(baseline.content)}")
        print(f"[*] Testing {len(param_names)} candidate parameter name(s)")
        print("-" * 60)

        found = []
        for param in param_names:
            resp = send_request(session, args.url, args.method, param, args.value, args.timeout, {})
            differs, reason = responses_differ(baseline, resp)
            if differs:
                found.append(param)
                print(f"[FOUND] {param:<20} {reason}")

    print("-" * 60)
    if found:
        print(f"[!] {len(found)} candidate hidden parameter(s) found: {', '.join(found)}")
        print("    Manually verify each — some differences come from server-side randomness")
        print("    (timestamps, request IDs) rather than the parameter actually being read.")
    else:
        print("[*] No parameters caused a response difference with this wordlist.")


if __name__ == "__main__":
    main()
