#!/usr/bin/env python3
"""
XSS Param Finder
------------------
Tests each query-string parameter of a URL for reflected XSS by
injecting a unique, harmless marker string and checking whether it
comes back unescaped in the response body (i.e. HTML special
characters like < > " ' were not encoded). This finds *candidates*
for XSS — it does not execute JavaScript or confirm exploitability in
a browser context, since that requires a real DOM/headless browser.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python xss_param_finder.py --url "https://target.com/search?q=test&page=1"
    python xss_param_finder.py --url "https://target.com/search?q=test" --context
"""

import argparse
import re
import sys
import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests

# A harmless marker containing characters that MUST be HTML-escaped by
# any properly output-encoded application. If it comes back verbatim,
# that parameter is a reflected-XSS candidate.
MARKER_CHARS = "<'\">"


def build_marker():
    # Unique per run so repeated params / cached responses don't cross-contaminate results
    token = uuid.uuid4().hex[:8]
    return f"xss{token}{MARKER_CHARS}", token


def inject_param(url, param_name, payload):
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, payload if k == param_name else v) for k, v in query_pairs]
    new_query = urlencode(new_pairs)
    return urlunparse(parsed._replace(query=new_query))


def get_context_snippet(body, token, window=40):
    idx = body.find(token)
    if idx == -1:
        return None
    start = max(0, idx - window)
    end = min(len(body), idx + len(token) + window)
    return body[start:end].replace("\n", " ")


def check_param(session, base_url, param_name, timeout):
    payload, token = build_marker()
    test_url = inject_param(base_url, param_name, payload)

    try:
        resp = session.get(test_url, timeout=timeout)
    except requests.RequestException as e:
        return {"param": param_name, "error": str(e)}

    body = resp.text
    raw_reflected = payload in body
    # If the raw payload isn't present, check if the token survived but got escaped
    # (e.g. &lt;xss...&gt;) — that means the app IS encoding output correctly.
    token_present = token in body

    result = {
        "param": param_name,
        "test_url": test_url,
        "status": resp.status_code,
        "raw_reflected": raw_reflected,
        "token_present": token_present,
        "snippet": get_context_snippet(body, token) if token_present else None,
    }
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Test URL parameters for reflected-XSS candidates using a marker injection."
    )
    parser.add_argument("--url", required=True, help="URL with query parameters to test")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--context", action="store_true", help="Show the surrounding HTML snippet for each reflection")
    args = parser.parse_args()

    parsed = urlparse(args.url)
    params = [k for k, _ in parse_qsl(parsed.query)]

    if not params:
        print("[!] No query parameters found in --url. Add at least one, e.g. ?q=test", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Target: {args.url}")
    print(f"[*] Testing {len(params)} parameter(s): {', '.join(params)}")
    print("-" * 60)

    any_vuln = False
    with requests.Session() as session:
        for param in params:
            result = check_param(session, args.url, param, args.timeout)
            if result.get("error"):
                print(f"[ERR ] {param:<20} {result['error']}")
                continue

            if result["raw_reflected"]:
                any_vuln = True
                print(f"[VULN] {param:<20} raw payload reflected unescaped -> candidate XSS")
                print(f"       test URL: {result['test_url']}")
                if args.context and result["snippet"]:
                    print(f"       context : ...{result['snippet']}...")
            elif result["token_present"]:
                print(f"[SAFE] {param:<20} reflected but appears HTML-escaped")
            else:
                print(f"[ -- ] {param:<20} not reflected in response body")

    print("-" * 60)
    if any_vuln:
        print("[!] Reflected-XSS candidate(s) found. Manually confirm in a browser before reporting —")
        print("    context matters (attribute vs. script vs. HTML body changes the required payload).")
    else:
        print("[*] No unescaped reflections found with this marker.")


if __name__ == "__main__":
    main()
