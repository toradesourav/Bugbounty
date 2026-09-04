#!/usr/bin/env python3
"""
SSTI Detector
---------------
Tests a URL parameter for Server-Side Template Injection by sending
template-syntax math expressions across several template engines
(Jinja2, Twig, Freemarker, Velocity, Smarty, ERB) and checking whether
the response contains the EVALUATED result rather than the literal
payload. If the app echoes back "49" instead of "{{7*7}}", the
template engine executed attacker-controlled syntax — a critical
finding, since most SSTI bugs escalate to full remote code execution.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python ssti_detector.py --url "https://target.com/greet?name=FUZZ"
"""

import argparse
import sys
from urllib.parse import quote

import requests

FUZZ_MARKER = "FUZZ"
EXPECTED_RESULT = "49"  # 7 * 7, chosen because it's an unusual-looking number unlikely to appear by coincidence

# (engine, payload) — each engine has its own template delimiter syntax
PAYLOADS = [
    ("Jinja2 / Twig (Python/PHP)", "{{7*7}}"),
    ("Jinja2 (alt, with quotes)", "{{7*'7'}}"),  # Jinja2 evaluates this differently (string repeat) -- distinct fingerprint
    ("Freemarker (Java)", "${7*7}"),
    ("Velocity (Java)", "#set($x=7*7)$x"),
    ("Smarty (PHP)", "{7*7}"),
    ("ERB (Ruby)", "<%= 7*7 %>"),
    ("Handlebars (Node.js, usually safe)", "{{#with \"s\" as |string|}}{{7*7}}{{/with}}"),
    ("Generic bracket (Pebble/others)", "{{7*7}}{%raw%}"),
]


def test_payload(session, url_template, payload, timeout):
    injected_url = url_template.replace(FUZZ_MARKER, quote(payload, safe=""))
    try:
        resp = session.get(injected_url, timeout=timeout)
    except requests.RequestException as e:
        return {"error": str(e)}

    body = resp.text or ""
    evaluated = EXPECTED_RESULT in body and payload not in body
    literal_reflected = payload in body

    return {
        "status": resp.status_code,
        "evaluated": evaluated,
        "literal_reflected": literal_reflected,
        "body_len": len(body),
    }


def main():
    parser = argparse.ArgumentParser(description="Test a URL parameter for Server-Side Template Injection.")
    parser.add_argument("--url", required=True, help=f"URL containing the {FUZZ_MARKER} marker")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    if FUZZ_MARKER not in args.url:
        print(f"[!] --url must contain the {FUZZ_MARKER} marker, e.g. https://target.com/greet?name={FUZZ_MARKER}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Target: {args.url}")
    print(f"[*] Testing {len(PAYLOADS)} template-engine payloads")
    print("-" * 60)

    any_confirmed = False
    with requests.Session() as session:
        for engine, payload in PAYLOADS:
            result = test_payload(session, args.url, payload, args.timeout)

            if result.get("error"):
                print(f"[ERR ] {engine:<38} {result['error']}")
                continue

            if result["evaluated"]:
                any_confirmed = True
                print(f"[!!! SSTI CONFIRMED] {engine}")
                print(f"      payload {payload!r} was evaluated (response contains '{EXPECTED_RESULT}', not the literal payload)")
            elif result["literal_reflected"]:
                print(f"[ -- ] {engine:<38} reflected but NOT evaluated (safely escaped/treated as text)")
            else:
                print(f"[ -- ] {engine:<38} not reflected at all")

    print("-" * 60)
    if any_confirmed:
        print("[!] SSTI confirmed on at least one engine's syntax. This typically escalates")
        print("    to full remote code execution — treat as CRITICAL severity. Do not attempt")
        print("    further exploitation (RCE payloads) without explicit written authorization")
        print("    for that specific level of testing.")
    else:
        print("[*] No template evaluation detected with these payloads. Consider trying the")
        print("    application's specific templating context (e.g. inside an attribute vs. a")
        print("    text node) if you have reason to suspect SSTI is still present.")


if __name__ == "__main__":
    main()
