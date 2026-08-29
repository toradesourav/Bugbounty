#!/usr/bin/env python3
"""
IDOR Tester
-------------
Tests for Insecure Direct Object Reference vulnerabilities in two modes:

  1. Enumeration mode (single session): iterates an ID parameter and
     checks which IDs return distinct, seemingly-valid objects. Useful
     as a first pass, but a 200 response alone doesn't prove IDOR —
     the app might just not have per-object records at all, or the
     same session might legitimately own every ID tested.

  2. Differential mode (two sessions) — the real IDOR test: logs
     requests as "User A" and "User B" (via separate cookies/headers),
     then checks whether User B's session can access an object ID
     that belongs to User A. This is the actual authorization check;
     enumeration alone cannot confirm broken access control.

Intended for use ONLY against systems you own or are explicitly
authorized to test — differential mode requires you to legitimately
control both test accounts.

Usage:
    # Enumeration mode
    python idor_tester.py --url "https://target.com/api/orders/FUZZ" --start 1 --end 20 \\
        --cookie "session=abc123"

    # Differential mode: does User B's session see User A's object?
    python idor_tester.py --url "https://target.com/api/orders/1001" \\
        --cookie-a "session=USER_A_TOKEN" --cookie-b "session=USER_B_TOKEN" --owner a
"""

import argparse
import hashlib
import sys

import requests

FUZZ_MARKER = "FUZZ"


def parse_cookie_string(cookie_str):
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            cookies[k] = v
    return cookies


def content_fingerprint(resp):
    # Hash the body so we can tell "same object returned every time" (likely a
    # generic error/login page) apart from genuinely distinct objects.
    return hashlib.sha256(resp.content).hexdigest()[:12]


def run_enumeration(url_template, start, end, cookies, headers, timeout):
    print(f"[*] Enumeration mode: testing IDs {start}..{end}")
    print("-" * 60)

    seen_fingerprints = {}
    accessible = []

    with requests.Session() as session:
        session.cookies.update(cookies)
        for object_id in range(start, end + 1):
            url = url_template.replace(FUZZ_MARKER, str(object_id))
            try:
                resp = session.get(url, headers=headers, timeout=timeout)
            except requests.RequestException as e:
                print(f"[ERR ] id={object_id} {e}")
                continue

            fp = content_fingerprint(resp)

            if resp.status_code == 200:
                repeat_count = seen_fingerprints.get(fp, 0)
                seen_fingerprints[fp] = repeat_count + 1
                accessible.append(object_id)
                note = " (duplicate content seen before — likely generic page, not a real object)" if repeat_count else ""
                print(f"[200 ] id={object_id:<6} len={len(resp.content):<8} fingerprint={fp}{note}")
            else:
                print(f"[{resp.status_code:>4} ] id={object_id}")

    print("-" * 60)
    unique_fingerprints = len(seen_fingerprints)
    print(f"[*] {len(accessible)}/{end - start + 1} IDs returned 200. {unique_fingerprints} distinct response fingerprint(s).")
    if unique_fingerprints > 1 and len(accessible) > 1:
        print("[!] Multiple distinct objects accessible from one session — if these IDs belong to")
        print("    different users/records, this is a strong IDOR candidate. Confirm with")
        print("    differential mode (--cookie-a/--cookie-b) to prove cross-account access.")
    elif unique_fingerprints <= 1 and accessible:
        print("[*] All accessible IDs returned identical content — likely a single generic")
        print("    page (e.g. a login wall), not evidence of distinct accessible objects.")


def run_differential(url, cookies_a, cookies_b, owner, headers, timeout):
    print(f"[*] Differential mode: does the OTHER user's session see this object?")
    print(f"[*] URL: {url}  (declared owner: User {owner.upper()})")
    print("-" * 60)

    other = "b" if owner == "a" else "a"
    other_cookies = cookies_b if owner == "a" else cookies_a
    owner_cookies = cookies_a if owner == "a" else cookies_b

    with requests.Session() as owner_session, requests.Session() as other_session:
        owner_session.cookies.update(owner_cookies)
        other_session.cookies.update(other_cookies)

        try:
            owner_resp = owner_session.get(url, headers=headers, timeout=timeout)
        except requests.RequestException as e:
            print(f"[!] Request as owner (User {owner.upper()}) failed: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            other_resp = other_session.get(url, headers=headers, timeout=timeout)
        except requests.RequestException as e:
            print(f"[!] Request as User {other.upper()} failed: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"User {owner.upper()} (owner)   -> status={owner_resp.status_code}  len={len(owner_resp.content)}")
    print(f"User {other.upper()} (other)   -> status={other_resp.status_code}  len={len(other_resp.content)}")
    print("-" * 60)

    if owner_resp.status_code == 200 and other_resp.status_code == 200:
        same_content = owner_resp.content == other_resp.content
        if same_content:
            print(f"[!!! IDOR CONFIRMED] User {other.upper()} received the SAME object content as the owner.")
            print("     This object should not be accessible to a different authenticated user.")
        else:
            print(f"[?] Both users got 200, but response bodies differ — the app may be returning a")
            print(f"    generic/redirected page to User {other.upper()} rather than the real object.")
            print(f"    Manually inspect both responses to confirm.")
    elif other_resp.status_code in (401, 403, 404):
        print(f"[SAFE] User {other.upper()} was denied ({other_resp.status_code}) — access control appears correct.")
    else:
        print(f"[?] Unexpected combination of status codes — manually review both responses.")


def main():
    parser = argparse.ArgumentParser(description="Test for Insecure Direct Object Reference (IDOR) vulnerabilities.")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    enum_parser = subparsers.add_parser("enumerate", help="Single-session ID enumeration (first-pass recon)")
    enum_parser.add_argument("--url", required=True, help=f"URL containing the {FUZZ_MARKER} marker for the object ID")
    enum_parser.add_argument("--start", type=int, required=True, help="Starting ID (inclusive)")
    enum_parser.add_argument("--end", type=int, required=True, help="Ending ID (inclusive)")
    enum_parser.add_argument("--cookie", help='Cookie string, e.g. "session=abc123; other=val"')
    enum_parser.add_argument("--header", action="append", help="Extra header, repeatable")
    enum_parser.add_argument("--timeout", type=float, default=10.0)

    diff_parser = subparsers.add_parser("differential", help="Two-account test — the real IDOR confirmation")
    diff_parser.add_argument("--url", required=True, help="Full URL to a specific object owned by User A or B")
    diff_parser.add_argument("--cookie-a", required=True, help="Cookie string for User A's session")
    diff_parser.add_argument("--cookie-b", required=True, help="Cookie string for User B's session")
    diff_parser.add_argument("--owner", required=True, choices=["a", "b"], help="Which user actually owns this object")
    diff_parser.add_argument("--header", action="append", help="Extra header, repeatable")
    diff_parser.add_argument("--timeout", type=float, default=10.0)

    args = parser.parse_args()

    headers = {}
    for h in (args.header or []):
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    if args.mode == "enumerate":
        if FUZZ_MARKER not in args.url:
            print(f"[!] --url must contain the {FUZZ_MARKER} marker, e.g. https://target.com/orders/{FUZZ_MARKER}", file=sys.stderr)
            sys.exit(1)
        cookies = parse_cookie_string(args.cookie)
        run_enumeration(args.url, args.start, args.end, cookies, headers, args.timeout)
    else:
        cookies_a = parse_cookie_string(args.cookie_a)
        cookies_b = parse_cookie_string(args.cookie_b)
        run_differential(args.url, cookies_a, cookies_b, args.owner, headers, args.timeout)


if __name__ == "__main__":
    main()
