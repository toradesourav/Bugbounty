#!/usr/bin/env python3
"""
Email Header Analyzer
------------------------
Parses raw email headers (paste the full header block, or point at a
.eml file) and reports on authentication results (SPF/DKIM/DMARC),
the actual sending path (Received chain), and common
spoofing/phishing indicators — mismatched From/Return-Path domains,
missing authentication, or suspicious Reply-To redirection.

Usage:
    python email_header_analyzer.py --file headers.txt
    cat headers.txt | python email_header_analyzer.py
"""

import argparse
import re
import sys
from email import message_from_string
from email.utils import parseaddr


def get_input_text(args):
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except OSError as e:
            print(f"[!] Could not read --file: {e}", file=sys.stderr)
            sys.exit(1)
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("[!] Provide --file or pipe header text via stdin.", file=sys.stderr)
    sys.exit(1)


def extract_domain(address):
    _, email_addr = parseaddr(address)
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower()
    return None


def parse_auth_results(auth_header):
    results = {}
    for mechanism in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def analyze(raw_headers):
    msg = message_from_string(raw_headers)
    findings = []

    from_addr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    sender = msg.get("Sender", "")

    from_domain = extract_domain(from_addr)
    return_path_domain = extract_domain(return_path)
    reply_to_domain = extract_domain(reply_to)

    print(f"[*] From:       {from_addr}")
    print(f"[*] Return-Path: {return_path or '(not set)'}")
    print(f"[*] Reply-To:   {reply_to or '(not set)'}")
    print(f"[*] Sender:     {sender or '(not set)'}")
    print()

    # Authentication-Results header (added by the receiving mail server)
    auth_results_header = msg.get("Authentication-Results", "")
    if auth_results_header:
        auth = parse_auth_results(auth_results_header)
        print(f"[*] Authentication-Results: {auth_results_header}")
        for mechanism in ["spf", "dkim", "dmarc"]:
            result = auth.get(mechanism, "not present")
            if result in ("pass",):
                print(f"    [OK]   {mechanism.upper()}: {result}")
            elif result == "not present":
                findings.append(("WARNING", f"{mechanism.upper()} result not found in Authentication-Results"))
                print(f"    [??]   {mechanism.upper()}: not present")
            else:
                findings.append(("CRITICAL" if mechanism == "dmarc" else "WARNING", f"{mechanism.upper()} check result: {result}"))
                print(f"    [FAIL] {mechanism.upper()}: {result}")
    else:
        findings.append(("WARNING", "No Authentication-Results header found — cannot verify SPF/DKIM/DMARC from these headers alone"))

    print()

    # Domain mismatch checks — classic spoofing indicators
    if from_domain and return_path_domain and from_domain != return_path_domain:
        findings.append(("WARNING", f"From domain ({from_domain}) differs from Return-Path domain ({return_path_domain}) — common in spoofing, but also legitimate for some mailing lists/ESPs"))

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        findings.append(("WARNING", f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain}) — replies would go somewhere other than the apparent sender, a common phishing pattern"))

    # Received chain — shows the actual server-to-server hops
    received_headers = msg.get_all("Received", [])
    if received_headers:
        print(f"[*] Received chain ({len(received_headers)} hop(s), most recent first):")
        for i, hop in enumerate(received_headers[:5]):
            first_line = hop.strip().splitlines()[0]
            print(f"    {i+1}. {first_line}")
        if len(received_headers) > 5:
            print(f"    ... and {len(received_headers) - 5} more hop(s)")
    else:
        findings.append(("INFO", "No Received headers found — unusual for a real delivered email"))

    return findings


def main():
    parser = argparse.ArgumentParser(description="Analyze raw email headers for authentication results and spoofing indicators.")
    parser.add_argument("--file", help="Path to a file containing raw email headers (or a .eml file)")
    args = parser.parse_args()

    raw_headers = get_input_text(args)

    print("=" * 60)
    findings = analyze(raw_headers)
    print("=" * 60)

    if not findings:
        print("[*] No issues found.")
    else:
        for severity, message in findings:
            print(f"[{severity}] {message}")


if __name__ == "__main__":
    main()
