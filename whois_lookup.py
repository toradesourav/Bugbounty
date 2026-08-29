#!/usr/bin/env python3
"""
Whois Lookup Tool
-------------------
Queries WHOIS servers directly over TCP (port 43) — no third-party
API key needed. Starts at IANA's root WHOIS server, follows the
"refer:" pointer to the registry-specific server (e.g. Verisign for
.com), and prints the final registration record: registrar,
creation/expiry dates, name servers, registrant org (when not
privacy-redacted).

Usage:
    python whois_lookup.py --domain target.com
    python whois_lookup.py --domain target.com --raw
"""

import argparse
import re
import socket
import sys

IANA_WHOIS = "whois.iana.org"
WHOIS_PORT = 43
SOCKET_TIMEOUT = 10

REFER_RE = re.compile(r"^refer:\s*(\S+)", re.MULTILINE | re.IGNORECASE)

FIELDS_OF_INTEREST = [
    "Domain Name", "Registrar", "Registrar WHOIS Server",
    "Creation Date", "Registry Expiry Date", "Updated Date",
    "Registrant Organization", "Registrant Country",
    "Name Server", "Domain Status",
]


def query_whois_server(server, query, timeout):
    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode(errors="ignore")


def lookup(domain, timeout):
    try:
        iana_response = query_whois_server(IANA_WHOIS, domain, timeout)
    except (socket.timeout, socket.gaierror, ConnectionError) as e:
        print(f"[!] Could not reach {IANA_WHOIS}: {e}", file=sys.stderr)
        sys.exit(1)

    match = REFER_RE.search(iana_response)
    if not match:
        print("[*] No referral found from IANA — showing IANA response as-is.")
        return iana_response

    registry_server = match.group(1)
    print(f"[*] Referred to registry server: {registry_server}")
    try:
        registry_response = query_whois_server(registry_server, domain, timeout)
    except (socket.timeout, socket.gaierror, ConnectionError) as e:
        print(f"[!] Could not reach {registry_server}: {e}", file=sys.stderr)
        print("[*] Falling back to IANA response.")
        return iana_response

    return registry_response


def extract_fields(raw_text):
    found = {}
    for line in raw_text.splitlines():
        for field in FIELDS_OF_INTEREST:
            if line.lower().startswith(field.lower() + ":"):
                value = line.split(":", 1)[1].strip()
                if value:
                    found.setdefault(field, []).append(value)
    return found


def main():
    parser = argparse.ArgumentParser(description="Look up WHOIS registration data for a domain (no API key required).")
    parser.add_argument("--domain", required=True, help="Domain to look up, e.g. target.com")
    parser.add_argument("--raw", action="store_true", help="Print the full raw WHOIS response instead of a parsed summary")
    parser.add_argument("--timeout", type=float, default=SOCKET_TIMEOUT, help="Socket timeout in seconds (default: 10)")
    args = parser.parse_args()

    print(f"[*] Looking up: {args.domain}")
    raw = lookup(args.domain, args.timeout)

    print("-" * 60)
    if args.raw:
        print(raw)
        return

    fields = extract_fields(raw)
    if not fields:
        print("[!] Could not parse structured fields — showing raw response instead:")
        print(raw)
        return

    for field in FIELDS_OF_INTEREST:
        if field in fields:
            for value in fields[field]:
                print(f"{field:<24}: {value}")


if __name__ == "__main__":
    main()
