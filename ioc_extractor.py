#!/usr/bin/env python3
"""
IOC Extractor
---------------
Extracts Indicators of Compromise from arbitrary text (logs, incident
reports, threat intel feeds, pasted emails, etc.): IPv4/IPv6
addresses, domains, URLs, email addresses, and file hashes
(MD5/SHA1/SHA256). Standard first step in SOC triage — turning a wall
of unstructured text into a clean, deduplicated list you can feed into
a blocklist, SIEM, or threat-intel lookup.

Usage:
    python ioc_extractor.py --file incident_report.txt
    python ioc_extractor.py --file email_headers.txt --types ip,domain
    cat suspicious.log | python ioc_extractor.py
"""

import argparse
import re
import sys

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "url": re.compile(r"\bhttps?://[^\s<>\"'\)\]]+"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

# Order matters: check longer/more-specific patterns before shorter ones
# that could be substrings (e.g. a domain is a substring of a URL/email)
EXTRACTION_ORDER = ["url", "email", "ipv6", "ipv4", "sha256", "sha1", "md5", "domain"]


def extract_all(text):
    results = {ioc_type: set() for ioc_type in IOC_PATTERNS}
    remaining = text

    for ioc_type in EXTRACTION_ORDER:
        pattern = IOC_PATTERNS[ioc_type]
        matches = pattern.findall(remaining)
        results[ioc_type].update(matches)

    # Domains extracted from inside URLs/emails are usually redundant noise;
    # filter out any "domain" match that's already fully contained in a
    # captured URL or email, so the domain list stays focused on standalone mentions
    url_and_email_text = " ".join(results["url"]) + " " + " ".join(results["email"])
    results["domain"] = {d for d in results["domain"] if d not in url_and_email_text}

    return results


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs (IPs, domains, URLs, emails, hashes) from text.")
    parser.add_argument("--file", help="Path to a text file to scan (omit to read from stdin)")
    parser.add_argument("--types", help="Comma-separated list of IOC types to show (default: all). Options: " + ", ".join(EXTRACTION_ORDER))
    parser.add_argument("--output", help="Write results to this file as one IOC per line (all types combined)")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError as e:
            print(f"[!] Could not read --file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("[!] No --file given and no piped input detected.", file=sys.stderr)
            sys.exit(1)
        text = sys.stdin.read()

    results = extract_all(text)

    requested_types = args.types.split(",") if args.types else EXTRACTION_ORDER
    requested_types = [t.strip() for t in requested_types if t.strip() in IOC_PATTERNS]

    all_found = []
    for ioc_type in EXTRACTION_ORDER:
        if ioc_type not in requested_types:
            continue
        values = sorted(results[ioc_type])
        if not values:
            continue
        print(f"[{ioc_type.upper()}] ({len(values)})")
        for v in values:
            print(f"    {v}")
        all_found.extend(values)

    total = sum(len(results[t]) for t in requested_types)
    print("-" * 60)
    print(f"[*] {total} total IOC(s) extracted across {len(requested_types)} type(s)")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(all_found) + ("\n" if all_found else ""))
            print(f"[*] Saved to {args.output}")
        except OSError as e:
            print(f"[!] Could not write output file: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
