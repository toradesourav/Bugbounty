#!/usr/bin/env python3
"""
JS Secret Scanner
------------------
Fetches one or more JavaScript files and scans them for hardcoded
secrets: API keys, tokens, private keys, and cloud credentials, using
a curated set of regex signatures.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python js_secret.py --url https://target.com/static/app.js
    python js_secret.py --url-list js_urls.txt
    python js_secret.py --file local_copy.js
"""

import argparse
import re
import sys

import requests

# (label, compiled regex) — kept intentionally readable/auditable rather
# than a giant opaque blob, so you can tune false positives per-target.
SIGNATURES = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key (heuristic)", re.compile(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Firebase URL", re.compile(r"\b[a-z0-9-]+\.firebaseio\.com\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe Key", re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Generic Bearer Token", re.compile(r"(?i)bearer\s+[a-z0-9\-_.]{20,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic API Key Assignment", re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]")),
    ("JWT-looking string", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]


def fetch_content(url, timeout):
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def read_local(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError as e:
        print(f"[!] Failed to read {path}: {e}", file=sys.stderr)
        return None


def line_number(content, index):
    return content.count("\n", 0, index) + 1


def scan_content(content, source_label):
    findings = []
    for label, pattern in SIGNATURES:
        for match in pattern.finditer(content):
            snippet = match.group(0)
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            findings.append({
                "source": source_label,
                "type": label,
                "line": line_number(content, match.start()),
                "match": snippet,
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Scan JavaScript files for hardcoded secrets.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Single JS file URL to scan")
    group.add_argument("--url-list", help="File with one JS URL per line")
    group.add_argument("--file", help="Local JS file to scan")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    args = parser.parse_args()

    sources = []  # list of (label, content)

    if args.file:
        content = read_local(args.file)
        if content is not None:
            sources.append((args.file, content))
    elif args.url:
        content = fetch_content(args.url, args.timeout)
        if content is not None:
            sources.append((args.url, content))
    elif args.url_list:
        try:
            with open(args.url_list, "r", encoding="utf-8", errors="ignore") as f:
                urls = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"[!] Could not read --url-list: {e}", file=sys.stderr)
            sys.exit(1)
        for url in urls:
            content = fetch_content(url, args.timeout)
            if content is not None:
                sources.append((url, content))

    if not sources:
        print("[!] Nothing was successfully loaded to scan.", file=sys.stderr)
        sys.exit(1)

    total_findings = 0
    for label, content in sources:
        findings = scan_content(content, label)
        print(f"[*] {label} — {len(content)} bytes, {len(findings)} finding(s)")
        for f in findings:
            print(f"    [{f['type']}] line {f['line']}: {f['match']}")
        total_findings += len(findings)

    print("-" * 60)
    if total_findings:
        print(f"[!] {total_findings} potential secret(s) found — verify each manually, regexes produce false positives.")
    else:
        print("[*] No matches from the current signature set.")


if __name__ == "__main__":
    main()
