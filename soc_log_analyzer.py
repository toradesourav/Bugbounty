#!/usr/bin/env python3
"""
SOC Log Analyzer — Brute Force Detector
-----------------------------------------
Parses auth logs (SSH/sshd-style "Failed password" lines, or any
custom log via --pattern) and flags source IPs with an excessive
number of failed login attempts — the classic first-pass brute-force
detection a SOC analyst builds.

Also supports a time-window mode: flag an IP only if its failures are
concentrated within a short window (a stronger signal than a raw
count, since it catches fast automated brute-forcing specifically).

Usage:
    python soc_log_analyzer.py --log auth.log
    python soc_log_analyzer.py --log auth.log --threshold 10
    python soc_log_analyzer.py --log auth.log --window-minutes 5 --threshold 5
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Matches common syslog-style timestamps, e.g. "Jan 15 03:22:11" or
# ISO-ish "2026-01-15T03:22:11". Falls back to no timestamp if unmatched.
TIMESTAMP_PATTERNS = [
    (re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    (re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
]

DEFAULT_FAIL_MARKERS = ["Failed password", "authentication failure", "Invalid user"]


def parse_timestamp(line, year_hint):
    for pattern, fmt in TIMESTAMP_PATTERNS:
        match = pattern.match(line.strip())
        if not match:
            continue
        raw = match.group(1).replace(" ", "T", 1) if "T" not in fmt else match.group(1)
        try:
            if "%Y" in fmt:
                return datetime.strptime(match.group(1), fmt)
            # syslog format has no year — assume year_hint (default: current year)
            dt = datetime.strptime(f"{year_hint} {match.group(1)}", f"%Y {fmt}")
            return dt
        except ValueError:
            continue
    return None


def extract_ip(line):
    matches = IP_RE.findall(line)
    return matches[0] if matches else None


def is_failure_line(line, markers):
    return any(marker.lower() in line.lower() for marker in markers)


def analyze(log_path, markers, threshold, window_minutes, year_hint):
    ip_failures = defaultdict(list)  # ip -> list of datetime (or None)
    total_fail_lines = 0

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not is_failure_line(line, markers):
                    continue
                total_fail_lines += 1
                ip = extract_ip(line)
                if not ip:
                    continue
                ts = parse_timestamp(line, year_hint)
                ip_failures[ip].append(ts)
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[!] Could not read log file: {e}", file=sys.stderr)
        sys.exit(1)

    flagged = []
    for ip, timestamps in ip_failures.items():
        count = len(timestamps)
        if count < threshold:
            continue

        if window_minutes and all(timestamps):
            timestamps.sort()
            # sliding window: does any `threshold`-sized run fit within window_minutes?
            window_hit = False
            for i in range(len(timestamps) - threshold + 1):
                span = (timestamps[i + threshold - 1] - timestamps[i]).total_seconds() / 60
                if span <= window_minutes:
                    window_hit = True
                    break
            if not window_hit:
                continue

        flagged.append((ip, count))

    flagged.sort(key=lambda x: x[1], reverse=True)
    return flagged, total_fail_lines, len(ip_failures)


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force login attempts from an auth log.")
    parser.add_argument("--log", required=True, help="Path to the log file (e.g. /var/log/auth.log)")
    parser.add_argument("--threshold", type=int, default=5, help="Minimum failed attempts to flag an IP (default: 5)")
    parser.add_argument("--window-minutes", type=int, help="Only flag if `threshold` failures occur within this many minutes (requires parseable timestamps)")
    parser.add_argument("--marker", action="append", help="Custom failure marker string to match, repeatable (default: common SSH failure phrases)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Year to assume for syslog-style timestamps without a year (default: current year)")
    parser.add_argument("--top", type=int, default=10, help="Show top N offending IPs (default: 10)")
    args = parser.parse_args()

    markers = args.marker if args.marker else DEFAULT_FAIL_MARKERS

    print(f"[*] Analyzing {args.log}")
    print(f"[*] Failure markers: {markers}")
    print(f"[*] Threshold: {args.threshold} failed attempts" +
          (f" within {args.window_minutes} min" if args.window_minutes else ""))
    print("-" * 60)

    flagged, total_fail_lines, unique_ips = analyze(
        args.log, markers, args.threshold, args.window_minutes, args.year
    )

    print(f"[*] Total failure lines matched: {total_fail_lines}")
    print(f"[*] Unique source IPs with failures: {unique_ips}")
    print("-" * 60)

    if not flagged:
        print("[*] No IPs met the brute-force threshold.")
        return

    print("[!] Potential brute-force attackers:")
    for ip, count in flagged[:args.top]:
        print(f"    {ip:<20} {count} failed attempts  [BLOCK / INVESTIGATE]")


if __name__ == "__main__":
    main()
