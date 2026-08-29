#!/usr/bin/env python3
"""
S3 Bucket Scanner
-------------------
Checks S3 buckets for public-read misconfigurations. Two modes:
  1. --bucket-list: check specific bucket names/URLs you already have
  2. --keyword: auto-generate common bucket-name permutations from a
     company/project name (the standard bug-bounty S3 recon approach,
     since bucket names are global and predictable naming conventions
     like "company-backup" or "company-dev" are extremely common)

This only sends GET requests (read-only recon) — it does NOT attempt
to write/upload/delete anything, which would require separate,
explicit authorization even in a bug bounty program.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python s3_scanner.py --bucket-list buckets.txt
    python s3_scanner.py --keyword acmecorp
    python s3_scanner.py --keyword acmecorp --region us-west-2
"""

import argparse
import sys

import requests

COMMON_SUFFIXES = [
    "", "-dev", "-prod", "-production", "-staging", "-test", "-backup",
    "-backups", "-assets", "-static", "-media", "-uploads", "-files",
    "-data", "-logs", "-private", "-public", "-internal", "-www",
    "-web", "-app", "-api", "-config", "-secrets", "-db", "-archive",
]


def generate_bucket_names(keyword):
    keyword = keyword.lower().strip()
    names = set()
    for suffix in COMMON_SUFFIXES:
        names.add(f"{keyword}{suffix}")
        names.add(f"{suffix.lstrip('-')}-{keyword}" if suffix else keyword)
    return sorted(n for n in names if n and n != "-")


def bucket_url(bucket_name, region):
    if region and region != "us-east-1":
        return f"https://{bucket_name}.s3.{region}.amazonaws.com"
    return f"https://{bucket_name}.s3.amazonaws.com"


def check_bucket(session, url, timeout):
    try:
        resp = session.get(url, timeout=timeout)
    except requests.RequestException as e:
        return {"url": url, "verdict": "ERROR", "detail": str(e)}

    body = resp.text

    if resp.status_code == 200 and ("<ListBucketResult" in body or "<Contents>" in body):
        # Count listed objects as a rough sense of exposure size
        object_count = body.count("<Key>")
        return {"url": url, "verdict": "PUBLIC_LISTABLE", "detail": f"{object_count} object(s) visible in listing", "status": 200}

    if resp.status_code == 403:
        # Bucket exists (AWS returns 403 for both "exists but private" and
        # "exists, listing denied but objects may still be individually readable")
        return {"url": url, "verdict": "EXISTS_PRIVATE", "detail": "403 Forbidden — bucket exists but listing is denied", "status": 403}

    if resp.status_code == 404:
        if "NoSuchBucket" in body:
            return {"url": url, "verdict": "NOT_FOUND", "detail": "NoSuchBucket — name is available, not currently in use", "status": 404}
        return {"url": url, "verdict": "NOT_FOUND", "detail": "404 response", "status": 404}

    return {"url": url, "verdict": "OTHER", "detail": f"status={resp.status_code}", "status": resp.status_code}


def main():
    parser = argparse.ArgumentParser(description="Check S3 buckets for public-read misconfigurations (read-only).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--keyword", help="Company/project name to generate common bucket-name permutations from")
    group.add_argument("--bucket-list", help="File with one bucket name (or full URL) per line")
    parser.add_argument("--region", default="us-east-1", help="AWS region for generated URLs (default: us-east-1)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds")
    parser.add_argument("--show-all", action="store_true", help="Show every result, not just interesting ones (PUBLIC_LISTABLE / EXISTS_PRIVATE)")
    args = parser.parse_args()

    if args.keyword:
        names = generate_bucket_names(args.keyword)
        urls = [bucket_url(name, args.region) for name in names]
        print(f"[*] Generated {len(urls)} bucket-name permutations from '{args.keyword}'")
    else:
        try:
            with open(args.bucket_list, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip()]
        except OSError as e:
            print(f"[!] Could not read --bucket-list: {e}", file=sys.stderr)
            sys.exit(1)
        urls = [line if line.startswith("http") else bucket_url(line, args.region) for line in lines]
        print(f"[*] Checking {len(urls)} bucket(s) from {args.bucket_list}")

    print("-" * 60)

    public_count = 0
    with requests.Session() as session:
        for url in urls:
            result = check_bucket(session, url, args.timeout)
            verdict = result["verdict"]

            if verdict == "PUBLIC_LISTABLE":
                public_count += 1
                print(f"[!!! PUBLIC] {url}")
                print(f"             {result['detail']}")
            elif verdict == "EXISTS_PRIVATE" and args.show_all:
                print(f"[ exists  ] {url}  ({result['detail']})")
            elif args.show_all:
                print(f"[ {verdict:<10}] {url}  ({result['detail']})")

    print("-" * 60)
    print(f"[*] {public_count} publicly-listable bucket(s) found out of {len(urls)} checked.")
    if not args.show_all:
        print("[*] Use --show-all to see every result including private/not-found buckets.")


if __name__ == "__main__":
    main()
