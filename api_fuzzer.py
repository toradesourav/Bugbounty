#!/usr/bin/env python3
"""
API Fuzzer
----------
Fuzzes a REST API endpoint by substituting a wordlist of values into a
placeholder in the URL (e.g. an ID, filename, or path segment) and
reports interesting responses (status code, response length, timing).

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python api_fuzzer.py --url "https://target.com/api/user/FUZZ" \\
        --wordlist wordlist.txt --method GET

    python api_fuzzer.py --url "https://target.com/api/user/FUZZ" \\
        --wordlist wordlist.txt --header "Authorization: Bearer TOKEN" \\
        --threads 5 --timeout 5
"""

import argparse
import concurrent.futures
import sys
import time
from dataclasses import dataclass

import requests

FUZZ_MARKER = "FUZZ"


@dataclass
class FuzzResult:
    payload: str
    status_code: int
    length: int
    elapsed_ms: float
    error: str = ""


def parse_headers(header_args):
    headers = {}
    for h in header_args or []:
        if ":" not in h:
            print(f"[!] Skipping malformed header: {h}", file=sys.stderr)
            continue
        key, _, value = h.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Could not read wordlist: {e}", file=sys.stderr)
        sys.exit(1)


def send_request(session, url_template, method, payload, headers, timeout, data):
    url = url_template.replace(FUZZ_MARKER, payload)
    body = data.replace(FUZZ_MARKER, payload) if data else None
    start = time.time()
    try:
        resp = session.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=timeout,
            allow_redirects=False,
        )
        elapsed_ms = (time.time() - start) * 1000
        return FuzzResult(payload, resp.status_code, len(resp.content), round(elapsed_ms, 1))
    except requests.RequestException as e:
        elapsed_ms = (time.time() - start) * 1000
        return FuzzResult(payload, 0, 0, round(elapsed_ms, 1), error=str(e))


def run_fuzzer(url, wordlist, method, headers, timeout, data, threads, filter_codes):
    if FUZZ_MARKER not in url and (not data or FUZZ_MARKER not in data):
        print(f"[!] No '{FUZZ_MARKER}' marker found in --url or --data. "
              f"Add {FUZZ_MARKER} where you want payloads inserted.", file=sys.stderr)
        sys.exit(1)

    results = []
    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [
                pool.submit(send_request, session, url, method, payload, headers, timeout, data)
                for payload in wordlist
            ]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

    results.sort(key=lambda r: wordlist.index(r.payload) if r.payload in wordlist else 0)

    for r in results:
        if r.error:
            print(f"[ERR ] {r.payload:<30} {r.error}")
            continue
        if filter_codes and r.status_code not in filter_codes:
            continue
        marker = "  <-- interesting" if r.status_code in (200, 201, 301, 302, 403) else ""
        print(f"[{r.status_code:>3}] {r.payload:<30} len={r.length:<8} {r.elapsed_ms}ms{marker}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Fuzz an API endpoint with a wordlist. Requires the FUZZ marker in --url or --data."
    )
    parser.add_argument("--url", required=True, help="Target URL containing the FUZZ marker, e.g. https://target.com/api/user/FUZZ")
    parser.add_argument("--wordlist", required=True, help="Path to a newline-separated wordlist file")
    parser.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "DELETE", "PATCH"], help="HTTP method (default: GET)")
    parser.add_argument("--data", help="Request body, may also contain the FUZZ marker")
    parser.add_argument("--header", action="append", help='Extra header, e.g. --header "Authorization: Bearer xyz". Repeatable.')
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=1, help="Concurrent requests (default: 1, be considerate of target load)")
    parser.add_argument("--filter-code", type=int, action="append", help="Only show responses with this status code. Repeatable.")
    args = parser.parse_args()

    headers = parse_headers(args.header)
    wordlist = load_wordlist(args.wordlist)

    if not wordlist:
        print("[!] Wordlist is empty.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Target: {args.url}")
    print(f"[*] Method: {args.method}  Payloads: {len(wordlist)}  Threads: {args.threads}")
    print("-" * 60)

    run_fuzzer(
        url=args.url,
        wordlist=wordlist,
        method=args.method,
        headers=headers,
        timeout=args.timeout,
        data=args.data,
        threads=args.threads,
        filter_codes=set(args.filter_code) if args.filter_code else None,
    )


if __name__ == "__main__":
    main()
