#!/usr/bin/env python3
"""
Directory & Sensitive File Finder
-----------------------------------
Brute-forces common paths (admin panels, .env files, backups, git
metadata, API docs, etc.) against a target and reports anything that
responds interestingly. Multi-threaded, supports custom wordlists.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python dir_finder.py --url https://target.com
    python dir_finder.py --url https://target.com --wordlist paths.txt --threads 10
    python dir_finder.py --url https://target.com --status 200 403
"""

import argparse
import concurrent.futures
import sys

import requests

DEFAULT_PATHS = [
    "admin", "admin/login", "login", "dashboard", "wp-admin",
    ".env", ".env.local", ".env.production",
    ".git/", ".git/config", ".git/HEAD",
    ".svn/", ".DS_Store",
    "backup.zip", "backup.sql", "backup.tar.gz", "db.sql", "dump.sql",
    "config.php", "config.json", "config.yml", "settings.py",
    "api/", "api/v1/", "api/docs", "swagger/", "swagger.json", "swagger-ui.html",
    "robots.txt", "sitemap.xml", "humans.txt",
    "debug/", "debug.log", "error_log", "phpinfo.php",
    ".htaccess", "web.config",
    "server-status", "actuator", "actuator/health",
    "test/", "staging/", "old/", "tmp/",
]

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403}


def load_wordlist(path):
    if not path:
        return list(DEFAULT_PATHS)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Could not read wordlist: {e}", file=sys.stderr)
        sys.exit(1)


def check_path(session, base_url, path, timeout, headers):
    full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = session.get(full_url, timeout=timeout, headers=headers, allow_redirects=False)
        return {"url": full_url, "status": resp.status_code, "length": len(resp.content)}
    except requests.RequestException as e:
        return {"url": full_url, "error": str(e)}


def run_scan(base_url, wordlist, threads, timeout, headers, status_filter):
    results = []
    with requests.Session() as session:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [
                pool.submit(check_path, session, base_url, path, timeout, headers)
                for path in wordlist
            ]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

    codes_to_show = status_filter if status_filter else INTERESTING_CODES
    found = [r for r in results if not r.get("error") and r["status"] in codes_to_show]
    found.sort(key=lambda r: r["url"])

    for r in found:
        print(f"[{r['status']}] {r['url']}  (len={r['length']})")

    return found


def main():
    parser = argparse.ArgumentParser(description="Brute-force common/sensitive paths against a target.")
    parser.add_argument("--url", required=True, help="Base target URL, e.g. https://target.com")
    parser.add_argument("--wordlist", help="Path to a custom wordlist (default: built-in common-paths list)")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent requests (default: 10)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5)")
    parser.add_argument("--header", action="append", help='Extra header, e.g. --header "Authorization: Bearer xyz". Repeatable.')
    parser.add_argument("--status", type=int, nargs="+", help="Only show these status codes (default: common interesting set)")
    args = parser.parse_args()

    headers = {}
    for h in args.header or []:
        if ":" not in h:
            print(f"[!] Skipping malformed header: {h}", file=sys.stderr)
            continue
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    wordlist = load_wordlist(args.wordlist)
    status_filter = set(args.status) if args.status else None

    print(f"[*] Target: {args.url}")
    print(f"[*] Paths to check: {len(wordlist)}  Threads: {args.threads}")
    print("-" * 60)

    found = run_scan(args.url, wordlist, args.threads, args.timeout, headers, status_filter)

    print("-" * 60)
    print(f"[+] Done. {len(found)} interesting path(s) found.")


if __name__ == "__main__":
    main()
