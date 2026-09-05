#!/usr/bin/env python3
"""
Google Dork Generator
------------------------
Generates a categorized list of Google dork queries for a target
domain — the standard OSINT step for finding exposed files, login
pages, error messages, and misconfigurations that are indexed but not
meant to be publicly found. Doesn't perform the searches itself
(Google blocks automated scraping); it prints ready-to-paste queries
and, optionally, direct search URLs.

Usage:
    python google_dork_gen.py --domain target.com
    python google_dork_gen.py --domain target.com --category files
    python google_dork_gen.py --domain target.com --urls --output dorks.txt
"""

import argparse
import sys
import urllib.parse

DORK_CATEGORIES = {
    "files": [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:doc OR filetype:docx',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:log',
        'site:{domain} filetype:env',
        'site:{domain} filetype:bak OR filetype:backup',
        'site:{domain} filetype:conf OR filetype:config',
        'site:{domain} ext:xml | ext:json | ext:yml',
    ],
    "login": [
        'site:{domain} inurl:login',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:signin',
        'site:{domain} intitle:"login" OR intitle:"sign in"',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:portal',
    ],
    "errors": [
        'site:{domain} intext:"sql syntax near"',
        'site:{domain} intext:"warning: mysql"',
        'site:{domain} intext:"unhandled exception"',
        'site:{domain} intext:"stack trace"',
        'site:{domain} intitle:"index of /"',
    ],
    "exposed-data": [
        'site:{domain} intext:"password" filetype:log',
        'site:{domain} intext:"api_key" OR intext:"apikey"',
        'site:{domain} intext:"BEGIN RSA PRIVATE KEY"',
        'site:{domain} inurl:wp-config.php.bak',
        'site:{domain} intext:"aws_secret_access_key"',
    ],
    "subdomains-and-scope": [
        'site:*.{domain} -site:www.{domain}',
        'site:{domain} -inurl:www',
    ],
    "cloud-storage": [
        'site:s3.amazonaws.com "{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:storage.googleapis.com "{domain}"',
        'site:drive.google.com "{domain}"',
    ],
    "code-leaks": [
        'site:pastebin.com "{domain}"',
        'site:github.com "{domain}" password',
        'site:github.com "{domain}" api_key',
        'site:trello.com "{domain}"',
    ],
}


def generate_dorks(domain, categories):
    result = {}
    for category in categories:
        templates = DORK_CATEGORIES[category]
        result[category] = [t.format(domain=domain) for t in templates]
    return result


def to_search_url(query):
    return "https://www.google.com/search?q=" + urllib.parse.quote(query)


def main():
    parser = argparse.ArgumentParser(description="Generate categorized Google dork queries for a target domain.")
    parser.add_argument("--domain", required=True, help="Target domain, e.g. target.com")
    parser.add_argument("--category", choices=list(DORK_CATEGORIES) + ["all"], default="all",
                         help="Dork category to generate (default: all)")
    parser.add_argument("--urls", action="store_true", help="Also print ready-to-click Google search URLs")
    parser.add_argument("--output", help="Save the query list to this file, one per line")
    args = parser.parse_args()

    categories = list(DORK_CATEGORIES) if args.category == "all" else [args.category]
    dorks_by_category = generate_dorks(args.domain, categories)

    all_queries = []
    for category, queries in dorks_by_category.items():
        print(f"[{category}]")
        for q in queries:
            print(f"    {q}")
            if args.urls:
                print(f"        -> {to_search_url(q)}")
            all_queries.append(q)
        print()

    print(f"[*] {len(all_queries)} dork(s) generated across {len(categories)} category/categories.")
    print("[*] Note: Google actively rate-limits/blocks automated querying — paste these")
    print("    manually into a browser rather than scripting requests against Google itself.")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(all_queries) + "\n")
            print(f"[*] Saved to {args.output}")
        except OSError as e:
            print(f"[!] Could not write output file: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
