#!/usr/bin/env python3
"""
Tech Stack Detector
----------------------
Fingerprints the technologies a website runs on — CMS, JS frameworks,
web server, analytics, CDN — by checking response headers, HTML meta
tags, script src patterns, and cookie names against a signature
database. A lightweight Wappalyzer-style tool; useful recon for
picking known-CVE targets once you know the exact stack.

Usage:
    python tech_detector.py --url https://target.com
"""

import argparse
import re
import sys

import requests

# (category, technology, signature_type, pattern)
# signature_type: "header", "header_value", "html", "cookie", "meta"
SIGNATURES = [
    ("CMS", "WordPress", "html", re.compile(r"wp-content|wp-includes", re.I)),
    ("CMS", "WordPress", "meta", re.compile(r'generator["\']\s*content=["\']WordPress', re.I)),
    ("CMS", "Joomla", "html", re.compile(r"/media/jui/|Joomla!", re.I)),
    ("CMS", "Drupal", "header", "X-Generator"),
    ("CMS", "Drupal", "html", re.compile(r"Drupal\.settings|/sites/default/files", re.I)),
    ("CMS", "Shopify", "html", re.compile(r"cdn\.shopify\.com", re.I)),
    ("CMS", "Wix", "html", re.compile(r"static\.wixstatic\.com", re.I)),
    ("CMS", "Squarespace", "html", re.compile(r"squarespace\.com|static1\.squarespace", re.I)),

    ("JS Framework", "React", "html", re.compile(r"__REACT_DEVTOOLS|data-reactroot|react-dom", re.I)),
    ("JS Framework", "Vue.js", "html", re.compile(r"__vue__|data-v-[a-f0-9]{8}|vue\.js", re.I)),
    ("JS Framework", "Angular", "html", re.compile(r"ng-version|ng-app|angular\.js", re.I)),
    ("JS Framework", "Next.js", "html", re.compile(r"__NEXT_DATA__|/_next/static", re.I)),
    ("JS Framework", "jQuery", "html", re.compile(r"jquery(\.min)?\.js", re.I)),

    ("Web Server", "nginx", "header_value", ("Server", re.compile(r"nginx", re.I))),
    ("Web Server", "Apache", "header_value", ("Server", re.compile(r"apache", re.I))),
    ("Web Server", "Microsoft-IIS", "header_value", ("Server", re.compile(r"microsoft-iis", re.I))),
    ("Web Server", "LiteSpeed", "header_value", ("Server", re.compile(r"litespeed", re.I))),

    ("Language/Runtime", "PHP", "header", "X-Powered-By"),
    ("Language/Runtime", "ASP.NET", "header", "X-AspNet-Version"),
    ("Language/Runtime", "Express (Node.js)", "header_value", ("X-Powered-By", re.compile(r"express", re.I))),

    ("CDN/Proxy", "Cloudflare", "header_value", ("Server", re.compile(r"cloudflare", re.I))),
    ("CDN/Proxy", "Cloudflare", "header", "CF-Ray"),
    ("CDN/Proxy", "Fastly", "header", "X-Served-By"),
    ("CDN/Proxy", "Akamai", "header", "X-Akamai-Transformed"),

    ("Analytics", "Google Analytics", "html", re.compile(r"google-analytics\.com/analytics\.js|gtag\(", re.I)),
    ("Analytics", "Google Tag Manager", "html", re.compile(r"googletagmanager\.com/gtm\.js", re.I)),
    ("Analytics", "Hotjar", "html", re.compile(r"static\.hotjar\.com", re.I)),
    ("Analytics", "Segment", "html", re.compile(r"cdn\.segment\.com", re.I)),

    ("Ecommerce", "WooCommerce", "html", re.compile(r"woocommerce", re.I)),
    ("Ecommerce", "Magento", "html", re.compile(r"Mage\.Cookies|/static/version", re.I)),

    ("Security", "reCAPTCHA", "html", re.compile(r"google\.com/recaptcha", re.I)),
    ("Security", "Cloudflare Turnstile", "html", re.compile(r"challenges\.cloudflare\.com/turnstile", re.I)),
]


def detect(headers, cookies, html):
    findings = []
    seen = set()

    for category, tech, sig_type, pattern in SIGNATURES:
        key = (category, tech)
        if key in seen:
            continue

        matched = False
        detail = None

        if sig_type == "header" and pattern in headers:
            matched = True
            detail = f"header '{pattern}' present"
        elif sig_type == "header_value":
            header_name, value_pattern = pattern
            value = headers.get(header_name, "")
            if value and value_pattern.search(value):
                matched = True
                detail = f"header '{header_name}: {value}'"
        elif sig_type == "html" and pattern.search(html):
            matched = True
            detail = "matched in page HTML"
        elif sig_type == "meta" and pattern.search(html):
            matched = True
            detail = "matched in meta tag"
        elif sig_type == "cookie":
            if any(pattern.search(c) for c in cookies):
                matched = True
                detail = "matched in cookie name"

        if matched:
            seen.add(key)
            findings.append((category, tech, detail))

    return findings


def main():
    parser = argparse.ArgumentParser(description="Fingerprint the technology stack behind a website.")
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://target.com")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    try:
        resp = requests.get(args.url, timeout=args.timeout)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    cookie_names = list(resp.cookies.keys())
    findings = detect(resp.headers, cookie_names, resp.text)

    print(f"[*] {args.url} -> HTTP {resp.status_code}")
    print("-" * 60)

    if not findings:
        print("[*] No known technology signatures matched.")
        return

    by_category = {}
    for category, tech, detail in findings:
        by_category.setdefault(category, []).append((tech, detail))

    for category, techs in by_category.items():
        print(f"[{category}]")
        for tech, detail in techs:
            print(f"    {tech:<28} ({detail})")

    print("-" * 60)
    print(f"[*] {len(findings)} technology signature(s) detected across {len(by_category)} categories.")


if __name__ == "__main__":
    main()
