#!/usr/bin/env python3
"""
Broken Link Hijack Finder
---------------------------
Scrapes a page for external links, scripts, and other resource
references, then checks each one for signs it points to an
unclaimed/expired resource — a dangling GitHub Pages repo, an
unclaimed S3 bucket, an expired domain, etc. If you can legitimately
register/claim that resource, you can potentially serve content
under the original site's trust (script injection, phishing setup).

This tool only reports candidates — you still need to manually verify
that a given service/resource is actually claimable before acting.

Intended for use ONLY against systems you own or are explicitly
authorized to test.

Usage:
    python broken_link_hijack.py --url https://target.com
    python broken_link_hijack.py --url https://target.com --external-only
"""

import argparse
import socket
import sys
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

# Known "this resource doesn't exist, but the DNS name still resolves"
# fingerprints — a much stronger signal than a bare 404, since these
# specifically mean "the hosting service is waiting for someone to claim this".
DANGLING_FINGERPRINTS = {
    "github.io": ["There isn't a github pages site here"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "herokuapp.com": ["No such app"],
    "azurewebsites.net": ["Error 404 - Web app not found"],
    "readme.io": ["Project doesnt exist... yet!"],
    "surge.sh": ["project not found"],
    "shopify.com": ["Sorry, this shop is currently unavailable"],
    "wordpress.com": ["Do you want to register"],
    "fastly.net": ["Fastly error: unknown domain"],
    "pantheonsite.io": ["The gods are wise"],
    "zendesk.com": ["Help Center Closed"],
}

TAG_ATTRS = [("a", "href"), ("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src")]


def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag_name, attr in TAG_ATTRS:
        for tag in soup.find_all(tag_name):
            value = tag.get(attr)
            if not value:
                continue
            full_url = urljoin(base_url, value)
            if full_url.startswith("http"):
                links.add(full_url)
    return links


def is_external(link, base_domain):
    return urlparse(link).netloc != base_domain and urlparse(link).netloc != ""


def dns_resolves(hostname):
    # netloc can include a port (e.g. "host:8080") or userinfo — strip both before resolving
    host_only = hostname.split("@")[-1].split(":")[0]
    try:
        socket.gethostbyname(host_only)
        return True
    except socket.gaierror:
        return False


def check_link(session, link, timeout):
    hostname = urlparse(link).netloc
    result = {"link": link, "hostname": hostname}

    if not dns_resolves(hostname):
        result["verdict"] = "NXDOMAIN"
        result["detail"] = "Hostname does not resolve at all — domain likely expired, could potentially be re-registered."
        return result

    try:
        resp = session.get(link, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        result["verdict"] = "UNREACHABLE"
        result["detail"] = str(e)
        return result

    body_lower = resp.text.lower() if resp.text else ""
    host_only = hostname.split("@")[-1].split(":")[0]
    for service_suffix, fingerprints in DANGLING_FINGERPRINTS.items():
        if service_suffix in host_only:
            for fp in fingerprints:
                if fp.lower() in body_lower:
                    result["verdict"] = "DANGLING"
                    result["detail"] = f"Matches known '{service_suffix}' unclaimed-resource fingerprint: {fp!r}"
                    return result

    if resp.status_code == 404:
        result["verdict"] = "404"
        result["detail"] = f"Resolves fine but returns 404 — not necessarily hijackable, verify manually for this service ({hostname})."
        return result

    result["verdict"] = "OK"
    result["detail"] = f"status={resp.status_code}"
    return result


def main():
    parser = argparse.ArgumentParser(description="Scrape a page and check its linked resources for dangling/hijackable references.")
    parser.add_argument("--url", required=True, help="Page URL to scrape")
    parser.add_argument("--external-only", action="store_true", help="Only check links pointing to a different domain than --url")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-link request timeout in seconds")
    args = parser.parse_args()

    base_domain = urlparse(args.url).netloc

    try:
        resp = requests.get(args.url, timeout=args.timeout)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Could not fetch {args.url}: {e}", file=sys.stderr)
        sys.exit(1)

    links = extract_links(resp.text, args.url)
    if args.external_only:
        links = {l for l in links if is_external(l, base_domain)}

    print(f"[*] Found {len(links)} resource link(s) to check")
    print("-" * 60)

    findings = {"DANGLING": [], "NXDOMAIN": [], "404": [], "UNREACHABLE": []}
    with requests.Session() as session:
        for link in sorted(links):
            result = check_link(session, link, args.timeout)
            verdict = result["verdict"]
            if verdict == "OK":
                continue
            findings.setdefault(verdict, []).append(result)
            tag = {"DANGLING": "[!!! HIJACKABLE]", "NXDOMAIN": "[EXPIRED DOMAIN]",
                   "404": "[404]", "UNREACHABLE": "[DEAD]"}.get(verdict, f"[{verdict}]")
            print(f"{tag} {result['link']}")
            print(f"    {result['detail']}")

    print("-" * 60)
    high_confidence = len(findings["DANGLING"]) + len(findings["NXDOMAIN"])
    if high_confidence:
        print(f"[!] {high_confidence} high-confidence hijack candidate(s) — verify claimability manually before acting.")
    else:
        print("[*] No high-confidence dangling references found (some plain 404s may still be worth a manual look).")


if __name__ == "__main__":
    main()
