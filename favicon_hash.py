#!/usr/bin/env python3
"""
FavIcon Hash Lookup
----------------------
Computes the MurmurHash3 hash of a site's favicon, in exactly the
format Shodan uses for its `http.favicon.hash` search filter. This is
a powerful recon trick: once you know a target's favicon hash (e.g.
a specific admin panel, CMS, or custom app), you can search Shodan
for every other host on the internet serving the same favicon —
instantly finding other instances of the same infrastructure/software,
including ones that were never linked or indexed anywhere.

Implements MurmurHash3 (x86, 32-bit) in pure Python, matching the
`mmh3` library's output exactly, since `mmh3` isn't always available
as a pre-built wheel on every platform.

Usage:
    python favicon_hash.py --url https://target.com
    python favicon_hash.py --file favicon.ico
"""

import argparse
import base64
import sys

import requests


def murmurhash3_x86_32(data, seed=0):
    """Pure-Python port of MurmurHash3 (x86, 32-bit), matching mmh3.hash()."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)

    for i in range(0, roundedEnd, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
             ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 &= 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    if val in (2, 3):
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    if val in (1, 2, 3):
        k1 |= (data[roundedEnd] & 0xff)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # mmh3.hash() returns a SIGNED 32-bit int, which is what Shodan's
    # http.favicon.hash filter expects -- convert from unsigned.
    if h1 > 0x7fffffff:
        h1 -= 0x100000000
    return h1


def shodan_favicon_hash(favicon_bytes):
    # Shodan's convention: base64-encode the favicon, insert a newline every
    # 76 characters (standard MIME base64 line wrapping), then hash that.
    b64 = base64.encodebytes(favicon_bytes)
    return murmurhash3_x86_32(b64)


def fetch_favicon(url, timeout):
    base = url.rstrip("/")
    favicon_url = base + "/favicon.ico"
    try:
        resp = requests.get(favicon_url, timeout=timeout)
        if resp.status_code == 200 and resp.content:
            return resp.content, favicon_url
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {favicon_url}: {e}", file=sys.stderr)
    return None, favicon_url


def main():
    parser = argparse.ArgumentParser(description="Compute a Shodan-compatible favicon hash.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Site URL — fetches {url}/favicon.ico automatically")
    group.add_argument("--file", help="Local favicon.ico file to hash directly")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, "rb") as f:
                favicon_bytes = f.read()
        except OSError as e:
            print(f"[!] Could not read {args.file}: {e}", file=sys.stderr)
            sys.exit(1)
        source = args.file
    else:
        favicon_bytes, source = fetch_favicon(args.url, args.timeout)
        if favicon_bytes is None:
            print(f"[!] Could not fetch a favicon from {source}", file=sys.stderr)
            sys.exit(1)

    hash_value = shodan_favicon_hash(favicon_bytes)

    print(f"[*] Source: {source}")
    print(f"[*] Favicon size: {len(favicon_bytes)} bytes")
    print(f"[*] Shodan favicon hash: {hash_value}")
    print()
    print(f"[*] Search Shodan for other hosts with this exact favicon:")
    print(f"    https://www.shodan.io/search?query=http.favicon.hash%3A{hash_value}")


if __name__ == "__main__":
    main()
