#!/usr/bin/env python3
"""
Hash Identifier & Cracker
---------------------------
Identifies the likely algorithm behind a hash (by length + character
set) and, if a wordlist is provided, attempts a dictionary attack —
i.e. hashes each wordlist entry and checks for a match. This is the
same principle as `hashid` + a basic dictionary mode of `hashcat`.

Only dictionary lookups against hashes you already have (e.g. from an
authorized pentest engagement, a CTF, or your own test data) — this
does not attack a live authentication system or attempt to bypass any
rate limiting.

Usage:
    python hash_identifier.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
    python hash_identifier.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou-sample.txt
    python hash_identifier.py --hash-list hashes.txt --wordlist wordlist.txt
"""

import argparse
import hashlib
import re
import sys

# (algorithm name, hex length, regex, hashlib name or None if unsupported for cracking here)
HASH_SIGNATURES = [
    ("MD5", 32, re.compile(r"^[a-f0-9]{32}$", re.I), "md5"),
    ("SHA-1", 40, re.compile(r"^[a-f0-9]{40}$", re.I), "sha1"),
    ("SHA-224", 56, re.compile(r"^[a-f0-9]{56}$", re.I), "sha224"),
    ("SHA-256", 64, re.compile(r"^[a-f0-9]{64}$", re.I), "sha256"),
    ("SHA-384", 96, re.compile(r"^[a-f0-9]{96}$", re.I), "sha384"),
    ("SHA-512", 128, re.compile(r"^[a-f0-9]{128}$", re.I), "sha512"),
    ("NTLM (same length as MD5 — context needed)", 32, re.compile(r"^[a-f0-9]{32}$", re.I), None),
    ("bcrypt", None, re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), None),
    ("MySQL 4.1+ (SHA1-based)", 41, re.compile(r"^\*[A-F0-9]{40}$"), None),
]


def identify(hash_str):
    matches = []
    for name, length, pattern, algo in HASH_SIGNATURES:
        if pattern.match(hash_str):
            matches.append((name, algo))
    return matches


def crack(hash_str, algo, wordlist_path):
    try:
        hash_fn = getattr(hashlib, algo)
    except AttributeError:
        return None

    target = hash_str.lower()
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                candidate = line.rstrip("\n")
                if hash_fn(candidate.encode()).hexdigest() == target:
                    return candidate
    except OSError as e:
        print(f"[!] Could not read wordlist: {e}", file=sys.stderr)
        sys.exit(1)
    return None


def process_hash(hash_str, wordlist_path):
    hash_str = hash_str.strip()
    matches = identify(hash_str)

    print(f"[*] Hash: {hash_str}")
    if not matches:
        print("    No known algorithm matched this format.")
        return

    for name, algo in matches:
        print(f"    Possible match: {name}")

    if wordlist_path:
        # Try cracking with every crackable candidate algorithm (ambiguous lengths like
        # MD5/NTLM both get attempted since we can't tell them apart from the hash alone)
        cracked = False
        for name, algo in matches:
            if not algo:
                continue
            result = crack(hash_str, algo, wordlist_path)
            if result is not None:
                print(f"    [CRACKED as {name}] plaintext = {result!r}")
                cracked = True
                break
        if not cracked:
            print("    Not found in wordlist.")


def main():
    parser = argparse.ArgumentParser(description="Identify a hash's likely algorithm and optionally crack it via dictionary attack.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hash", help="A single hash to identify/crack")
    group.add_argument("--hash-list", help="File with one hash per line")
    parser.add_argument("--wordlist", help="Wordlist for dictionary-attack cracking (omit to only identify the algorithm)")
    args = parser.parse_args()

    if args.hash:
        process_hash(args.hash, args.wordlist)
        return

    try:
        with open(args.hash_list, "r", encoding="utf-8", errors="ignore") as f:
            hashes = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Could not read --hash-list: {e}", file=sys.stderr)
        sys.exit(1)

    for h in hashes:
        process_hash(h, args.wordlist)
        print("-" * 60)


if __name__ == "__main__":
    main()
