# Hash Identifier & Cracker

Identifies the likely algorithm behind a hash (by length and
character-set pattern) and, if a wordlist is provided, attempts a
dictionary attack — the same principle as `hashid` plus a basic
dictionary mode of `hashcat`.

## Scope
This only runs dictionary lookups against hashes you already have
(from an authorized pentest engagement, a CTF, your own test data,
etc.). It does not attack a live authentication system, does not
brute-force character-by-character, and does not attempt to bypass
any rate limiting.

## Requirements
Python 3 standard library only — no `pip install` needed.

## Usage
```bash
# Identify only (no wordlist)
python hash_identifier.py --hash 5f4dcc3b5aa765d61d8327deb882cf99

# Identify + dictionary crack
python hash_identifier.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou-sample.txt

# Batch mode
python hash_identifier.py --hash-list hashes.txt --wordlist wordlist.txt
```

## Algorithms detected
MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (all crackable via
dictionary), plus format-only identification for NTLM (same length as
MD5 — context needed to tell them apart), bcrypt, and MySQL 4.1+
password hashes.

## Notes
- MD5 and NTLM hashes are the same length and character set, so both
  are listed as possible matches — the tool tries cracking as MD5
  first since that's far more common outside Windows environments.
- bcrypt/MySQL hashes are identified by format but not crackable here
  — bcrypt's per-hash salt and deliberate slowness need a dedicated
  tool (e.g. `hashcat` with GPU support) for practical dictionary
  attacks.

## Status
Part of a personal 100-tool security scripting project. Verified
against real hashes of a known plaintext across all 6 crackable
algorithms (MD5 through SHA-512) — each correctly identified and
successfully cracked via a small test wordlist containing the
plaintext among distractors. bcrypt format detection verified against
a correctly-shaped sample string.

## License
MIT
