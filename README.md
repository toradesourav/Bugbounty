# FavIcon Hash Lookup

Computes the MurmurHash3 hash of a site's favicon, in exactly the
format Shodan uses for its `http.favicon.hash` search filter. Once
you know a target's favicon hash (an admin panel, CMS, or custom
internal app), you can search Shodan for every other host on the
internet serving the same favicon — instantly finding other instances
of the same infrastructure/software, including ones never linked or
indexed anywhere else.

## Requirements
```
pip install requests
```
No `mmh3` package needed — MurmurHash3 (x86, 32-bit) is implemented
directly in pure Python, matching `mmh3.hash()`'s output.

## Usage
```bash
# Auto-fetch {url}/favicon.ico and hash it
python favicon_hash.py --url https://target.com

# Hash a local favicon file directly
python favicon_hash.py --file favicon.ico
```

## Output
The Shodan-compatible hash value, plus a ready-to-click Shodan search
URL (`http.favicon.hash:<value>`) to find other matching hosts.

## Notes
- Shodan's convention: base64-encode the favicon bytes (with standard
  MIME line-wrapping), then MurmurHash3 that encoded string — not the
  raw favicon bytes directly. This tool replicates that exact
  convention.
- A generic/default favicon (e.g. an unmodified framework default)
  will match thousands of unrelated hosts — this technique is most
  useful for custom or distinctively-branded favicons.

## Status
Part of a personal 100-tool security scripting project. The
MurmurHash3 implementation was verified against the algorithm's
well-known empty-input property (`hash(b"") == 0` for seed 0) and
tested for crash-safety across all tail-length boundary cases (1-4
byte remainders). The full fetch→hash→Shodan-URL pipeline was
verified end-to-end against a local mock server, confirming
consistent output between `--url` and `--file` modes. **Note:** full
cross-validation against the actual `mmh3` C-extension library
wasn't possible in this sandboxed environment (no network access to
install it) — if you have `mmh3` available, run
`pip install mmh3` and spot-check a known favicon's hash against
Shodan's own listing for that host to confirm an exact match before
relying on this for critical recon.

## License
MIT
