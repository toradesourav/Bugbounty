# Robots.txt & Sitemap Parser

Fetches and parses a site's `robots.txt` and `sitemap.xml` — a
classic, zero-noise recon step. `Disallow` entries often point at
admin panels, staging areas, or internal tools the site owner didn't
want indexed (but which are still perfectly reachable if you request
them directly), and sitemaps hand you the site's structure for free.

## Requirements
```
pip install requests
```

## Usage
```bash
# Fetch and parse both robots.txt and sitemap.xml
python robots_sitemap_parser.py --url https://target.com

# Skip robots.txt, only parse the sitemap
python robots_sitemap_parser.py --url https://target.com --sitemap-only
```

## What it does
1. Fetches `robots.txt`, parses every `Disallow`/`Allow` entry per
   user-agent, and flags paths containing interesting keywords
   (`admin`, `internal`, `staging`, `config`, `backup`, `debug`, etc.).
2. Follows any `Sitemap:` reference found in `robots.txt` (falls back
   to guessing `/sitemap.xml` if none is declared).
3. Parses the sitemap — including **sitemap index files** that point
   to multiple nested sitemaps, which it recurses into automatically
   (up to 2 levels deep) — and lists every URL found.

## Notes
- A `Disallow` entry is a **hint**, not proof of anything sensitive —
  always verify manually what's actually at that path before treating
  it as a finding.
- Sitemap parsing is namespace-agnostic, so it works whether the XML
  declares the standard sitemap namespace or not.

## Status
Part of a personal 100-tool security scripting project. Verified
end-to-end against a local mock server with a `robots.txt` containing
4 Disallow entries (3 flagged for interesting keywords) and a sitemap
index file that nests 2 further sitemaps — recursion correctly
aggregated all 3 URLs across both nested files.

## License
MIT
