# DNS Lookup Tool

Looks up DNS records for a domain: A, AAAA, MX, TXT, NS, CNAME, SOA.
Uses `dnspython` for full record-type support when installed, and
falls back to Python's built-in `socket` module (A/CNAME only) with
zero dependencies if `dnspython` isn't available — so it always works,
just with less detail without the extra package.

## Requirements
```
pip install dnspython   # optional, for full record-type support
```
Works with zero dependencies too (A/CNAME records only, via stdlib
`socket`).

## Usage
```bash
# All default record types
python dns_lookup.py target.com

# Specific record types only
python dns_lookup.py target.com --types A MX TXT

# Custom timeout
python dns_lookup.py target.com --timeout 10
```

## Why this over a one-liner `socket.gethostbyname`
- `MX` records reveal the mail provider (useful for phishing-sim
  scoping and email-security recon).
- `TXT` records often contain SPF/DKIM/DMARC policy, domain
  verification strings, and sometimes leaked internal info.
- `NS` records confirm the authoritative nameservers — useful before
  a subdomain-takeover check.
- `SOA` gives you the zone's primary nameserver and refresh/retry
  timers.

## Status
Part of a personal 100-tool security scripting project. The
zero-dependency socket fallback path was verified with a mocked
resolution. The `dnspython`-based multi-record path is standard
library usage of a well-established package but wasn't independently
re-verified in this environment — run once against a known domain to
confirm.

## License
MIT
