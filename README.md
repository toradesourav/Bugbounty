# IP Geolocation + ASN Lookup

Looks up geolocation and ASN (Autonomous System Number) info for an
IP address using [ip-api.com](https://ip-api.com)'s free endpoint —
no API key required. Useful for identifying hosting providers/cloud
regions, spotting CDN-fronted IPs, and mapping a target's
infrastructure footprint across multiple discovered IPs.

## Requirements
```
pip install requests
```

## Usage
```bash
# Single IP
python ip_geolocation.py --ip 8.8.8.8

# Batch from a file
python ip_geolocation.py --ip-list ips.txt --delay 1.5
```

## What it shows
City/region/country/zip, lat/lon coordinates, ISP, organization, and
ASN (with the AS name) — useful for spotting things like "this IP
resolves to Cloudflare's AS, so the origin server is hidden behind
their proxy" or grouping a subdomain list by hosting provider.

## Notes
- Uses the free tier of ip-api.com, which is rate-limited (default
  `--delay 1.5` between batch requests to stay well under it — check
  ip-api.com's current limits since these can change).
- No API key needed for basic lookups; ip-api.com does offer a paid
  tier with higher limits and HTTPS if you need that.

## Status
Part of a personal 100-tool security scripting project. Response
parsing verified against ip-api.com's documented JSON schema for both
the success case (full geolocation/ASN data) and the failure case
(invalid IP query) — both handled correctly without crashing.

## License
MIT
