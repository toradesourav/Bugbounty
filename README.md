# Wayback URL Harvester

Pulls historical URLs for a domain from the Internet Archive's Wayback
Machine CDX API. Classic recon step for finding old/forgotten
endpoints, exposed backup files, JS files with hardcoded secrets, or
admin panels that may still be reachable but no longer linked
anywhere.

## ⚠️ Authorized use only
Only use against domains you own or have explicit written permission
to test/recon.

## Requirements
```
pip install requests
```

## Usage
```bash
# All archived URLs for a domain (incl. subdomains)
python wayback.py --domain target.com

# Only JavaScript files
python wayback.py --domain target.com --ext js --output js_urls.txt

# Only URLs containing "admin"
python wayback.py --domain target.com --keyword admin

# Exact domain only, no subdomains
python wayback.py --domain target.com --no-subdomains
```

## Notes
- Uses the public `web.archive.org/cdx/search/cdx` endpoint — no API
  key required, but be considerate of request volume.
- Large/popular domains can return tens of thousands of URLs; use
  `--ext` / `--keyword` to narrow results.
- This only lists URLs that were *archived* at some point — always
  verify liveness separately (e.g. a simple status-code check) before
  treating a result as a current finding.

## Status
Part of a personal 100-tool security scripting project. Script logic
verified (argument parsing, filtering, output writing); the live CDX
API call should be tested with an active internet connection.

## License
MIT
