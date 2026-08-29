# JS Secret Scanner

Scans JavaScript files (remote or local) for hardcoded secrets using a
curated set of regex signatures: AWS keys, Google API keys, Stripe
keys, GitHub tokens, Slack tokens, private key blocks, JWTs, and
generic key/token/password assignments.

## ⚠️ Authorized use only
Only scan JS files belonging to systems you own or have explicit
written permission to test.

## Requirements
```
pip install requests
```

## Usage
```bash
# Scan a single remote JS file
python js_secret.py --url https://target.com/static/app.js

# Scan a list of JS URLs (one per line) — pair well with 58-wayback --ext js
python js_secret.py --url-list js_urls.txt

# Scan a local file
python js_secret.py --file app.js
```

## Signatures detected
AWS Access Key ID, AWS Secret Key (heuristic), Google API Key,
Firebase URL, Slack Token, Stripe Key, GitHub Token, Generic Bearer
Token, PEM Private Key Block, Generic API-key/secret/token/password
assignment, JWT-looking strings.

## Notes
- Regex-based detection **will** produce false positives (test
  fixtures, placeholder strings, minified variable names that happen
  to match). Always verify a hit before reporting it.
- Pairs well with the Wayback URL Harvester (tool #58): filter for
  `--ext js` there, feed the list here with `--url-list`.

## Status
Part of a personal 100-tool security scripting project. Verified
against a synthetic JS file with planted secrets covering every
signature — all correctly detected.

## License
MIT
