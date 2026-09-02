# WAF Detector

Identifies which Web Application Firewall (if any) sits in front of a
target, using two techniques:

1. **Passive header/cookie fingerprinting** — checks the normal
   response for WAF-specific signatures (Cloudflare's `cf-ray`,
   Sucuri's `X-Sucuri-ID`, Incapsula's `visid_incap` cookie, etc.).
2. **Active provocation** — sends a deliberately malicious-looking
   request (classic SQLi + XSS + path-traversal payload combined) and
   checks whether the WAF blocks it with a recognizable challenge/
   block page. Many WAFs stay completely invisible on clean requests
   and only reveal themselves when provoked.

Knowing the WAF in front of a target tells you what evasion research
to focus on, and sets realistic expectations for how aggressive
scanning can be before you get blocked entirely.

## ⚠️ Authorized use only
Only use against systems you own or have explicit written permission
to test. The provocation payload is designed to trigger WAF rules,
not to exploit anything — but sending it still counts as an attack
signature on the wire, so don't run this against anything you're not
authorized to test.

## Requirements
```
pip install requests
```

## Usage
```bash
python waf_detector.py --url https://target.com

# Passive-only (skip sending the malicious provocation payload)
python waf_detector.py --url https://target.com --skip-provocation
```

## WAFs detected
Cloudflare, Sucuri, Akamai, Imperva/Incapsula, AWS WAF/CloudFront,
F5 BIG-IP ASM, Barracuda, Fortinet FortiWeb, Citrix NetScaler,
Wordfence, and generic ModSecurity-style block pages.

## Notes
- A clean/no-match result does **not** guarantee there's no WAF —
  some are configured to be silent, or use signatures not in this
  tool's list. Treat "no WAF detected" as "no *known* WAF detected."
- A status-code change on the provocation request (e.g. 200 → 403)
  without a specific signature match is still a useful signal: some
  filter/WAF is present, just not one this tool recognizes by name.

## Status
Part of a personal 100-tool security scripting project. Verified
against three local mock scenarios: a Cloudflare-style WAF (correctly
identified via headers, cookies, and a status-code change on the
malicious payload), a plain server with no WAF (correctly reported no
match), and an unlisted/generic WAF that blocks with a 403 but no
recognizable signature (correctly flagged as "a filter is present,
just not a recognized one" rather than a false negative or false
positive).

## License
MIT
