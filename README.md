# IOC Extractor

Extracts Indicators of Compromise from arbitrary text (incident
reports, logs, threat intel feeds, pasted phishing emails, etc.):
IPv4/IPv6 addresses, domains, URLs, email addresses, and file hashes
(MD5/SHA1/SHA256). The standard first step in SOC triage — turning a
wall of unstructured text into a clean, deduplicated list you can
feed into a blocklist, SIEM, or threat-intel lookup.

## Requirements
Python 3 standard library only — no `pip install` needed.

## Usage
```bash
# From a file
python ioc_extractor.py --file incident_report.txt

# From stdin
cat suspicious.log | python ioc_extractor.py

# Only specific IOC types
python ioc_extractor.py --file report.txt --types ip,domain,sha256
# (use ipv4/ipv6/email/url/domain/md5/sha1/sha256 as needed)

# Save combined results to a file
python ioc_extractor.py --file report.txt --output iocs.txt
```

## IOC types extracted
IPv4, IPv6, email addresses, URLs, domains, MD5, SHA1, SHA256 hashes.

## Notes on the domain list
Domains that appear *inside* an already-captured URL or email address
are filtered out of the standalone domain list — otherwise every URL
and email would also show up redundantly as a "domain" finding. The
domain list only shows domains mentioned on their own (e.g. in
running prose, not as part of a link).

## Status
Part of a personal 100-tool security scripting project. Verified
against a realistic synthetic incident report containing all 8 IOC
types mixed together (IPv4, IPv6, 2 emails, 3 URLs, MD5/SHA1/SHA256
hashes) — all 12 IOCs correctly extracted with zero false positives,
and the domain-deduplication logic correctly suppressed domains
already captured inside URLs/emails while still correctly extracting
domains mentioned standalone in a separate test.

## License
MIT
