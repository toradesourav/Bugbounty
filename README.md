# SSL Certificate Analyzer

Connects to a host over TLS and analyzes the presented certificate:
expiry (with days-remaining countdown), issuer/subject, Subject
Alternative Names, signature algorithm, self-signed detection, and
the negotiated TLS protocol/cipher.

Handles the common gotcha where Python's built-in
`ssl.getpeercert()` returns an **empty dict** for any certificate
that isn't independently trust-chain-verified (self-signed, expired,
wrong hostname) — exactly the kind of cert you most want to inspect.
This tool always pulls the raw DER bytes and parses them directly
with the `cryptography` library instead, regardless of trust status.

## Requirements
```
pip install cryptography
```

## Usage
```bash
python ssl_analyzer.py --host target.com
python ssl_analyzer.py --host target.com --port 8443
```

## What it checks
- Expiry status: expired / expiring within 14 days / within 30 days / OK
- Self-signed detection (subject CN == issuer CN)
- Subject Alternative Names (and a warning if there are none —
  reliance on deprecated CN-only matching)
- Weak signature algorithm (MD5/SHA-1 — collision-vulnerable)
- Deprecated TLS protocol version negotiated (SSLv2/3, TLS 1.0/1.1)
- Cipher suite and key strength

## Status
Part of a personal 100-tool security scripting project. Verified
end-to-end against a real local TLS server: generated a genuine
self-signed X.509 certificate (RSA-2048, SHA-256) expiring in 10 days,
served it over an actual `ssl`-wrapped socket, and ran the analyzer
against it live. Correctly detected: self-signed status, the
near-expiry warning (9 days remaining), the SAN entry, TLS 1.3
negotiation, and the cipher suite in use.

## License
MIT
