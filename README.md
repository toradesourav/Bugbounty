# Bugbounty Toolkit — by Sourav Torade

A collection of security recon, vulnerability-testing, and blue-team
scripts, each in its own folder with source + README. Built as part
of a personal 100-tool challenge.

⚠️ All tools are for use only against systems you own or have
explicit written authorization to test.

## Recon
| # | Tool | Description |
|---|---|---|
| 01 | [API Fuzzer](./01-api-fuzzer) | Multi-threaded REST API fuzzer with FUZZ-marker payload substitution |
| 06 | [Wayback Fetcher](./06-wayback-fetcher) | Pulls historical URLs for a domain from the Wayback Machine CDX API |
| 09 | [Dir Finder](./09-dir-finder) | Multi-threaded sensitive-path/file brute-forcer |
| 11 | [Whois Lookup](./11-whois-lookup) | Direct IANA→registry WHOIS queries over raw sockets |
| 12 | [DNS Lookup](./12-dns-lookup) | A/AAAA/MX/TXT/NS/CNAME/SOA record lookup |
| 13 | [HTTP Header Analyzer](./13-http-header-analyzer) | Grades security headers, flags info-disclosure & weak cookies |
| 15 | [Screenshot Taker](./15-screenshot-taker) | Headless-browser bulk visual recon |
| 19 | [Tech Stack Detector](./19-tech-stack-detector) | Wappalyzer-style technology fingerprinting |
| 21 | [Subdomain Finder](./21-subdomain-finder) | crt.sh + wordlist DNS brute-force subdomain enumeration |
| 23 | [Recon Toolkit Installer](./23-recon-toolkit-installer) | Installs jadx, apktool, subfinder, httpx from official sources |

## Vulnerability Testing
| # | Tool | Description |
|---|---|---|
| 02 | [JWT Tool](./02-jwt-tool) | Decode, alg=none check, HMAC secret crack, forge alg=none |
| 03 | [CSRF Generator](./03-csrf-generator) | Auto-submitting HTML/JS PoC generator for CSRF findings |
| 04 | [CORS Checker](./04-cors-checker) | Detects reflected-origin, credentialed-wildcard CORS misconfigs |
| 05 | [Open Redirect Scanner](./05-open-redirect-scanner) | Tests URL params against 10 open-redirect bypass techniques |
| 07 | [JS Secret Scanner](./07-js-secret-scanner) | Scans JS files for hardcoded API keys/tokens (11 signatures) |
| 08 | [Email Harvester](./08-email-harvester) | Extracts emails from pages with obfuscation handling |
| 14 | [XSS Param Finder](./14-xss-param-finder) | Flags unescaped parameter reflections as candidate XSS |
| 18 | [Broken Link Hijack Finder](./18-broken-link-hijack-finder) | Finds dangling external resource references (GitHub Pages, S3, expired domains) |
| 20 | [S3 Bucket Scanner](./20-s3-bucket-scanner) | Read-only public-bucket detector with naming permutation generator |

## Utilities
| # | Tool | Description |
|---|---|---|
| 16 | [Payload Encoder](./16-payload-encoder) | Multi-format encode/decode (base64, URL, HTML, hex, unicode, ROT13) |

## Blue Team / SOC
| # | Tool | Description |
|---|---|---|
| 10 | [SOC Log Analyzer](./10-soc-log-analyzer) | Brute-force detection from auth logs, threshold + time-window burst detection |
| 17 | [YARA Rule Tester](./17-yara-rule-tester) | Compiles and tests YARA detection rules against files |
| 22 | [Hash Identifier & Cracker](./22-hash-identifier) | Identifies hash algorithm, dictionary-attack cracking |

## Status
Every tool above (except YARA Rule Tester, which needs `yara-python`
installed to run, and the Recon Toolkit Installer's live download
steps) was tested end-to-end against local mock servers or synthetic
data during development. See each tool's own README for exactly what
was verified.

## License
MIT — see each tool's folder for details.

