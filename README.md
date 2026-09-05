# Bugbounty Toolkit — by Sourav Torade

A collection of security recon and vulnerability-testing scripts,
built as part of a personal 100-tool challenge.

⚠️ All tools are for use only against systems you own or have
explicit written authorization to test.

## Recon
| Tool | File | Description |
|---|---|---|
| API Fuzzer | [api_fuzzer.py](./api_fuzzer.py) | Multi-threaded REST API fuzzer with FUZZ-marker payload substitution |
| Wayback Fetcher | [wayback.py](./wayback.py) | Pulls historical URLs for a domain from the Wayback Machine CDX API |
| Dir Finder | [dir_finder.py](./dir_finder.py) | Multi-threaded sensitive-path/file brute-forcer |
| Whois Lookup | [whois_lookup.py](./whois_lookup.py) | Direct IANA→registry WHOIS queries over raw sockets |
| DNS Lookup | [dns_lookup.py](./dns_lookup.py) | A/AAAA/MX/TXT/NS/CNAME/SOA record lookup |
| HTTP Header Analyzer | [header_analyzer.py](./header_analyzer.py) | Grades security headers, flags info-disclosure & weak cookies |
| Screenshot Taker | [screenshot_taker.py](./screenshot_taker.py) | Headless-browser bulk visual recon |
| Tech Stack Detector | [tech_detector.py](./tech_detector.py) | Wappalyzer-style technology fingerprinting |
| Subdomain Finder | [subdomain_finder.py](./subdomain_finder.py) | crt.sh + wordlist DNS brute-force subdomain enumeration |
| Subdomain Takeover Checker | [10-subdomain-takeover-checker/](./10-subdomain-takeover-checker) | Checks dangling CNAMEs for subdomain takeover |
| Recon Toolkit Installer | [install_recon_toolkit.sh](./install_recon_toolkit.sh) | Installs jadx, apktool, subfinder, httpx from official sources |
| Shodan API Tool | [shodan_tool.py](./shodan_tool.py) | Host lookup (ports/banners/CVEs) and search via the Shodan API |
| SSL Certificate Analyzer | [ssl_analyzer.py](./ssl_analyzer.py) | Checks expiry, self-signed status, SAN coverage & weak signature algorithms |
| Robots.txt & Sitemap Parser | [robots_sitemap_parser.py](./robots_sitemap_parser.py) | Extracts Disallow entries and recursively parses nested sitemap indexes |
| IP Geolocation + ASN Lookup | [ip_geolocation.py](./ip_geolocation.py) | Geolocation/ISP/ASN info via ip-api.com, no key required |
| Google Dork Generator | [google_dork_gen.py](./google_dork_gen.py) | Generates categorized Google dork queries across 7 categories |
| Reverse IP Lookup | [reverse_ip_lookup.py](./reverse_ip_lookup.py) | Finds other domains hosted on the same IP address |

## Vulnerability Testing
| Tool | File | Description |
|---|---|---|
| JWT Tool | [jwt_tool.py](./jwt_tool.py) | Decode, alg=none check, HMAC secret crack, forge alg=none |
| CSRF Generator | [csrf_gen.py](./csrf_gen.py) | Auto-submitting HTML/JS PoC generator for CSRF findings |
| CORS Checker | [cors_check.py](./cors_check.py) | Detects reflected-origin, credentialed-wildcard CORS misconfigs |
| Open Redirect Scanner | [redirect_scan.py](./redirect_scan.py) | Tests URL params against 10 open-redirect bypass techniques |
| JS Secret Scanner | [js_secret.py](./js_secret.py) | Scans JS files for hardcoded API keys/tokens (11 signatures) |
| Email Harvester | [email_harvest.py](./email_harvest.py) | Extracts emails from pages with obfuscation handling |
| XSS Param Finder | [xss_param_finder.py](./xss_param_finder.py) | Flags unescaped parameter reflections as candidate XSS |
| Broken Link Hijack Finder | [broken_link_hijack.py](./broken_link_hijack.py) | Finds dangling external resource references (GitHub Pages, S3, expired domains) |
| S3 Bucket Scanner | [s3_scanner.py](./s3_scanner.py) | Read-only public-bucket detector with naming permutation generator |
| Rate Limit Tester | [rate_limit_tester.py](./rate_limit_tester.py) | Sends identical repeated requests to detect missing throttling/lockout protection |
| IDOR Tester | [idor_tester.py](./idor_tester.py) | Enumeration + two-account differential testing to confirm broken object-level access control |
| Cookie Analyzer | [cookie_analyzer.py](./cookie_analyzer.py) | Checks cookie flags + Shannon-entropy analysis for weak session tokens |
| GraphQL Scanner | [graphql_scanner.py](./graphql_scanner.py) | Detects introspection exposure, flags sensitive-sounding queries/mutations |
| SSRF Detector | [ssrf_detector.py](./ssrf_detector.py) | Tests URL params against internal-target payloads (cloud metadata, loopback encodings) |
| Host Header Injection Tester | [host_header_tester.py](./host_header_tester.py) | Tests whether Host/X-Forwarded-Host headers are trusted and reflected |
| CRLF Injection Scanner | [crlf_scanner.py](./crlf_scanner.py) | Confirms real HTTP header injection via multiple CRLF encoding variants |
| WAF Detector | [waf_detector.py](./waf_detector.py) | Passive header fingerprinting + active provocation to identify 10 major WAFs |
| HTTP Methods Tester | [http_methods_tester.py](./http_methods_tester.py) | Checks which HTTP methods (PUT/DELETE/TRACE) are actually enabled |
| SSTI Detector | [ssti_detector.py](./ssti_detector.py) | Tests 8 template-engine syntaxes via math-expression evaluation |
| Param Miner | [param_miner.py](./param_miner.py) | Discovers hidden/undocumented parameters via wordlist + response diffing |
| NoSQL Injection Scanner | [nosql_scanner.py](./nosql_scanner.py) | Boolean-based MongoDB operator-injection detection ($ne/$gt/$regex/$exists) |

## Utilities & Automation
| Tool | File | Description |
|---|---|---|
| Payload Encoder | [payload_encoder.py](./payload_encoder.py) | Multi-format encode/decode (base64, URL, HTML, hex, unicode, ROT13) |
| IOC Extractor | [ioc_extractor.py](./ioc_extractor.py) | Extracts IPs, domains, URLs, emails & hashes from unstructured text |
| CVSS Score Calculator | [cvss_calculator.py](./cvss_calculator.py) | CVSS v3.1 base score calculator, verified against published NVD scores |
| Bug Report Generator | [report_generator.py](./report_generator.py) | Generates structured Markdown vulnerability reports |
| Email Header Analyzer | [email_header_analyzer.py](./email_header_analyzer.py) | Checks SPF/DKIM/DMARC and spoofing indicators from raw headers |

## Related
Blue-team/SOC tools (log analysis, YARA rules, hash cracking) live in
a separate repo: [soc-blue-team-toolkit](https://github.com/toradesourav/soc-blue-team-toolkit)

## Status
Every tool above was tested end-to-end against local mock servers,
synthetic data, or (where relevant) real protocol implementations —
e.g. genuine TLS handshakes, real Jinja2 template rendering, and
hand-implemented MongoDB operator semantics — not just simulated
responses. Exceptions: the Recon Toolkit Installer's live download
steps and the Shodan API Tool's live API calls, which were verified
via mocked/documented API responses instead (no internet access in
the build environment).

## License
MIT
