# 🎯 BugBounty Toolkit | 100 Tools Challenge

![Progress](https://img.shields.io/badge/Progress-27%2F100%20Tools-brightgreen)
![Language](https://img.shields.io/badge/Language-Python-blue)
![License](https://img.shields.io/badge/License-MIT-orange)

Building 100 Security & Bug Bounty Tools in 100 Days for Recon, Web Vulnerability Scanning, and OSINT.

---

## 🛠️ Active Tools (27/100)

| # | Tool Name | Description | Category |
|---|-----------|-------------|----------|
| 01 | **Subdomain-Scanner** | Fast subdomain enumeration tool | Recon |
| 02 | **JS-Secrets** | Extracts API keys & sensitive tokens from JS files | Scanners |
| 03 | **Wayback-Harvester** | Fetches historical URLs and parameters | Recon |
| 04 | **Dir-Finder** | Multi-threaded directory & path brute-forcer | Fuzzing |
| 05 | **CORS-Check** | Probes endpoints for CORS misconfigurations | Vulnerability |
| 06 | **Redirect-Scan** | Detects open redirect vulnerabilities | Vulnerability |
| 07 | **CSRF-Gen** | Auto-generates HTML/JS PoC for CSRF | Exploitation |
| 08 | **API-Fuzzer** | REST API endpoint & parameter fuzzer | Fuzzing |
| 09 | **JWT-Tools** | Decodes, audits, and tampers with JWTs | Auth |
| 10 | **Broken-Link-Hijack** | Identifies broken links vulnerable to hijacking | Scanners |
| 11 | **Rate-Limit-Tester** | Tests OTP & login endpoints for rate limits | Auth |
| 12 | **Tech-Detector** | Fingerprints server & web technology stack | Recon |
| 13 | **Payload-Encoder** | Multi-format string & payload encoder | Utility |
| 14 | **Screenshot-Taker** | Automated webpage screenshot utility | Recon |
| 15 | **XSS-Param-Finder** | Discovers reflection points for XSS testing | Scanners |
| 16 | **HTTP-Header-Checker** | Analyzes HTTP response security headers | Scanners |
| 17 | **DNS-Lookup** | Queries DNS records (A, MX, TXT, NS) | Recon |
| 18 | **Whois-Lookup** | Direct WHOIS domain data fetcher | Recon |
| 19 | **Subdomain-Takeover** | Checks dangling CNAME records for takeover | Scanners |
| 20 | **Port-Scanner** | Multi-threaded TCP port scanner | Network |
| 21 | **Install-Recon-Toolkit** | Automated environment setup script | Setup |
| 22 | **CORS-Tester** | Lightweight CORS header validation tool | Vulnerability |
| 23 | **Email-Harvester** | Scrapes target emails for OSINT | OSINT |
| 24 | **Header-Analyzer** | Inspects request & response header anomalies | Scanners |
| 25 | **Sublog-Takeover** | Subdomain & blog takeover validator | Scanners |
| 26 | **YARA-Tester** | Rule testing utility for malware signatures | Utility |
| 27 | **SH-Scanner** | Shell script vulnerability scanner | Scanners |

> **Status:** 27 tools listed, 73 planned for future release.

---

## 🚀 Usage

Run tools directly via python CLI:

```bash
# Clone the repository
git clone [https://github.com/toradesourav/Bugbounty.git](https://github.com/toradesourav/Bugbounty.git)
cd Bugbounty

# Example: Run JS-Secrets scanner
python3 main.py --tool js-secrets --target [https://example.com](https://example.com)
