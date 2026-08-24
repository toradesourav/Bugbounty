# BugBounty-Toolkit - 100 Security Tools Challenge

> Building 100 Tools in 100 Days | Day 10/100 | Aspiring SOC Analyst

**Progress: 10/100 Tools Built (10%)**

I am building 100 security tools from scratch to become a SOC Analyst. No copy-paste, all tools built and understood by me.

### 🛠️ My 10 Tools So Far:

**Recon & Takeover**
1. Api-fuzzer - Fuzzes API endpoints
2. Subdomain-Scanner - Finds subdomains
3. Port Scanner - Fast TCP port scanner
4. Js-secret-finder - Finds API keys in JS files
5. Wayback Harvester - Gets old URLs from archive.org
6. **Subdomain Takeover Checker - NEW! Detects dangling DNS takeover**

**Vuln Scanners**
7. Cors-check - Checks CORS misconfig
8. Csrf-gen - Generates CSRF PoC
9. Jwt-tools - Decodes & tests JWTs
10. Redirect Scanner - Finds Open Redirect

### How to Use Any Tool
```bash
git clone https://github.com/toradesourav/Bugbounty
cd 10-subdomain-takeover-checker
python3 subdomain-takeover-checker.py -d sub.example.com
python3 subdomain-takeover-checker.py -l subs.txt -o results.txt
