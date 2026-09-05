#!/usr/bin/env python3
"""
Bug Report Template Generator
--------------------------------
Generates a structured, professional Markdown vulnerability report
from command-line inputs — the format most bug bounty platforms
(HackerOne, Bugcrowd) and internal security teams expect: summary,
steps to reproduce, impact, and remediation, with a CVSS vector slot.

Usage:
    python report_generator.py \\
        --title "Reflected XSS in search parameter" \\
        --severity High \\
        --target "https://target.com/search?q=" \\
        --summary "The 'q' parameter reflects user input without HTML encoding." \\
        --steps "Navigate to /search?q=<script>alert(1)</script>" "Observe the alert fires" \\
        --impact "An attacker can execute arbitrary JavaScript in a victim's session." \\
        --remediation "HTML-encode all user input before reflecting it in the response." \\
        --output report.md
"""

import argparse
import datetime
import sys

SEVERITY_CVSS_HINT = {
    "critical": "9.0 - 10.0",
    "high": "7.0 - 8.9",
    "medium": "4.0 - 6.9",
    "low": "0.1 - 3.9",
    "informational": "0.0",
}


def build_report(args):
    date_str = datetime.date.today().isoformat()
    steps_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(args.steps))

    cvss_line = f"- **CVSS Vector:** `{args.cvss}`\n" if args.cvss else ""
    cvss_hint = SEVERITY_CVSS_HINT.get(args.severity.lower(), "")

    references_md = ""
    if args.references:
        references_md = "\n## References\n" + "\n".join(f"- {r}" for r in args.references) + "\n"

    report = f"""# {args.title}

**Severity:** {args.severity} {f"(typical CVSS range: {cvss_hint})" if cvss_hint else ""}
**Target:** {args.target}
**Date Reported:** {date_str}
**Reported By:** {args.reporter or "_(add your name)_"}
{cvss_line}
## Summary
{args.summary}

## Steps to Reproduce
{steps_md}

## Proof of Concept
```
{args.poc or "(attach screenshot/request-response pair here)"}
```

## Impact
{args.impact}

## Remediation
{args.remediation}
{references_md}
---
_Report generated with Bug Report Template Generator — part of a personal 100-tool security scripting project._
"""
    return report


def main():
    parser = argparse.ArgumentParser(description="Generate a structured Markdown vulnerability report.")
    parser.add_argument("--title", required=True, help="Short vulnerability title")
    parser.add_argument("--severity", required=True, choices=["Critical", "High", "Medium", "Low", "Informational"], help="Severity rating")
    parser.add_argument("--target", required=True, help="Affected URL/endpoint/asset")
    parser.add_argument("--summary", required=True, help="One-paragraph summary of the vulnerability")
    parser.add_argument("--steps", required=True, nargs="+", help="Steps to reproduce, one per argument")
    parser.add_argument("--impact", required=True, help="What an attacker could actually do with this")
    parser.add_argument("--remediation", required=True, help="How to fix it")
    parser.add_argument("--cvss", help='CVSS vector string, e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" (pair with the CVSS Score Calculator tool)')
    parser.add_argument("--poc", help="Proof-of-concept request/payload text")
    parser.add_argument("--reporter", help="Your name/handle")
    parser.add_argument("--references", nargs="*", help="Reference links (CWE, OWASP, prior write-ups)")
    parser.add_argument("--output", help="Save to this file instead of printing to stdout")
    args = parser.parse_args()

    report = build_report(args)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"[*] Report saved to {args.output}")
        except OSError as e:
            print(f"[!] Could not write output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(report)


if __name__ == "__main__":
    main()
