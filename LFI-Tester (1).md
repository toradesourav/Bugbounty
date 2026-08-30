# LFI-Tester

**LFI-Tester** is a conservative Local File Inclusion (LFI) and directory-traversal scanner for **authorized local and private-network testing**. It inspects URL query parameters with a small, read-only payload set and reports only high-confidence response markers.

> Use this project only against systems you own or have explicit permission to assess. The default configuration blocks public targets.

## Features

| Capability | Description |
|---|---|
| Local-first safety | Loopback and private-network targets are allowed by default; public hosts require an explicit opt-in flag. |
| Low-volume probes | Query parameters are tested one at a time with a small fixed payload set. |
| High-confidence evidence | Findings require recognizable Unix passwd or Windows INI markers. |
| Machine-readable output | Use `--json` for CI pipelines and custom reporting. |
| No destructive behavior | The scanner uses GET requests, does not submit forms, does not follow redirects, and never executes downloaded content. |

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Usage

The target should include at least one query parameter:

```bash
lfi-tester "http://127.0.0.1:8000/view?file=home"
```

JSON output:

```bash
lfi-tester "http://127.0.0.1:8000/view?file=home" --json
```

## Standalone Python file

You can also run the single-file version without installing the package:

```bash
python3 lfi_tester.py "http://127.0.0.1:8000/view?file=home"
python3 lfi_tester.py "http://127.0.0.1:8000/view?file=home" --json
```

The standalone file uses only Python's standard library and keeps the same local-target safety default.

Public targets are blocked unless you explicitly opt in and have authorization:

```bash
lfi-tester "https://authorized.example/view?file=home" --allow-external
```

The process returns exit code `0` when no high-confidence indicator is found, `1` when findings are reported, and `2` for invalid or blocked input.

## Testing

```bash
python -m pip install pytest
pytest
```

## Scope and limitations

This is an indicator scanner, not a complete vulnerability assessment platform. It does not crawl websites, discover hidden parameters, bypass authentication, exploit POST bodies, bypass filters, or prove exploitability in every framework. A positive result should be manually verified in an approved test environment.

The scanner deliberately avoids broad internet scanning, recursive crawling, stealth features, concurrency, and payload obfuscation. These choices make it suitable for local labs, CI checks, and controlled security testing.

## Recommended local lab

Run the scanner against an intentionally vulnerable application or a small test server that you control. Do not point it at random public websites. Keep request logs and obtain written authorization before testing any non-local system.

## Repository layout

```text
src/lfi_tester/scanner.py   Scanner logic and safety checks
src/lfi_tester/cli.py       Command-line interface
lfi_tester.py               Standalone standard-library version
tests/test_scanner.py       Unit tests
pyproject.toml              Packaging configuration
```

## License

MIT. See [LICENSE](LICENSE).

## References

[1]: https://owasp.org/www-community/attacks/Path_Traversal "OWASP Path Traversal"
[2]: https://owasp.org/www-community/attacks/ - "OWASP Web Application Security Risks"
