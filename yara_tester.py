#!/usr/bin/env python3
"""
YARA Rule Tester
------------------
Compiles a YARA rule (or a directory of .yar/.yara rules) and tests it
against a target file or directory — the core workflow when writing
or validating detection rules for a SOC/threat-hunting workload.

Requires yara-python:
    pip install yara-python

Usage:
    python yara_tester.py --rule rules/suspicious.yar --target sample.exe
    python yara_tester.py --rule-dir rules/ --target-dir /path/to/scan
    python yara_tester.py --rule rules/suspicious.yar --target sample.exe --show-strings
"""

import argparse
import sys
from pathlib import Path

try:
    import yara
except ImportError:
    print("[!] yara-python not installed. Run:\n    pip install yara-python", file=sys.stderr)
    sys.exit(1)


def compile_rules(rule_path, rule_dir):
    try:
        if rule_dir:
            rule_files = {}
            for i, path in enumerate(sorted(Path(rule_dir).glob("*.yar*"))):
                rule_files[f"ns{i}_{path.stem}"] = str(path)
            if not rule_files:
                print(f"[!] No .yar/.yara files found in {rule_dir}", file=sys.stderr)
                sys.exit(1)
            return yara.compile(filepaths=rule_files)
        else:
            return yara.compile(filepath=rule_path)
    except yara.SyntaxError as e:
        print(f"[!] YARA rule syntax error: {e}", file=sys.stderr)
        sys.exit(1)
    except yara.Error as e:
        print(f"[!] YARA compile error: {e}", file=sys.stderr)
        sys.exit(1)


def scan_file(rules, filepath, show_strings, timeout):
    try:
        matches = rules.match(filepath=str(filepath), timeout=timeout)
    except yara.Error as e:
        return {"file": str(filepath), "error": str(e)}
    return {"file": str(filepath), "matches": matches}


def collect_targets(target, target_dir, recursive):
    if target:
        return [Path(target)]
    pattern = "**/*" if recursive else "*"
    return [p for p in Path(target_dir).glob(pattern) if p.is_file()]


def print_match(result, show_strings):
    matches = result.get("matches")
    if result.get("error"):
        print(f"[ERR ] {result['file']}: {result['error']}")
        return False
    if not matches:
        print(f"[ -- ] {result['file']}: no match")
        return False

    for m in matches:
        tags = f" [{', '.join(m.tags)}]" if m.tags else ""
        print(f"[HIT ] {result['file']} -> rule '{m.rule}'{tags}")
        if m.meta:
            for k, v in m.meta.items():
                print(f"         meta.{k} = {v}")
        if show_strings:
            for s in m.strings:
                # yara-python string match objects vary by version; handle both shapes defensively
                try:
                    offset, identifier, data = s
                except (TypeError, ValueError):
                    offset, identifier, data = s.instances[0].offset, s.identifier, s.instances[0].matched_data
                snippet = data if isinstance(data, str) else data.decode(errors="replace")
                print(f"         match {identifier} @ offset {offset}: {snippet!r}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Compile and test YARA rules against a file or directory.")
    rule_group = parser.add_mutually_exclusive_group(required=True)
    rule_group.add_argument("--rule", help="Path to a single .yar/.yara rule file")
    rule_group.add_argument("--rule-dir", help="Directory of .yar/.yara rule files to compile together")

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", help="Single file to scan")
    target_group.add_argument("--target-dir", help="Directory of files to scan")

    parser.add_argument("--recursive", action="store_true", help="Recurse into subdirectories when using --target-dir")
    parser.add_argument("--show-strings", action="store_true", help="Show the matched string content and offsets")
    parser.add_argument("--timeout", type=int, default=30, help="Per-file scan timeout in seconds (default: 30)")
    args = parser.parse_args()

    print("[*] Compiling rules...")
    rules = compile_rules(args.rule, args.rule_dir)
    print("[*] Rules compiled successfully.")

    targets = collect_targets(args.target, args.target_dir, args.recursive)
    if not targets:
        print("[!] No target files found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning {len(targets)} file(s)")
    print("-" * 60)

    hit_count = 0
    for target in targets:
        result = scan_file(rules, target, args.show_strings, args.timeout)
        if print_match(result, args.show_strings):
            hit_count += 1

    print("-" * 60)
    print(f"[*] {hit_count}/{len(targets)} file(s) matched at least one rule.")


if __name__ == "__main__":
    main()
