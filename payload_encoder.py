#!/usr/bin/env python3
"""
Payload Encoder
-----------------
A multi-format encoder/decoder for security testing workflows —
functionally similar to Burp Suite's "Decoder" tab. Transforms text
between common encodings used when testing input handling and filter
bypass (WAF/validation logic often only decodes one layer, so
double-encoding or an unexpected encoding sometimes slips through).

This tool only transforms text; it does not generate exploit code.

Usage:
    python payload_encoder.py --encode base64 --text "<script>alert(1)</script>"
    python payload_encoder.py --decode url --text "%3Cscript%3E"
    python payload_encoder.py --encode url --text "test" --double
    echo "some text" | python payload_encoder.py --encode hex
"""

import argparse
import base64
import codecs
import html
import sys
import urllib.parse

ENCODERS = {
    "base64": lambda s: base64.b64encode(s.encode()).decode(),
    "url": lambda s: urllib.parse.quote(s, safe=""),
    "url-plus": lambda s: urllib.parse.quote_plus(s),
    "html": lambda s: html.escape(s),
    "hex": lambda s: s.encode().hex(),
    "unicode": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
    "rot13": lambda s: codecs.encode(s, "rot_13"),
    "ascii-decimal": lambda s: " ".join(str(ord(c)) for c in s),
}

DECODERS = {
    "base64": lambda s: base64.b64decode(s).decode(errors="replace"),
    "url": lambda s: urllib.parse.unquote(s),
    "url-plus": lambda s: urllib.parse.unquote_plus(s),
    "html": lambda s: html.unescape(s),
    "hex": lambda s: bytes.fromhex(s).decode(errors="replace"),
    "unicode": lambda s: s.encode().decode("unicode_escape"),
    "rot13": lambda s: codecs.encode(s, "rot_13"),
    "ascii-decimal": lambda s: "".join(chr(int(n)) for n in s.split()),
}


def get_input_text(args):
    if args.text is not None:
        return args.text
    if not sys.stdin.isatty():
        return sys.stdin.read().rstrip("\n")
    print("[!] No --text given and no piped input detected.", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Encode or decode text using common formats used in security testing (like Burp's Decoder tab)."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encode", choices=sorted(ENCODERS), help="Encode using this format")
    group.add_argument("--decode", choices=sorted(DECODERS), help="Decode using this format")
    parser.add_argument("--text", help="Text to transform (or pipe via stdin)")
    parser.add_argument("--double", action="store_true", help="Apply the transform twice (double-encode/decode)")
    args = parser.parse_args()

    text = get_input_text(args)

    try:
        if args.encode:
            fn = ENCODERS[args.encode]
            result = fn(text)
            if args.double:
                result = fn(result)
        else:
            fn = DECODERS[args.decode]
            result = fn(text)
            if args.double:
                result = fn(result)
    except Exception as e:
        print(f"[!] Transform failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(result)


if __name__ == "__main__":
    main()
