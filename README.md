# Payload Encoder

A multi-format encoder/decoder for security testing — functionally
similar to Burp Suite's "Decoder" tab. Transforms text between common
encodings used when testing input handling and filter bypass (a WAF
or validation layer often only decodes one layer, so double-encoding
or an unexpected format sometimes slips past it).

This tool only transforms text between encodings; it does not
generate exploit code or attack payloads itself.

## Requirements
Python 3 standard library only — no `pip install` needed.

## Usage
```bash
# Encode
python payload_encoder.py --encode base64 --text "<script>alert(1)</script>"
python payload_encoder.py --encode url --text "<script>"
python payload_encoder.py --encode html --text "<img src=x onerror=alert(1)>"
python payload_encoder.py --encode hex --text "test123"

# Decode
python payload_encoder.py --decode base64 --text "PHNjcmlwdD4="
python payload_encoder.py --decode url --text "%3Cscript%3E"

# Double-encode (e.g. to test WAFs that only decode once)
python payload_encoder.py --encode url --text "<script>" --double

# Pipe input instead of --text
echo -n "some text" | python payload_encoder.py --encode base64
```

## Supported formats
`base64`, `url`, `url-plus` (space → `+`), `html` (entity escaping),
`hex`, `unicode` (`\uXXXX` escapes), `rot13`, `ascii-decimal`
(space-separated char codes).

## Status
Part of a personal 100-tool security scripting project. Every format
tested with an encode/decode round-trip, double-encoding verified on
URL encoding, stdin piping verified, and malformed input (invalid
base64) confirmed to fail with a clear error instead of crashing.

## License
MIT
