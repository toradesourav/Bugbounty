# Param Miner

Discovers hidden/undocumented parameters by sending a baseline
request, then adding candidate parameter names one at a time and
comparing the response against the baseline. A parameter that changes
the response — different status code or meaningfully different
length — is likely a real parameter the app reads internally, even if
it's undocumented. Classic finds this way: debug flags, feature
toggles, admin overrides, and internal-only fields.

## ⚠️ Authorized use only
Only use against systems you own or have explicit written permission
to test.

## Requirements
```
pip install requests
```

## Usage
```bash
# GET request, built-in 55-name wordlist
python param_miner.py --url https://target.com/api/user

# POST request with a custom wordlist
python param_miner.py --url https://target.com/page --wordlist params.txt --method POST

# Custom test value (default is "1")
python param_miner.py --url https://target.com/api/user --value true
```

## How it works
1. Sends one baseline request with no extra parameters.
2. For each candidate name, sends the same request with
   `?candidate_name=value` added, and compares:
   - **Status code changed** → strong signal.
   - **Response length changed by more than 5% (min 20 bytes)** →
     signal, since this catches added/removed content without being
     overly sensitive to tiny formatting differences.
3. Reports every parameter that triggered a difference.

## Notes
- Some response differences come from server-side randomness
  (timestamps, request IDs, ads/rotating content) rather than the
  parameter actually being read — always manually verify a finding
  before reporting it.
- Built-in wordlist covers common categories: debug/internal flags,
  pagination, formatting/output, auth/role overrides, and caching
  controls. Swap in a larger list (e.g. Arjun's or param-miner's
  wordlists) via `--wordlist` for deeper coverage.

## Status
Part of a personal 100-tool security scripting project. Verified
against a local mock server with a genuinely hidden `debug` parameter
that adds significant extra content to the response when present —
correctly identified out of 58 candidate names tested, with zero
false positives on the other 57.

## License
MIT
