# S3 Bucket Scanner

Checks S3 buckets for public-read misconfigurations. Two modes: check
a specific list of bucket names/URLs, or auto-generate common
naming-convention permutations from a company/project keyword (since
bucket names are globally unique, and predictable patterns like
`company-backup` or `company-dev` are extremely common
misconfigurations found in bug bounty recon).

This tool only sends **read-only GET requests**. It does not attempt
to write, upload, or delete anything — testing write-access would
need separate, explicit authorization even within an authorized
engagement.

## ⚠️ Authorized use only
Only use against buckets you own or have explicit written permission
to test.

## Requirements
```
pip install requests
```

## Usage
```bash
# Auto-generate 50+ common name permutations from a keyword
python s3_scanner.py --keyword acmecorp

# Specific region
python s3_scanner.py --keyword acmecorp --region eu-west-1

# Check a specific list of bucket names or full URLs
python s3_scanner.py --bucket-list buckets.txt

# Show every result, not just public/private hits
python s3_scanner.py --keyword acmecorp --show-all
```

## Verdicts
| Verdict | Meaning |
|---|---|
| `PUBLIC_LISTABLE` | Bucket contents are publicly listable — high severity, report immediately |
| `EXISTS_PRIVATE` | Bucket exists (403), listing denied — still worth checking if individual objects are directly readable |
| `NOT_FOUND` | `NoSuchBucket` — the name is available; interesting for takeover if something still references it |
| `OTHER` | Unexpected status code, review manually |

## Notes
- A `403` doesn't mean the bucket is fully secure — individual objects
  can still have public-read ACLs even when bucket listing is denied.
  This tool only checks the listing; testing individual known object
  paths is a separate step.
- `--keyword` generates ~50 permutations by default (dev/prod/staging/
  backup/assets/etc. combined as both suffix and prefix). Feed your
  own list via `--bucket-list` for a larger or more targeted wordlist.

## Status
Part of a personal 100-tool security scripting project. Bucket-name
generation and URL formatting verified directly. Full scan behavior
verified against three mock servers simulating a public-listable
bucket, a private (403) bucket, and a nonexistent (`NoSuchBucket`)
bucket — all three correctly classified.

## License
MIT
