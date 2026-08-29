# IDOR Tester

Tests for Insecure Direct Object Reference vulnerabilities in two
modes:

1. **Enumeration** (single session) — iterates an ID parameter and
   reports which IDs return distinct, accessible-looking objects.
   Good first-pass recon, but **a 200 response alone doesn't prove
   IDOR** — confirm with differential mode.
2. **Differential** (two accounts) — the actual IDOR confirmation.
   Requests the same object as both its real owner and a different
   authenticated user, and checks whether the second user can access
   it. This is what actually proves broken access control.

## ⚠️ Authorized use only
Only use against systems you own or have explicit written permission
to test. Differential mode requires you to legitimately control both
test accounts (e.g. two accounts you created for the authorized
engagement) — never use credentials that aren't yours to test with.

## Requirements
```
pip install requests
```

## Usage
```bash
# Enumeration: which order IDs are accessible from one session?
python idor_tester.py enumerate \
  --url "https://target.com/api/orders/FUZZ" \
  --start 1000 --end 1050 \
  --cookie "session=YOUR_SESSION_TOKEN"

# Differential: object 1002 belongs to User B — can User A's session see it?
python idor_tester.py differential \
  --url "https://target.com/api/orders/1002" \
  --cookie-a "session=USER_A_TOKEN" \
  --cookie-b "session=USER_B_TOKEN" \
  --owner b
```

## How differential mode works
1. Requests the URL once with the **owner's** session, once with the
   **other** user's session.
2. If both return `200` with **identical body content** → IDOR
   confirmed: the object is accessible to someone who shouldn't see it.
3. If the other user gets `401`/`403`/`404` → access control is working.
4. If both return `200` but bodies **differ** → inconclusive; the app
   may be silently redirecting the other user to a generic page
   rather than truly authorizing them. Inspect both responses by hand.

## Notes
- Enumeration mode fingerprints response bodies (SHA-256, first 12
  hex chars) so you can tell "3 different real objects" apart from
  "the same generic page returned 3 times" (e.g. a login wall that
  happens to return 200).
- A missing distinct-object signal doesn't mean the app is safe —
  some APIs return `200` with an empty/null object for IDs you don't
  own instead of an error code. Manually inspect a few "successful"
  responses before concluding much from enumeration alone.

## Status
Part of a personal 100-tool security scripting project. Verified
against two local mock APIs: one with no ownership checks (enumeration
correctly found 3 distinct accessible objects with unique
fingerprints; differential mode correctly confirmed IDOR when User A's
session accessed User B's order), and one with correct ownership
checks (differential mode correctly reported SAFE when the
non-owning user was denied with a 403).

## License
MIT
