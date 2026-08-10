# IDOR (Insecure Direct Object Reference)

Confirming an IDOR means showing that changing an object identifier lets you
access or modify a resource that should belong to someone else — access control
is missing or broken, not just that an ID is in the URL.

## What to check, in order

1. **Identify the object reference.** A numeric/UUID/username in the path, query
   string, or body that names a specific resource (`/api/Users/1`,
   `/rest/basket/6`, `?orderId=1042`).
2. **Establish the legitimate baseline.** With the current session/identity,
   request the object you're *supposed* to own. Note status + body.
3. **Swap the identifier to another subject's.** Same session, different ID
   (adjacent value, another known user's ID, or `id=1` for the admin/first
   record). This is the core test.
4. **Compare.** If the other subject's data comes back with a 200 and real
   content, access control is missing.
5. **Check unauthenticated too, when relevant.** Repeat the swapped-ID request
   with the session cookie / Authorization header stripped — if it still returns
   the data, that's an even more severe finding.
6. **For write/IDOR-to-modify:** attempt the state-changing action
   (PUT/PATCH/DELETE) on another subject's object and confirm the change took
   effect (re-read it), don't just trust a 200.

## Response signatures

**Real finding:**
- Swapped-ID request returns HTTP 200 with data that clearly belongs to a
  *different* user (different email, name, basket contents, order) than the
  authenticated identity.
- Stripped-auth request still returns the object.
- A write succeeds and a follow-up read confirms the other user's object
  actually changed.

**False positive / not confirmed:**
- Swapped-ID request returns 401/403/404, or a body that says
  "not authorized" / empty result — access control is working.
- It returns 200 but with *your own* data regardless of the ID (the ID is
  ignored / scoped server-side to your session) — not an IDOR.
- The "other" object is genuinely public (e.g. a public product), so seeing it
  proves nothing about access control.
- Same content for every ID because it's a static/shared resource.

## Tooling

- `probe_variant` is the ideal tool here and should be the default: baseline =
  your own object with your session, variant = swapped ID (and/or stripped auth
  header). The status/body diff directly shows whether the other object leaked.
- Fall back to `execute_python` only for: enumerating a range of IDs to gauge how
  many other records are exposed, or a write-then-read confirmation chain. Use
  `ronin_target.request` for network calls in that code.
