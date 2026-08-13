---
status: full
cwe: CWE-287
attack_technique: T1190
attack_tactic: Initial Access
---

# Authentication / Authorization Bypass

Confirming an auth bypass means reaching a protected resource or action WITHOUT
the credentials/steps that are supposed to gate it — and proving the gate was
actually supposed to be there.

## What to check, in order

1. **Baseline the gate.** Request the protected resource/action *properly
   authenticated* and confirm it works. Then confirm that WITHOUT auth it's
   refused (401/403/redirect to login). If it's already open to everyone, that's
   the finding — but establish the intended gate first.
2. **Missing-auth checks:**
   - Strip the `Authorization` header / session cookie and re-request. Still 200
     with protected data? Bypass.
   - Access a deep/direct URL that the UI only exposes post-login.
3. **Broken-auth-logic checks:**
   - Missing-parameter bypass: omit a field the check depends on (e.g. a
     `current_password` on a change-password endpoint) and see if the action
     still succeeds.
   - Verb tampering: if `POST` is gated, try `GET`/`PUT`/`HEAD` on the same path.
   - Forced browsing to admin-only endpoints as a low-priv user.
   - Token/JWT issues: `alg:none`, unsigned/none-verified tokens, or a token from
     one account accepted for another (overlaps with IDOR).
4. **Confirm impact.** The bypassed request must return the actual protected data
   or effect a state change (re-read to confirm), not just a 200 on an endpoint
   that would 200 anyway.

## Response signatures

**Real finding:**
- Stripped-credential request returns the same protected data as the
  authenticated baseline (200 + real content).
- An action completes with a required security parameter omitted (e.g. password
  changed without the current password), confirmed by a follow-up.
- A low-priv or unauthenticated identity reaches an admin-only function and it
  executes.

**False positive / not confirmed:**
- Without credentials you get 401/403/redirect — the gate holds.
- You get a 200 but it's a public page / generic shell with no protected data.
- The endpoint returns 200 but the *effect* didn't happen (state re-read shows no
  change) — it accepted the request but didn't actually perform the gated action.
- "Bypass" that actually still used a valid session you forgot to strip — re-run
  clean to be sure.

## Tooling

- `probe_variant` is the natural fit and the preferred path: baseline =
  authenticated (or full-parameter) request, variant = credential stripped /
  parameter omitted / verb changed. The diff shows whether the gate held.
- Fall back to `execute_python` for JWT manipulation (crafting `alg:none` or
  re-signing), multi-step login-flow bypasses, or extract-then-reuse token
  chains. Use `ronin_target.request` for network calls in that code.
