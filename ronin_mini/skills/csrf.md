---
status: full
cwe: CWE-352
attack_technique: T1190
attack_tactic: Initial Access
---

# Cross-Site Request Forgery (CSRF)

Confirming CSRF means showing a state-changing request succeeds using only
ambient credentials (cookies) with no valid anti-CSRF token attached — not
just that a token field exists in the form.

## What to check, in order

1. **Confirm the action is actually state-changing.** CSRF only matters for
   requests that change something (password/email change, fund transfer,
   privilege change, delete). Read-only GETs aren't CSRF targets in the
   traditional sense — though a state-changing action reachable via GET is
   itself a finding (see step 5).
2. **Baseline: perform the action properly**, with a valid session and
   whatever token the app sends, and confirm it succeeds.
3. **Strip the token entirely.** Resend the same request with the
   anti-CSRF token field/header removed (but keep the session cookie). If
   it still succeeds, the token isn't enforced — a bypass, not just a
   presence check.
4. **If the token is present in the request, check it's actually
   validated**, not just expected:
   - Submit an empty or obviously-invalid token value — does the request
     still succeed?
   - Reuse a token value captured from a *different* session/user, if you
     have one — accepted tokens not tied to the specific session are not
     doing their job.
5. **Check for a GET-based state change.** If the state-changing action can
   be triggered via a simple `GET` (no token needed by design because it
   "isn't a form submission"), that's an instant, high-confidence finding —
   a plain link/image tag from another origin triggers it.
6. **Note SameSite as a mitigating control**, not proof either way. If
   response `Set-Cookie` headers show `SameSite=Strict` or `Lax` on the
   session cookie, cross-origin forgery is harder in modern browsers even
   if the server-side token check is weak — worth noting in evidence, but
   it doesn't change whether the *server-side* validation itself is broken.

## Response signatures

**Real finding:**
- Token-stripped request still performs the action (confirmed by
  re-reading state afterward, not just trusting a 200/redirect).
- A token from a different session, or an empty/malformed token, is
  accepted.
- The action is reachable via plain `GET` with no token at all.

**False positive / not confirmed:**
- Token-stripped request is rejected (400/403, or the action's effect
  doesn't actually occur on re-check).
- The app requires a custom header (e.g. `X-Requested-With`) that browsers
  won't send cross-origin without CORS permission — this is itself a
  mitigating control, not a broken one, unless CORS is also misconfigured
  to allow it.
- The "successful" request only worked because you were still using a
  fully valid session+token from your own prior request — re-run the strip
  test cleanly to be sure.

## Tooling

- `probe_variant` is the natural fit: baseline = full request with valid
  token, variant = token stripped / empty / swapped. The diff shows whether
  the action's response (and, ideally, a follow-up state re-read) changed.
- Fall back to `execute_python` for a state-changing action that needs a
  follow-up read to confirm effect (e.g. change email, then re-fetch the
  profile to confirm it actually changed), or for capturing/reusing a token
  across two different session contexts.
