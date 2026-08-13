---
status: full
cwe: CWE-79
attack_technique: T1190
attack_tactic: Initial Access
---

# Cross-Site Scripting (XSS)

Confirming XSS means showing attacker-controlled input is returned in a page in
a context where it would execute as script (or is stored and served to others) —
reflection alone is not enough; the reflection has to land in an executable
context without neutralizing encoding.

## What to check, in order

1. **Reflection probe.** Send a unique, harmless marker (e.g. `roninXSS12345`)
   in the parameter and confirm it appears verbatim in the response. No
   reflection, no reflected XSS.
2. **Determine the context** where it lands: HTML body text, inside an attribute
   (`value="..."`), inside a `<script>` block, in a URL/href, or in a JSON
   response rendered client-side. The context dictates the payload and whether
   it's exploitable at all.
3. **Encoding check — the make-or-break step.** Send characters that matter for
   that context and see if they come back raw or encoded:
   - HTML body: do `<` and `>` return as `<` `>` (raw) or `&lt;` `&gt;` (encoded)?
   - Attribute: does `"` return raw or as `&quot;`?
   Raw special characters in the right context = likely real. Encoded = the app
   is defending; not exploitable as-is.
4. **Context-appropriate payload.** Only once encoding looks absent:
   - HTML body: `<script>...</script>` or an `<img src=x onerror=...>` style tag.
   - Attribute: break out first — `"><svg onload=...>`.
   - JS context: break the string/statement.
5. **Stored XSS:** submit the payload where it persists (comment, profile,
   feedback), then fetch the page that renders it back and confirm it's present
   un-encoded in an executable context.

## Response signatures

**Real finding:**
- Marker reflects, AND the context-critical characters (`<`, `>`, `"`) come back
  raw (not entity-encoded) in an executable context.
- Stored: the payload is served back un-encoded on a subsequent, separate fetch
  of the rendering page.
- Content-Type is `text/html` (a payload reflected into a `application/json`
  response that's never HTML-rendered is not XSS by itself).

**False positive / not confirmed:**
- Marker reflects but `<`/`>`/`"` come back HTML-entity-encoded — output encoding
  is doing its job.
- Reflection only in a non-executed context (e.g. inside a JSON string the client
  renders as text, or a `Content-Type: text/plain` response).
- Reflection only in a response to a request no other user/browser would make in
  a way that executes (self-XSS with no delivery path) — note the limitation.
- A CSP that would block inline script — worth noting it may not be exploitable
  even if reflected raw.

## Tooling

- `probe_variant` fits the reflection + encoding check well: baseline = benign
  marker, variant = marker with `<>"` metacharacters, then inspect whether the
  variant's body contains them raw. Prefer this for the confirm/deny decision.
- Fall back to `execute_python` for stored XSS (submit-then-fetch-elsewhere
  chains) or when you need to parse the response to locate exactly how the input
  was encoded in a specific element. Use `ronin_target.request` for network calls.
