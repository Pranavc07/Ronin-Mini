---
status: full
cwe: CWE-918
attack_technique: T1190
attack_tactic: Initial Access
---

# Server-Side Request Forgery (SSRF)

Confirming SSRF means showing the server itself made a request to a
destination you chose — internal, cloud-metadata, or otherwise — not just
that a URL parameter exists.

## What to check, in order

1. **Identify a parameter that takes a URL, hostname, or file reference** —
   webhook/callback URLs, "import from URL," avatar/image-from-URL,
   PDF/document generators that fetch a remote resource, SSO/OAuth
   discovery-URL fields.
2. **In-band confirmation, if the response reflects fetched content.** Point
   the parameter at an internal/loopback target and see if the response
   contains that target's actual content instead of an error:
   - `http://127.0.0.1/` or `http://localhost/` — does the response now
     show a *different* body than pointing at the original external target?
   - `http://169.254.169.254/latest/meta-data/` (cloud instance metadata,
     if the target plausibly runs on a cloud VM) — real metadata content in
     the response is a severe, high-confidence finding.
   - An internal-only port on the target host itself (e.g. `127.0.0.1:22`,
     `127.0.0.1:3306`) — a *different* error (connection refused vs a real
     banner/timeout) between a closed and open internal port is itself a
     port-scanning signal even without full content disclosure.
3. **If nothing reflects (blind SSRF), use timing/error differentials
   instead.** Compare response time/error message for a target you're
   confident is closed (fast connection-refused) vs one you're testing —
   consistently different behavior across repeats supports the request
   left the server, even with no visible output.
4. **Try protocol/format variations if the plain URL is rejected** by
   allowlist filtering: alternate IP encodings (`http://0177.0.0.1/` octal,
   `http://2130706433/` decimal for 127.0.0.1), or a redirect chain
   (point at an external URL you control that 302s to the internal target,
   if the fetcher follows redirects) — note this only if the app's own
   validation clearly happens before redirect-following.
5. **True blind SSRF (no observable response difference at all): use
   out-of-band confirmation.** Call `generate_oob_url`, point the vulnerable
   parameter at the returned URL instead of an internal target, then call
   `poll_oob_interactions` with the same correlation_id. A real DNS/HTTP
   callback is direct, independent proof the server made the outbound
   request — the strongest possible SSRF confirmation, since it doesn't
   depend on any response content leaking back at all. If polling shows
   nothing, wait briefly and poll once more before concluding `dead-end` —
   some fetches (queued jobs, async webhooks) take a moment to fire.

## Response signatures

**Real finding:**
- Response body contains actual content from the internal/loopback/
  metadata target that differs from what the legitimate external URL
  returns.
- Consistent, repeatable behavioral difference (error type, timing) between
  a known-closed and known-open internal target.

**False positive / not confirmed:**
- Identical error/response regardless of target — the app likely validates
  the URL before fetching, or isn't actually making a server-side request
  from user input at all.
- The parameter accepts a URL but only ever fetches a fixed, allowlisted
  set of destinations server-side (input just selects from a list).
- A generic timeout with no distinguishing pattern between different
  internal targets — not enough signal to call it confirmed.

## Tooling

- `execute_python` (via `ronin_target.request`) is the primary tool —
  SSRF confirmation usually needs timing comparisons or trying several
  encoded target variants in sequence.
- `probe_variant` works for the simple in-band case (baseline = original
  external URL, variant = internal target) when you just need a body diff,
  no timing logic.
- `generate_oob_url` + `poll_oob_interactions` for the true-blind case —
  see step 5.
