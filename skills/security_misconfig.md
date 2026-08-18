---
status: full
cwe: CWE-16
attack_technique: T1190
attack_tactic: Initial Access
---

# Security Misconfiguration

Confirming a security misconfiguration means retrieving real sensitive
content or demonstrating a genuinely exploitable exposed feature — a bare
200 status on a guessed path is not enough; the response body has to
actually contain something sensitive.

## What to check, in order

1. **Sensitive-path checklist.** Request each of these directly and inspect
   the actual response body (not just status code):
   - `/.git/config` / `/.git/HEAD` — exposed version control (can lead to
     full source disclosure via further `.git` object requests)
   - `/.env` — exposed environment file (credentials, API keys)
   - `/phpinfo.php`, `/info.php`, `/test.php` — PHP config disclosure
   - Backup/temp files: `<known-file>.bak`, `<known-file>~`,
     `<known-file>.old`, `<known-file>.orig`
   - `/.well-known/`, `/admin`, `/manager`, `/console` — admin surfaces
     that may be reachable without auth
   - `/robots.txt`, `/sitemap.xml` — not sensitive themselves, but often
     name other paths worth checking directly
2. **Directory listing.** Request a directory path directly (no filename,
   trailing slash) for any directory referenced elsewhere on the site — an
   Apache/nginx-style autoindex listing real filenames is a genuine finding.
3. **Verbose error disclosure.** Send input designed to trigger a
   server-side error (malformed data, an unexpected type, a very long
   value) and check whether the response includes a stack trace, file
   paths, framework/library version strings, or SQL fragments — not just
   whether it errors at all.
4. **Missing security headers**, on the main response: check for the
   absence of `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`,
   `Strict-Transport-Security`, `X-Content-Type-Options`. Note this
   category is lower-severity by itself — record it as evidence but don't
   overstate a missing header alone as equivalent to an active exploit.
5. **Confirm content, always.** For every path above, the finding requires
   the response body to actually contain what the path implies (real git
   objects, real env values, a real stack trace, real file names in a
   listing) — a 200 with a generic app page (many SPAs return 200 + their
   normal shell for any path) is not evidence.

## Response signatures

**Real finding:**
- `.git/config`/`.env`/backup file responses contain real, readable
  content matching what that file type should look like (git remote URLs,
  actual environment variable assignments, real source/config content).
- A triggered error response includes a genuine stack trace, internal file
  paths, or library/version strings.
- Directory listing shows real filenames from the actual filesystem.

**False positive / not confirmed:**
- 200 status but the body is the app's normal page/shell (common with
  SPAs and catch-all routing) — check the body matches the expected file
  type, not just the status code.
- A 403/404 styled as a normal page (some apps serve a branded 404 with a
  200 status) — verify the body doesn't just look like a generic response.
- Missing headers alone, with no other exposure — real, but lower severity;
  don't inflate it to the same confidence as a confirmed content leak.

## Tooling

- `probe_variant` fits most of this directly: request each candidate path
  and inspect the body/status returned — no diffing needed against a
  baseline for most checks, just direct inspection of a single response.
- Fall back to `execute_python` for constructing an error-triggering
  payload that needs specific malformed structure, or for following up a
  `.git/HEAD` hit with further object requests to assess how much source
  is actually exposed.
