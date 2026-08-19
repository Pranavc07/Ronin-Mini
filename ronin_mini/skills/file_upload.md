---
status: full
cwe: CWE-434
attack_technique: T1190
attack_tactic: Initial Access
---

# Unrestricted / Malicious File Upload

Confirming a malicious file upload means showing an uploaded file is stored
somewhere reachable and served/interpreted in a way that has real impact
(executes as code, or is served with attacker-controlled content-type) — not
just that a file with a "wrong" extension was accepted.

## What to check, in order

1. **Baseline the upload.** Upload a legitimate file of the type the
   feature expects and note where it ends up — does the response return a
   URL/path to the stored file? Is it directly web-accessible?
2. **Extension-check probe.** Upload a file with a dangerous extension for
   the stack in play (`.php`/`.phtml` for PHP, `.asp`/`.aspx` for
   IIS/.NET, `.jsp` for Java) but otherwise matching what was accepted.
   Rejected? Note the exact rejection point (client-side only vs a real
   server error) before moving on.
3. **If extension is blocked, try bypass variants:**
   - Double extension: `shell.php.jpg` / `shell.jpg.php` (some configs
     execute on any `.php` anywhere in the name)
   - Case variation: `shell.PHP`, `shell.PhP` (case-insensitive filesystems/
     configs)
   - Null byte in legacy stacks: `shell.php%00.jpg` (rarely relevant on
     modern PHP, cheap to try if the stack looks old)
   - Content-Type header mismatch: upload with a `.php` filename but
     `Content-Type: image/jpeg` — some validators trust only the header.
4. **Content/magic-byte check.** If extension filtering holds firm, check
   whether *content* is validated at all: does prepending a valid image's
   magic bytes (e.g. GIF89a header) before your payload code let a
   `.php`-named file through a "must be a real image" check while still
   containing executable code the interpreter will find?
5. **Confirm impact by requesting the uploaded file back.** The upload
   succeeding is not the finding — request the stored file's URL directly
   and observe:
   - Is it served with the content-type/extension that makes it execute
     (e.g. actually runs as PHP) rather than download as a static file?
   - If it's not directly executable, does it still serve with an
     attacker-controlled `Content-Type` (e.g. `text/html` for an uploaded
     `.html`/`.svg`) that would enable stored XSS when linked to a victim?

## Response signatures

**Real finding:**
- The uploaded file is retrievable at a predictable/returned URL AND either
  executes server-side code (e.g. a PHP payload's output appears, not the
  raw source) or is served with a content-type that enables another
  concrete impact (stored XSS via `.html`/`.svg`).

**False positive / not confirmed:**
- Upload with a dangerous extension is rejected server-side (not just a
  client-side JS check you can bypass by calling the API directly).
- The file uploads and is stored, but requesting it back serves it as a
  forced download (`Content-Disposition: attachment`) with a generic
  content-type, or from a location with no execution context (e.g. an
  object-storage bucket serving static files only) — stored, but no
  demonstrated impact.
- Content is re-encoded/re-processed on upload (e.g. images are actually
  re-rendered through an image library), which would strip injected code
  even if the extension check is weak — verify the retrieved file still
  contains your payload before calling it confirmed.

## Tooling

- `execute_python` (via `ronin_target.request`) is the primary tool —
  multipart file uploads with crafted filenames/content/magic bytes need
  real request construction, and confirming impact needs a follow-up GET
  to the stored file's URL.
- `probe_variant` can work for a simple extension-swap comparison if the
  upload is a straightforward single-file POST and you just need to diff
  accept-vs-reject responses.
