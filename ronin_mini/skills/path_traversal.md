---
status: full
cwe: CWE-22
attack_technique: T1190
attack_tactic: Initial Access
---

# Path Traversal / Local File Inclusion

Confirming path traversal means retrieving the actual content of a file
outside the intended directory — not just a different status code or error
message.

## What to check, in order

1. **Identify a parameter that names a file/path.** Filename, template,
   page, document, or image parameters (`?file=`, `?page=`, `?doc=`) are the
   classic candidates, especially if the value already looks like a relative
   path or filename.
2. **Baseline first.** Request the endpoint with its original, legitimate
   value and note the response (status, body shape, content-type).
3. **Basic traversal.** Try a depth-guessed `../` chain to a well-known file:
   - Unix: `../../../../etc/passwd` (vary the depth, 2-8 levels, since you
     don't know the app's base directory)
   - Windows: `..\..\..\..\windows\win.ini`
4. **If the raw sequence is filtered, try encoding/bypass variants** before
   concluding dead-end:
   - URL-encoded: `%2e%2e%2f` (`../`), `%2e%2e/`
   - Double-encoded: `%252e%252e%252f`
   - Absolute path directly: `/etc/passwd` (some parameters concatenate a
     base dir + input naively and an absolute path overrides it)
   - Null byte (legacy PHP <5.3.4 only, rarely relevant now but cheap to try
     if the stack looks old): `../../etc/passwd%00.jpg`
5. **PHP-specific: stream wrappers**, if the app is PHP and traversal alone
   is filtered:
   - `php://filter/convert.base64-encode/resource=<local file>` — reads
     source code instead of executing it, defeating naive extension checks.
6. **Confirm via content, not status.** A 200 alone proves nothing —
   the response body must contain the target file's actual, recognizable
   content.

## Response signatures

**Real finding:**
- Response body contains the real content of a known file: `/etc/passwd`'s
  `root:x:0:0:` line, `win.ini`'s `[fonts]`/`[extensions]` section, or (via
  `php://filter`) recognizable source code (`<?php` plus real application
  logic) instead of a rendered page.

**False positive / not confirmed:**
- A 200 with generic/unrelated content (a default error page, the app's own
  "file not found" page rendered as 200) — check the actual body, not the
  status code.
- The response is identical regardless of how many `../` you add or what
  file you name — the parameter likely isn't used as a real path at all.
- Traversal chars appear stripped/normalized in any reflected output —
  sanitization may be active; try the encoding variants in step 4 before
  giving up.

## Tooling

- `probe_variant` fits this well: baseline = legitimate value, variant =
  traversal payload, diff the bodies. Good for the basic and encoded-bypass
  attempts.
- Fall back to `execute_python` for depth-guessing loops (trying several
  `../` counts programmatically) or when you need to inspect/decode a
  `php://filter` base64 response body. Use `ronin_target.request` for
  network calls in that code.
