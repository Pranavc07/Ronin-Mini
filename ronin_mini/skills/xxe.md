---
status: full
cwe: CWE-611
attack_technique: T1190
attack_tactic: Initial Access
---

# XML External Entity (XXE) Injection

Confirming XXE means showing an attacker-defined external entity actually
gets resolved by the server's XML parser — the entity's referenced content
(a local file, or an SSRF side effect) appears, not just that XML input is
accepted.

## What to check, in order

1. **Confirm the endpoint accepts and parses XML.** Content-Type
   `application/xml`/`text/xml`, a SOAP endpoint, a file-upload that takes
   `.xml`/`.docx`/`.svg` (all of these can contain embedded XML with a
   DOCTYPE), or an API that clearly deserializes XML into objects.
2. **Baseline.** Submit well-formed, legitimate XML first and confirm a
   normal response — you need to know what "working" looks like before
   testing for injection.
3. **In-band file-read probe.** Submit XML with a DOCTYPE declaring an
   external entity pointing at a known local file, referenced in a field
   that gets reflected back in the response:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>
   ```
   If the response includes real file content (e.g. `root:x:0:0:` from
   `/etc/passwd`) in place of `&xxe;`, that's confirmed in-band XXE.
4. **If nothing reflects, try an SSRF-style entity** instead of a file read
   — point the external entity at an internal/loopback URL you control the
   interpretation of, same signal logic as the SSRF skill (differing
   response/error/timing vs a clearly-external target).
5. **Blind XXE: use out-of-band confirmation.** If in-band file-read and
   SSRF-style probes both show nothing, call `generate_oob_url` and
   reference it in the external entity/DTD instead of a local file or
   internal target:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<oob-url>/">]>
   <foo>&xxe;</foo>
   ```
   Then `poll_oob_interactions` with the same correlation_id — a real
   callback means the parser resolved the external entity, direct proof of
   XXE with no dependence on any content reflecting back. A full external-
   DTD/data-exfiltration chain (parameter entities pulling a local file's
   content into the OOB request path) is a further escalation once basic
   entity resolution is confirmed this way, not required for the base
   finding.

## Response signatures

**Real finding:**
- Response contains real local-file content (recognizable file structure,
  e.g. `/etc/passwd`'s `root:` line) in place of the entity reference.
- Response/timing behavior for an internal-target entity clearly differs
  from a known-external one, mirroring the SSRF confirmation signal.

**False positive / not confirmed:**
- Parser returns an XML parsing error and nothing else — many modern
  parsers reject external entities by default (a secure config, not a
  finding) or the payload was malformed, not blocked.
- The entity reference is stripped/not reflected anywhere in the response
  — no observable channel for the in-band variant even if it's technically
  parsed.
- Identical behavior for internal vs external entity targets — no evidence
  the request differs at all.

## Tooling

- `execute_python` (via `ronin_target.request`) is the primary tool — XXE
  needs constructing a specific XML/DOCTYPE payload and posting it with the
  right content-type, which isn't a shape `probe_variant` covers directly.
- `probe_variant` can work if the XML payload itself is the only thing that
  varies between baseline and variant and both are simple POST bodies —
  baseline = legitimate XML, variant = XXE payload.
- `generate_oob_url` + `poll_oob_interactions` for the blind case — see
  step 5.
