---
status: full
cwe: CWE-502
attack_technique: T1190
attack_tactic: Initial Access
---

# Insecure Deserialization

Confirming insecure deserialization means showing the server actually
deserializes attacker-controlled data server-side — evidenced by a
behavioral difference between valid, tampered, and malformed serialized
input — not just that a serialized-looking blob exists somewhere.

## What to check, in order

1. **Find a serialized blob** in a cookie, hidden form field, API request/
   response body, or cache value. Identify the format by signature:
   - Java: base64 starting `rO0` (raw bytes `AC ED 00 05`)
   - PHP: `O:8:"ClassName":N:{...}` or `a:N:{...}` (array)
   - Python pickle: base64/binary starting with an opcode-heavy pattern
     (`\x80\x04` for protocol 4, or a `c` opcode for global imports in
     older protocols), or a `!!python/object` tag if using unsafe YAML
   - .NET: base64 often containing `TypeObject`/`AAEAAAD/////` (BinaryFormatter
     header)
2. **Baseline.** Confirm the blob round-trips normally — submit it back
   unmodified and confirm the app accepts it and behaves as expected.
3. **Malformed-input differential.** Submit the blob with a single byte
   corrupted (flip one byte inside the serialized structure, not the
   encoding wrapper) and compare the error against a completely
   different-shaped garbage value (e.g. a random string that isn't
   serialized data at all):
   - A *specific* deserialization error (e.g. a Java
     `ClassNotFoundException`/`InvalidClassException`, a PHP
     "unserialize(): Error at offset") proves the server is actually
     running a deserializer against your input — different error classes
     for "malformed serialized data" vs "not serialized data at all" is
     strong confirmation.
   - A generic, identical error for both cases is weaker evidence — the
     value might just be opaquely stored/compared, not deserialized.
4. **Field-tampering probe**, if the format allows readable field
   inspection (PHP's format is plaintext-readable, Java/`.NET` are
   binary): modify a *non-critical* field's value in an otherwise-valid
   blob (e.g. change a display name inside a PHP serialized object) and
   see if the modified value is reflected back — confirms the server
   parsed and used your tampered structure, not just validated a
   signature/checksum on the whole blob.
5. **Be explicit that full RCE-via-gadget-chain is out of scope for this
   skill.** Building a working gadget chain (ysoserial-style for Java,
   PHPGGC-style for PHP) requires target-specific library/classpath
   knowledge this harness can't enumerate generically. The bar here is
   confirming the server deserializes attacker-influenced data unsafely
   (steps 3-4) — record that as the finding; full RCE escalation is a
   follow-up requiring manual gadget-chain research, not something
   `execute_python` can construct from scratch.

## Response signatures

**Real finding:**
- Distinct, deserializer-specific error messages differentiate malformed
  serialized data from non-serialized garbage — proves server-side
  deserialization is occurring.
- A tampered non-critical field's new value is reflected/used by the app
  after round-tripping a modified blob — proves the server parsed your
  modified structure rather than rejecting it via signature/HMAC check.

**False positive / not confirmed:**
- Any tampering (even a single flipped byte) produces the exact same
  generic rejection as completely garbage input — likely an
  integrity-checked (signed/HMAC'd) blob rejected before deserialization
  even starts.
- The "serialized-looking" value is actually just an opaque token/ID that's
  looked up server-side, never deserialized at all.

## Tooling

- `execute_python` (via `ronin_target.request`) is the primary tool —
  constructing and tampering with binary/structured serialized payloads,
  and comparing error responses, needs real code, not a fixed diff shape.
- `probe_variant` can carry the simple round-trip and error-differential
  checks (baseline = valid blob, variant = corrupted blob) if the blob is
  just a request body or cookie value being swapped — use it for the
  quick differential before reaching for custom payload construction.
