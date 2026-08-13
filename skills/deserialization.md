---
status: stub
cwe: CWE-502
attack_technique: T1190
attack_tactic: Initial Access
---

# Insecure Deserialization

The application deserializes attacker-controlled data with an unsafe deserializer,
allowing object injection, tampering, or remote code execution — often signalled
by serialized blobs in cookies, hidden fields, or API payloads (e.g. Java/PHP/
Python pickle formats, base64-encoded object graphs).

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
