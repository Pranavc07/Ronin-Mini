---
status: stub
cwe: CWE-611
attack_technique: T1190
attack_tactic: Initial Access
---

# XML External Entity (XXE) Injection

An XML parser processes attacker-supplied external entities, enabling local file
disclosure, SSRF, or denial of service — typically where the app accepts XML
input and the parser has external entity resolution enabled.

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
