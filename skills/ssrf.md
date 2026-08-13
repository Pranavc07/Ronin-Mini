---
status: stub
cwe: CWE-918
attack_technique: T1190
attack_tactic: Initial Access
---

# Server-Side Request Forgery (SSRF)

The application can be coerced into making HTTP (or other-protocol) requests to a
destination the attacker controls — e.g. internal services, cloud metadata
endpoints, or arbitrary hosts — via a parameter that takes a URL, hostname, or
file reference.

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
