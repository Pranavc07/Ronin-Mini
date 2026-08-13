---
status: stub
cwe: CWE-352
attack_technique: T1190
attack_tactic: Initial Access
---

# Cross-Site Request Forgery (CSRF)

A state-changing request can be forged from another origin because it lacks an
unpredictable anti-CSRF token (or the token isn't validated), relying only on
ambient credentials like cookies.

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
