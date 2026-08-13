---
status: stub
cwe: CWE-1336
attack_technique: T1190
attack_tactic: Initial Access
---

# Server-Side Template Injection (SSTI)

User input is embedded into a server-side template and evaluated, letting an
attacker run template expressions (and often escalate to code execution) —
classic probe is a math expression like `{{7*7}}` rendering as `49`.

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
