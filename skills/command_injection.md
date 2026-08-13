---
status: stub
cwe: CWE-78
attack_technique: T1190
attack_tactic: Initial Access
---

# OS Command Injection

User input is passed into a shell command, letting an attacker append or inject
additional commands (via `;`, `&&`, `|`, backticks, `$()`) that the server
executes — confirmed by observing command output or an out-of-band effect.

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
