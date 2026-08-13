---
status: stub
cwe: CWE-16
attack_technique: T1190
attack_tactic: Initial Access
---

# Security Misconfiguration

A broad class covering insecure defaults, exposed sensitive endpoints (e.g.
`phpinfo`, admin panels, `.git`, backups), verbose error/stack-trace disclosure,
missing security headers, directory listing, or debug features left enabled in a
reachable environment. Also the catch-all for information-disclosure findings.

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
