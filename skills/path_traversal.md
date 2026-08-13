---
status: stub
cwe: CWE-22
attack_technique: T1190
attack_tactic: Initial Access
---

# Path Traversal / Local File Inclusion

A file-path or filename parameter isn't properly constrained, so sequences like
`../` (or absolute paths, or PHP stream wrappers) let an attacker read files
outside the intended directory — confirmed by retrieving a file that should be
inaccessible (e.g. `/etc/passwd`, app config/source).

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
