---
status: stub
cwe: CWE-434
attack_technique: T1190
attack_tactic: Initial Access
---

# Unrestricted / Malicious File Upload

An upload feature fails to properly validate file type, content, or storage
location, allowing an attacker to upload a dangerous file (e.g. a web shell, or a
file that's later served/executed) or to abuse the upload for other impact
(overwrite, path control, XSS via served content).

No hand-authored methodology yet for this class. Call `lookup_attack_technique`
(try the `attack_technique` id above first) for a relevant ATT&CK technique
reference, and derive your testing approach from its description before you
start probing. Use `execute_python` (via `ronin_target.request`) to construct
and confirm the proof of concept, staying within the authorized target scope.
