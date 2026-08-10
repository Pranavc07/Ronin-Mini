# Unrestricted / Malicious File Upload

An upload feature fails to properly validate file type, content, or storage
location, allowing an attacker to upload a dangerous file (e.g. a web shell, or a
file that's later served/executed) or to abuse the upload for other impact
(overwrite, path control, XSS via served content).

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
