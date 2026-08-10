# Path Traversal / Local File Inclusion

A file-path or filename parameter isn't properly constrained, so sequences like
`../` (or absolute paths, or PHP stream wrappers) let an attacker read files
outside the intended directory — confirmed by retrieving a file that should be
inaccessible (e.g. `/etc/passwd`, app config/source).

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
