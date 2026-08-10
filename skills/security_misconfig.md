# Security Misconfiguration

A broad class covering insecure defaults, exposed sensitive endpoints (e.g.
`phpinfo`, admin panels, `.git`, backups), verbose error/stack-trace disclosure,
missing security headers, directory listing, or debug features left enabled in a
reachable environment. Also the catch-all for information-disclosure findings.

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
