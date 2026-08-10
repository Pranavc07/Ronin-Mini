# OS Command Injection

User input is passed into a shell command, letting an attacker append or inject
additional commands (via `;`, `&&`, `|`, backticks, `$()`) that the server
executes — confirmed by observing command output or an out-of-band effect.

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
