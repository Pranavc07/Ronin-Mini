# Server-Side Template Injection (SSTI)

User input is embedded into a server-side template and evaluated, letting an
attacker run template expressions (and often escalate to code execution) —
classic probe is a math expression like `{{7*7}}` rendering as `49`.

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
