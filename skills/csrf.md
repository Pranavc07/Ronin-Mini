# Cross-Site Request Forgery (CSRF)

A state-changing request can be forged from another origin because it lacks an
unpredictable anti-CSRF token (or the token isn't validated), relying only on
ambient credentials like cookies.

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
