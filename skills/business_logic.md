# Business Logic Flaws

The application enforces its intended rules incorrectly, letting an attacker abuse
legitimate functionality in unintended ways — e.g. negative quantities/prices,
skipping required workflow steps, race conditions, coupon/discount abuse, or
quantity/limit bypasses. There's no single payload; it's about violating an
assumption the app makes. Catch-all for findings that don't fit a named class.

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
