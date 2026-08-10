# Server-Side Request Forgery (SSRF)

The application can be coerced into making HTTP (or other-protocol) requests to a
destination the attacker controls — e.g. internal services, cloud metadata
endpoints, or arbitrary hosts — via a parameter that takes a URL, hostname, or
file reference.

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
