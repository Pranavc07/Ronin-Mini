# XML External Entity (XXE) Injection

An XML parser processes attacker-supplied external entities, enabling local file
disclosure, SSRF, or denial of service — typically where the app accepts XML
input and the parser has external entity resolution enabled.

Methodology not yet fleshed out for this class. Fall back to base reasoning and
use `execute_python` (via `ronin_target.request`) to construct and confirm the
proof of concept, staying within the authorized target scope.
