"""recon category: http_request, dns_lookup -- ported from Ronin-Mini's tools.py."""

from __future__ import annotations

import socket

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None

from manifest import DEFAULT_TIMEOUT_SECONDS

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT")


def register(mcp, scope, executor, timeouts: dict) -> None:
    def http_request(
        method: str, url: str, headers: dict | None = None, body: str | None = None
    ) -> dict:
        """Send an HTTP request to a target URL within scope."""
        try:
            scope.validate_host(url)
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}
        return executor.run_http(
            method, url, headers, body, timeout=timeouts.get("http_request", DEFAULT_TIMEOUT_SECONDS)
        )

    def dns_lookup(hostname: str) -> dict:
        """Resolve A/AAAA/CNAME/TXT DNS records for a hostname within scope."""
        try:
            scope.validate_host(hostname)
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

        timeout = timeouts.get("dns_lookup", DEFAULT_TIMEOUT_SECONDS)
        results: dict[str, list[str]] = {}
        errors: dict[str, str] = {}

        if dns is not None:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            for rtype in DNS_RECORD_TYPES:
                try:
                    answers = resolver.resolve(hostname, rtype)
                    results[rtype] = [str(r) for r in answers]
                except dns.resolver.NoAnswer:
                    results[rtype] = []
                except dns.resolver.NXDOMAIN:
                    errors["NXDOMAIN"] = f"{hostname} does not exist"
                    break
                except Exception as e:  # noqa: BLE001
                    errors[rtype] = f"{type(e).__name__}: {e}"
        else:  # pragma: no cover - fallback path when dnspython missing
            try:
                infos = socket.getaddrinfo(hostname, None)
                addrs = sorted({info[4][0] for info in infos})
                results["A"] = [a for a in addrs if ":" not in a]
                results["AAAA"] = [a for a in addrs if ":" in a]
            except socket.gaierror as e:
                errors["socket"] = str(e)

        out = {"hostname": hostname, "records": results}
        if errors:
            out["errors"] = errors
        return out

    mcp.add_tool(http_request)
    mcp.add_tool(dns_lookup)
