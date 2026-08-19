"""Unit tests for executor.run_http's manual redirect-following: every hop
must be independently re-validated against scope.validate_host before it's
followed, so an initially in-scope URL can never redirect the caller out of
scope. Covers the exact scenarios flagged in the hardening review: HTTP and
HTTPS redirects to an out-of-scope host, relative and absolute redirects,
chained redirects, redirect loops (must terminate via the cap, not hang),
disallowed schemes, and malformed/unparseable Location headers.

No network, no Docker -- requests.request is mocked throughout.

Run with: pytest tests/test_redirect_scope.py -v
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin_mini", "ronin-tools-mcp"))

import executor  # noqa: E402
from categories import recon, web_exploit  # noqa: E402
from categories.exploit_runtime import _HELPER_TEMPLATE  # noqa: E402
from scope import Scope  # noqa: E402


def _scope(allowed_hosts=("target.test",)):
    return Scope(scope_dir=_REPO_ROOT, allowed_hosts=list(allowed_hosts))


def _fake_response(status_code, location=None, text="", headers=None):
    hdrs = dict(headers or {})
    if location is not None:
        hdrs["Location"] = location
    return SimpleNamespace(status_code=status_code, headers=hdrs, text=text, url="unused")


# --- no redirect: baseline ---------------------------------------------------


def test_no_redirect_returns_normally():
    with patch("executor.requests.request", return_value=_fake_response(200, text="ok")) as mock_req:
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert result["status_code"] == 200
    assert result["body"] == "ok"
    assert result["redirect_chain"] == [{"url": "http://target.test/", "allowed": True, "status_code": 200}]
    mock_req.assert_called_once()
    assert mock_req.call_args.kwargs["allow_redirects"] is False


# --- the actual bug: out-of-scope redirect targets --------------------------


def test_http_redirect_to_out_of_scope_host_is_rejected():
    with patch("executor.requests.request", return_value=_fake_response(302, location="http://evil.test/steal")):
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert "evil.test" in result["error"]
    chain = result["redirect_chain"]
    assert chain[-1] == {"url": "http://evil.test/steal", "allowed": False, "reason": chain[-1]["reason"]}
    assert "evil.test" in chain[-1]["reason"]


def test_https_redirect_to_out_of_scope_http_host_is_rejected():
    with patch("executor.requests.request", return_value=_fake_response(301, location="http://evil.test/")):
        result = executor.run_http("GET", "https://target.test/", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert result["redirect_chain"][-1]["allowed"] is False


def test_relative_redirect_to_out_of_scope_path_stays_in_scope():
    """A relative redirect resolves against the current host -- same host,
    different path, must be allowed (this is the common, legitimate case:
    a login redirect to /dashboard on the same app).
    """
    responses = [
        _fake_response(302, location="/dashboard"),
        _fake_response(200, text="welcome"),
    ]
    with patch("executor.requests.request", side_effect=responses):
        result = executor.run_http("GET", "http://target.test/login", None, None, timeout=5, scope=_scope())
    assert result["status_code"] == 200
    assert result["body"] == "welcome"
    assert len(result["redirect_chain"]) == 2
    assert result["redirect_chain"][1]["url"] == "http://target.test/dashboard"


def test_relative_redirect_using_protocol_relative_url_to_out_of_scope_host_is_rejected():
    """A protocol-relative Location ("//evil.test/x") is a classic obfuscated
    redirect target -- urljoin resolves it to a full URL on a different host,
    which must be caught by the same scope check as an absolute redirect.
    """
    with patch("executor.requests.request", return_value=_fake_response(302, location="//evil.test/steal")):
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert result["redirect_chain"][-1]["allowed"] is False


def test_absolute_redirect_to_in_scope_host_is_followed():
    responses = [
        _fake_response(302, location="http://target.test/next"),
        _fake_response(200, text="final"),
    ]
    with patch("executor.requests.request", side_effect=responses) as mock_req:
        result = executor.run_http("GET", "http://target.test/start", None, None, timeout=5, scope=_scope())
    assert result["status_code"] == 200
    assert result["body"] == "final"
    assert mock_req.call_count == 2
    assert len(result["redirect_chain"]) == 2
    assert all(hop["allowed"] for hop in result["redirect_chain"])


def test_multiple_chained_redirects_all_in_scope_succeed():
    responses = [
        _fake_response(301, location="http://target.test/a"),
        _fake_response(302, location="http://target.test/b"),
        _fake_response(303, location="http://target.test/c"),
        _fake_response(200, text="done"),
    ]
    with patch("executor.requests.request", side_effect=responses) as mock_req:
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert result["status_code"] == 200
    assert result["body"] == "done"
    assert mock_req.call_count == 4
    assert len(result["redirect_chain"]) == 4


def test_chain_that_goes_out_of_scope_partway_through_is_rejected():
    """First two hops in-scope, third redirects out -- must reject at the
    third hop specifically, not follow it just because earlier hops passed.
    """
    responses = [
        _fake_response(302, location="http://target.test/a"),
        _fake_response(302, location="http://evil.test/b"),
    ]
    with patch("executor.requests.request", side_effect=responses) as mock_req:
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert mock_req.call_count == 2  # did not attempt a 3rd request to evil.test
    chain = result["redirect_chain"]
    assert chain[0]["allowed"] is True
    assert chain[1]["allowed"] is True
    assert chain[2]["allowed"] is False
    assert "evil.test" in chain[2]["reason"]


# --- redirect loops: must terminate, not hang --------------------------------


def test_redirect_loop_terminates_via_max_count():
    def always_redirect(*args, **kwargs):
        return _fake_response(302, location="http://target.test/loop")

    with patch("executor.requests.request", side_effect=always_redirect) as mock_req:
        result = executor.run_http("GET", "http://target.test/loop", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert "max redirect count" in result["error"].lower() or "exceeded" in result["error"].lower()
    # exactly MAX_REDIRECTS + 1 real requests attempted, not an unbounded loop
    assert mock_req.call_count == executor.MAX_REDIRECTS + 1


def test_two_hop_redirect_loop_also_terminates():
    call_log = []

    def alternating(*args, **kwargs):
        url = kwargs.get("url") or args[1]
        call_log.append(url)
        next_path = "/b" if url.endswith("/a") else "/a"
        return _fake_response(302, location=f"http://target.test{next_path}")

    with patch("executor.requests.request", side_effect=alternating):
        result = executor.run_http("GET", "http://target.test/a", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert len(call_log) == executor.MAX_REDIRECTS + 1


# --- disallowed schemes -------------------------------------------------------


def test_redirect_to_disallowed_scheme_is_rejected():
    with patch("executor.requests.request", return_value=_fake_response(302, location="file:///etc/passwd")):
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert "scheme" in result["error"].lower()
    assert result["redirect_chain"][-1]["allowed"] is False


def test_initial_url_with_disallowed_scheme_is_rejected_before_any_request():
    with patch("executor.requests.request") as mock_req:
        result = executor.run_http("GET", "javascript:alert(1)", None, None, timeout=5, scope=_scope())
    assert "error" in result
    mock_req.assert_not_called()


# --- malformed / unparseable redirect targets --------------------------------


def test_malformed_location_header_is_rejected_not_crashed():
    # No host at all once resolved -- urljoin against a relative garbage
    # value still needs *some* host to pass scope; empty/garbage host fails
    # the same validate_host check as an out-of-scope one, cleanly.
    with patch("executor.requests.request", return_value=_fake_response(302, location="   ")):
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    # Must not raise -- either rejected as out of scope/malformed, or (if it
    # resolves to the same host with a whitespace path) allowed. Either way,
    # no exception propagates out of run_http.
    assert isinstance(result, dict)


def test_redirect_status_with_no_location_header_returns_final_response():
    # A 302 without a Location header isn't a followable redirect -- treat
    # it as the final response rather than crashing on a missing header.
    with patch("executor.requests.request", return_value=_fake_response(302, location=None, text="weird")):
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert result["status_code"] == 302
    assert result["body"] == "weird"


# --- encoded/obfuscated IP targets are rejected by the literal string match -


def test_redirect_to_decimal_encoded_ip_is_rejected():
    """127.0.0.1 encoded as a decimal integer (2130706433) is a classic
    allowlist-bypass trick -- it doesn't literally match any allowed
    hostname string, so it's rejected the same way any other unknown host
    is, no special-casing needed.
    """
    with patch("executor.requests.request", return_value=_fake_response(302, location="http://2130706433/")):
        result = executor.run_http("GET", "http://target.test/", None, None, timeout=5, scope=_scope())
    assert "error" in result
    assert result["redirect_chain"][-1]["allowed"] is False


# --- 303/POST-to-GET downgrade semantics -------------------------------------


def test_303_redirect_downgrades_post_to_get_and_drops_body():
    responses = [
        _fake_response(303, location="http://target.test/result"),
        _fake_response(200, text="ok"),
    ]
    with patch("executor.requests.request", side_effect=responses) as mock_req:
        result = executor.run_http(
            "POST", "http://target.test/submit", None, "some=data", timeout=5, scope=_scope()
        )
    assert result["status_code"] == 200
    second_call_kwargs = mock_req.call_args_list[1].kwargs
    assert second_call_kwargs["method"] == "GET"
    assert second_call_kwargs["data"] is None


# --- integration: the REAL registered http_request/probe_variant closures -
#
# Everything above tests executor.run_http directly. These tests close the
# remaining gap -- that categories/recon.py's http_request and
# categories/web_exploit.py's probe_variant, as actually registered onto the
# MCP server, correctly thread their own `scope` closure variable into
# run_http's new scope= parameter, not just that run_http itself is correct
# in isolation.


class _ToolCollector:
    """Fake mcp.add_tool: captures registered tool functions by name so
    tests can call them directly without a real MCP server/transport.
    """

    def __init__(self):
        self.tools: dict = {}

    def add_tool(self, fn):
        self.tools[fn.__name__] = fn


def test_registered_http_request_rejects_out_of_scope_redirect():
    collector = _ToolCollector()
    recon.register(collector, _scope(), executor, {})
    with patch("executor.requests.request", return_value=_fake_response(302, location="http://evil.test/steal")):
        result = collector.tools["http_request"]("GET", "http://target.test/")
    assert "error" in result
    assert "evil.test" in result["error"]


def test_registered_http_request_follows_in_scope_redirect():
    collector = _ToolCollector()
    recon.register(collector, _scope(), executor, {})
    responses = [
        _fake_response(302, location="http://target.test/next"),
        _fake_response(200, text="final"),
    ]
    with patch("executor.requests.request", side_effect=responses):
        result = collector.tools["http_request"]("GET", "http://target.test/start")
    assert result["status_code"] == 200
    assert result["body"] == "final"


def test_registered_probe_variant_rejects_out_of_scope_redirect_on_either_branch():
    collector = _ToolCollector()
    web_exploit.register(collector, _scope(), executor, {})
    with patch("executor.requests.request", return_value=_fake_response(302, location="http://evil.test/steal")):
        result = collector.tools["probe_variant"]("GET", "http://target.test/")
    # both baseline and variant hit the same (mocked) redirect -- both legs
    # of the diff must show the rejection, not silently succeed
    assert "error" in result["baseline"]
    assert "error" in result["variant"]
    assert result["diff"] == {"comparable": False}


# --- the SECOND copy of this bug: ronin_target.py's generated request() ----
#
# categories/exploit_runtime.py's _HELPER_TEMPLATE is injected into every
# execute_python sandbox container -- it can't import the real scope.py (an
# isolated container has no access to the main process), so it carries its
# own self-contained redirect-following logic. Rendered and exec'd here
# in-process (pure stdlib + requests, no Docker needed to test the logic
# itself) with the real `requests` package's .request patched, since the
# rendered code's own `import requests` resolves to the same cached module
# object.


def _load_ronin_target(allowed_hosts=("target.test",), host_map=None):
    rendered = _HELPER_TEMPLATE.format(allowed_hosts=set(allowed_hosts), host_map=host_map or {})
    namespace: dict = {}
    exec(compile(rendered, "<ronin_target.py>", "exec"), namespace)  # noqa: S102 -- test-only, rendering our own template
    return namespace


def test_ronin_target_request_no_redirect_returns_response():
    ns = _load_ronin_target()
    with patch("requests.request", return_value=_fake_response(200, text="ok")):
        resp = ns["request"]("GET", "http://target.test/")
    assert resp.status_code == 200
    assert resp.text == "ok"
    assert resp.history == []


def test_ronin_target_request_rejects_out_of_scope_redirect():
    ns = _load_ronin_target()
    with patch("requests.request", return_value=_fake_response(302, location="http://evil.test/steal")):
        try:
            ns["request"]("GET", "http://target.test/")
            raised = False
        except ns["ScopeError"] as e:
            raised = True
            assert "evil.test" in str(e)
    assert raised, "expected ScopeError for an out-of-scope redirect target"


def test_ronin_target_request_follows_in_scope_redirect_and_populates_history():
    ns = _load_ronin_target()
    responses = [
        _fake_response(302, location="http://target.test/next"),
        _fake_response(200, text="final"),
    ]
    with patch("requests.request", side_effect=responses):
        resp = ns["request"]("GET", "http://target.test/start")
    assert resp.status_code == 200
    assert resp.text == "final"
    assert len(resp.history) == 1
    assert resp.history[0].status_code == 302


def test_ronin_target_request_loop_terminates_via_max_count():
    ns = _load_ronin_target()
    call_count = {"n": 0}

    def always_redirect(*args, **kwargs):
        call_count["n"] += 1
        return _fake_response(302, location="http://target.test/loop")

    with patch("requests.request", side_effect=always_redirect):
        try:
            ns["request"]("GET", "http://target.test/loop")
            raised = False
        except ns["ScopeError"]:
            raised = True
    assert raised
    assert call_count["n"] == ns["_MAX_REDIRECTS"] + 1


def test_ronin_target_request_rejects_disallowed_scheme_redirect():
    ns = _load_ronin_target()
    with patch("requests.request", return_value=_fake_response(302, location="file:///etc/passwd")):
        try:
            ns["request"]("GET", "http://target.test/")
            raised = False
        except ns["ScopeError"] as e:
            raised = True
            assert "scheme" in str(e).lower()
    assert raised


def test_ronin_target_request_applies_loopback_host_map_on_every_hop():
    """localhost -> host.docker.internal translation must apply on redirect
    hops too, not just the first request -- otherwise a redirect on a
    loopback-scoped target would try to reach the container's own loopback
    instead of the real target.
    """
    ns = _load_ronin_target(allowed_hosts=("localhost",), host_map={"localhost": "host.docker.internal"})
    responses = [
        _fake_response(302, location="http://localhost/next"),
        _fake_response(200, text="ok"),
    ]
    with patch("requests.request", side_effect=responses) as mock_req:
        ns["request"]("GET", "http://localhost/start")
    urls_requested = [call.args[1] for call in mock_req.call_args_list]
    assert all("host.docker.internal" in u for u in urls_requested)
