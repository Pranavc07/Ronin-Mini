"""End-to-end smoke test: runs the real agent loop against a local test
server (or OWASP Juice Shop if it's already running at localhost:3000) and
verifies a transcript JSON file is produced with the expected shape.

This makes a real call to the Anthropic API and is skipped automatically if
ANTHROPIC_API_KEY is not set. It does not assert that any particular
vulnerability is found -- only that the loop runs end to end.

Run with: pytest tests/test_e2e.py -v -s
"""

import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INDEX_HTML = b"""<!doctype html>
<html><head><title>Test Target</title></head>
<body>
<h1>Local test app</h1>
<p>version=1.0.0-test</p>
</body></html>
"""


def _juice_shop_available() -> bool:
    try:
        urllib.request.urlopen("http://localhost:3000", timeout=2)
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def local_test_server(tmp_path_factory):
    if _juice_shop_available():
        yield "http://localhost:3000"
        return

    web_root = tmp_path_factory.mktemp("webroot")
    (web_root / "index.html").write_bytes(INDEX_HTML)

    handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(
        *a, directory=str(web_root), **kw
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set; skipping live end-to-end test",
)
def test_agent_loop_runs_end_to_end(local_test_server, tmp_path):
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    cmd = [
        sys.executable,
        os.path.join(ROOT, "main.py"),
        "--target", local_test_server,
        "--objective", "Do a very quick initial recon pass; call at most one or two tools then stop.",
        "--scope-dir", str(scope_dir),
        "--max-iterations", "3",
        "--max-minutes", "3",
        "--output-dir", str(output_dir),
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    print(proc.stdout)
    print(proc.stderr, file=sys.stderr)

    assert proc.returncode == 0, f"agent run failed: {proc.stderr}"

    transcript_files = list(output_dir.glob("transcript_*.json"))
    assert len(transcript_files) == 1, "expected exactly one transcript file"

    with open(transcript_files[0], encoding="utf-8") as f:
        data = json.load(f)

    assert "metadata" in data
    assert "transcript" in data
    assert "findings" in data
    assert data["metadata"]["target"] == local_test_server
    assert data["metadata"]["stop_reason"] in {
        "end_turn",
        "iteration_cap",
        "wall_clock_cap",
    }
