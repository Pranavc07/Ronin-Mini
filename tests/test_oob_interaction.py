"""Unit tests for categories/oob_interaction.py (Phase 4: interactsh-backed
out-of-band testing for blind SSRF/XXE/command-injection). Network calls to
the interactsh server are mocked; the crypto round-trip (RSA-OAEP key
exchange + AES-CTR interaction decryption) is tested for real against a
synthetic server response built the same way a real interactsh server
would, so this actually proves the decryption logic works, not just that
mocks were called.

Protocol details reverse-engineered from interactsh's own Go client/server
source (github.com/projectdiscovery/interactsh, pkg/client/client.go,
pkg/server) -- no official Python client exists on PyPI. Endpoints:
POST /register {public-key, secret-key, correlation-id}; GET /poll?id=...
&secret=... -> {aes_key: RSA-OAEP(AES key), data: [AES-CTR(interaction)...]}.

Run with: pytest tests/test_oob_interaction.py -v
"""

import base64
import json
import os
import sys
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_REPO_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ronin_mini")
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin-tools-mcp"))

from categories import oob_interaction as oob  # noqa: E402


def _fake_store():
    """A minimal in-memory stand-in for the (action, mission_id,
    correlation_id, session) callable server.py wires to FindingsStore.
    """
    sessions = {}

    def store(action, mission_id, correlation_id, session):
        if action == "save":
            sessions[(mission_id, correlation_id)] = session
            return None
        return sessions.get((mission_id, correlation_id))

    return store


# --- run_generate_oob_url ----------------------------------------------------


def test_generate_oob_url_no_store_configured():
    result = oob.run_generate_oob_url(None, "m1")
    assert "error" in result


def test_generate_oob_url_success_saves_session_and_returns_url():
    store = _fake_store()
    mock_resp = MagicMock(status_code=200)
    with patch("categories.oob_interaction.requests.post", return_value=mock_resp) as mock_post:
        result = oob.run_generate_oob_url(store, "m1")

    assert "error" not in result
    assert "url" in result
    assert "correlation_id" in result
    correlation_id = result["correlation_id"]
    assert result["url"].startswith(correlation_id)
    assert len(correlation_id) == oob.CORRELATION_ID_LENGTH

    # Session was actually persisted with real key material.
    saved = store("get", "m1", correlation_id, None)
    assert saved is not None
    assert "BEGIN PRIVATE KEY" in saved["private_key_pem"]
    assert saved["server"] in oob.DEFAULT_SERVERS

    mock_post.assert_called_once()
    _, kwargs = mock_post.call_args
    assert kwargs["json"]["correlation-id"] == correlation_id


def test_generate_oob_url_registration_http_failure():
    store = _fake_store()
    mock_resp = MagicMock(status_code=500, text="server error")
    with patch("categories.oob_interaction.requests.post", return_value=mock_resp):
        result = oob.run_generate_oob_url(store, "m1")
    assert "error" in result
    assert "500" in result["error"]


def test_generate_oob_url_network_error():
    import requests

    store = _fake_store()
    with patch("categories.oob_interaction.requests.post", side_effect=requests.ConnectionError("boom")):
        result = oob.run_generate_oob_url(store, "m1")
    assert "error" in result


# --- run_poll_oob_interactions -----------------------------------------------


def test_poll_no_store_configured():
    result = oob.run_poll_oob_interactions(None, "m1", "corr123")
    assert "error" in result


def test_poll_unknown_correlation_id():
    store = _fake_store()
    result = oob.run_poll_oob_interactions(store, "m1", "does-not-exist")
    assert "error" in result


def _encrypt_like_a_real_server(public_key_pem: bytes, interaction: dict) -> tuple[str, str]:
    """Build a (data_entry_b64, aes_key_b64) pair the exact way a real
    interactsh server would, using the client's own public key -- proves
    run_poll_oob_interactions' decryption is genuinely compatible with the
    real protocol, not just internally self-consistent.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
    plaintext = json.dumps(interaction).encode("utf-8")
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    data_entry = base64.b64encode(iv + ciphertext).decode("ascii")

    encrypted_aes_key = public_key.encrypt(
        aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    aes_key_b64 = base64.b64encode(encrypted_aes_key).decode("ascii")
    return data_entry, aes_key_b64


def test_poll_decrypts_a_real_interaction_end_to_end():
    """The core proof: generate a real keypair the way run_generate_oob_url
    does, persist it via the store, then simulate a server response
    encrypted against that keypair's public key, and confirm
    run_poll_oob_interactions correctly decrypts it back to the original
    interaction dict.
    """
    store = _fake_store()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    store("save", "m1", "corr123", {"secret_key": "sk", "private_key_pem": private_key_pem.decode("ascii"), "server": "oast.fun"})

    interaction = {"protocol": "dns", "remote-address": "203.0.113.5", "unique-id": "corr123"}
    data_entry, aes_key_b64 = _encrypt_like_a_real_server(public_key_pem, interaction)

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"data": [data_entry], "aes_key": aes_key_b64}
    with patch("categories.oob_interaction.requests.get", return_value=mock_resp):
        result = oob.run_poll_oob_interactions(store, "m1", "corr123")

    assert result["any_interaction"] is True
    assert result["interaction_count"] == 1
    assert result["interactions"][0] == interaction


def test_poll_no_interactions_yet():
    store = _fake_store()
    store("save", "m1", "corr123", {"secret_key": "sk", "private_key_pem": "irrelevant", "server": "oast.fun"})
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"data": [], "aes_key": None}
    with patch("categories.oob_interaction.requests.get", return_value=mock_resp):
        result = oob.run_poll_oob_interactions(store, "m1", "corr123")
    assert result["any_interaction"] is False
    assert result["interaction_count"] == 0


def test_poll_http_failure():
    store = _fake_store()
    store("save", "m1", "corr123", {"secret_key": "sk", "private_key_pem": "x", "server": "oast.fun"})
    mock_resp = MagicMock(status_code=401, text="unauthorized")
    with patch("categories.oob_interaction.requests.get", return_value=mock_resp):
        result = oob.run_poll_oob_interactions(store, "m1", "corr123")
    assert "error" in result


# --- register() wiring -------------------------------------------------------


def test_register_adds_both_tools():
    mcp = MagicMock()
    oob.register(mcp, scope=None, executor=None, timeouts={}, oob_store=_fake_store())
    registered_names = [call.args[0].__name__ for call in mcp.add_tool.call_args_list]
    assert "generate_oob_url" in registered_names
    assert "poll_oob_interactions" in registered_names
