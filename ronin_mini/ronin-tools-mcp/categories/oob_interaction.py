"""oob_interaction category: generate_oob_url + poll_oob_interactions --
out-of-band (OOB) interaction testing for blind vulnerabilities (SSRF, XXE,
command injection) where the target's HTTP response alone can't confirm
impact. Uses interactsh (github.com/projectdiscovery/interactsh), the free,
open-source OOB interaction service -- not Burp Collaborator, which requires
a paid Burp Suite Professional license and would make this capability
inaccessible to anyone using ronin-mini without one. See docs/roadmap.md's
Phase 4 for why.

No target interaction happens here at all -- these two tools only ever talk
to the interactsh server (a public server by default, e.g. oast.fun), never
the operator-specified target -- so scope.py's host-allowlist validation
doesn't apply, same reasoning as searchsploit's "local offline lookup, no
target host" exemption. What IS scope-relevant is the payload the model
crafts using the returned URL (e.g. embedding it in an SSRF/XXE payload sent
via execute_python/probe_variant) -- that request goes through the normal
scope-checked path like any other, this category is just the OOB
infrastructure underneath it.

Protocol (reverse-engineered from interactsh's own Go client/server source,
since no official Python client exists on PyPI -- see the module docstring
in tests/test_oob_interaction.py for the exact source references):
- generate_oob_url: generate an RSA-2048 keypair + a random correlation_id
  + secret_key, POST /register with {public-key, secret-key, correlation-id}
  (PEM-encoded pubkey, base64), return a payload URL
  (correlation_id + nonce + "." + server).
- poll_oob_interactions: GET /poll?id={correlation_id}&secret={secret_key},
  decrypt each returned entry (RSA-OAEP-decrypt an AES key, then AES-CTR-
  decrypt the interaction payload with that key + a 16-byte IV prefix).

Session keys (the RSA private key, secret_key) are persisted per-mission via
FindingsStore, not held in the MCP server subprocess's memory -- exploit_agent
and verify_agent each spawn their own fresh subprocess (see server.py's
build_server), so anything held only in-process wouldn't survive from one
agent's session to a later replay by another.
"""

from __future__ import annotations

import base64
import json
import secrets
import string
import uuid
from datetime import datetime, timezone

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_SERVERS = ["oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"]
CORRELATION_ID_LENGTH = 20
NONCE_LENGTH = 13
REQUEST_TIMEOUT_SECONDS = 15
_ALPHABET = string.ascii_lowercase + string.digits


def _random_id(length: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_generate_oob_url(oob_store, mission_id: str) -> dict:
    """Register a fresh interactsh session and return a unique payload URL
    to embed in a blind-vulnerability probe (e.g. an SSRF/XXE payload). Each
    call creates its own new session (own keypair, own correlation_id) --
    call it again for each distinct injection point you want to test/
    distinguish. Persists the session's keys via `oob_store` so a later
    poll_oob_interactions call (including one made during verify_agent's
    replay, in a separate process) can decrypt interactions on it.
    """
    if oob_store is None:
        return {"error": "OOB session storage is not configured on this server (no mission/mongo context)"}

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_pem_b64 = base64.b64encode(public_key_der).decode("ascii")
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    correlation_id = _random_id(CORRELATION_ID_LENGTH)
    secret_key = str(uuid.uuid4())
    server = secrets.choice(DEFAULT_SERVERS)

    try:
        resp = requests.post(
            f"https://{server}/register",
            json={"public-key": public_key_pem_b64, "secret-key": secret_key, "correlation-id": correlation_id},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as e:
        return {"error": f"could not reach interactsh server {server}: {e}"}

    if resp.status_code != 200:
        return {"error": f"registration failed: HTTP {resp.status_code}: {resp.text[:300]}"}

    oob_store(
        "save",
        mission_id,
        correlation_id,
        {
            "secret_key": secret_key,
            "private_key_pem": private_key_pem,
            "server": server,
            "created_at": _now_iso(),
        },
    )

    nonce = _random_id(NONCE_LENGTH)
    url = f"{correlation_id}{nonce}.{server}"

    return {
        "url": url,
        "correlation_id": correlation_id,
        "note": (
            "Embed this URL in the payload you're testing (e.g. an SSRF 'fetch this URL' "
            "parameter, an XXE external entity, a command-injection DNS lookup). Then call "
            "poll_oob_interactions with this same correlation_id to check whether the target "
            "actually reached out to it -- that's the only way to confirm a blind vulnerability, "
            "since the target's direct HTTP response won't show it."
        ),
    }


def _decrypt_interaction(entry_b64: str, aes_key: bytes) -> dict | str:
    raw = base64.b64decode(entry_b64)
    iv, ciphertext = raw[:16], raw[16:]
    decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        return json.loads(plaintext)
    except json.JSONDecodeError:
        return plaintext.decode("utf-8", errors="replace")


def run_poll_oob_interactions(oob_store, mission_id: str, correlation_id: str) -> dict:
    """Poll for any interactions (DNS/HTTP/SMTP) received on a URL generated
    by generate_oob_url. Interactions are retained server-side for a limited
    time (not deleted on read), so polling multiple times is safe, but a
    poll long after the original test may legitimately show nothing even if
    an interaction happened earlier -- that's a live-environment limitation
    of the OOB service, not evidence the vulnerability doesn't exist.
    """
    if oob_store is None:
        return {"error": "OOB session storage is not configured on this server (no mission/mongo context)"}

    session = oob_store("get", mission_id, correlation_id, None)
    if session is None:
        return {"error": f"no OOB session found for correlation_id {correlation_id!r}"}

    try:
        resp = requests.get(
            f"https://{session['server']}/poll",
            params={"id": correlation_id, "secret": session["secret_key"]},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as e:
        return {"error": f"could not reach interactsh server {session['server']}: {e}"}

    if resp.status_code != 200:
        return {"error": f"poll failed: HTTP {resp.status_code}: {resp.text[:300]}"}

    body = resp.json()
    data_entries = body.get("data") or body.get("Data") or []
    aes_key_b64 = body.get("aes_key") or body.get("AESKey")

    interactions: list[dict | str] = []
    if data_entries and aes_key_b64:
        private_key = serialization.load_pem_private_key(session["private_key_pem"].encode("ascii"), password=None)
        encrypted_aes_key = base64.b64decode(aes_key_b64)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        for entry in data_entries:
            interactions.append(_decrypt_interaction(entry, aes_key))

    return {
        "correlation_id": correlation_id,
        "any_interaction": len(interactions) > 0,
        "interaction_count": len(interactions),
        "interactions": interactions,
        "note": (
            "Each interaction shows the target (or something acting on its behalf) actually "
            "reaching out to the generated URL -- real confirmation of a blind vulnerability. "
            "any_interaction: false means nothing has arrived yet, not proof the vulnerability "
            "doesn't exist -- some payloads take time, or the target may not have processed it."
        ),
    }


def register(mcp, scope, executor, timeouts: dict, oob_store=None) -> None:
    """oob_store: an optional callable of the shape
    oob_store(action, mission_id, correlation_id, session_or_none) -> dict | None,
    where action is "save" (persist `session_or_none`, returns None) or "get"
    (return the persisted session dict or None). server.py wires this to
    FindingsStore.save_oob_session/get_oob_session; None (no mission/mongo
    context) makes both tools return an explicit error rather than silently
    doing nothing.
    """

    def generate_oob_url(mission_id: str) -> dict:
        """Generate a unique out-of-band interaction URL (via interactsh) for
        testing blind SSRF/XXE/command-injection where the target's direct
        HTTP response can't confirm impact. Embed the returned URL in your
        payload, then call poll_oob_interactions with the returned
        correlation_id to check whether the target actually reached out to
        it. Pass the current mission_id (same one findings/mission state is
        stored under).
        """
        return run_generate_oob_url(oob_store, mission_id)

    def poll_oob_interactions(mission_id: str, correlation_id: str) -> dict:
        """Check whether any DNS/HTTP/SMTP interaction has arrived on a URL
        previously generated by generate_oob_url. This is the only way to
        confirm a blind vulnerability actually fired -- the target's own
        HTTP response won't show it.
        """
        return run_poll_oob_interactions(oob_store, mission_id, correlation_id)

    mcp.add_tool(generate_oob_url)
    mcp.add_tool(poll_oob_interactions)
