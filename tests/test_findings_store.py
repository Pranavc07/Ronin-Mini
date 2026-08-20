"""Unit tests for findings_store.FindingsStore (Phase 3: MongoDB-backed
mission storage, replacing findings.json). Uses mongomock so these run
without a real MongoDB instance -- FindingsStore itself just wraps
pymongo.MongoClient, which mongomock.MongoClient is a drop-in stand-in for.

Run with: pytest tests/test_findings_store.py -v
"""

import os
import sys

import pytest

mongomock = pytest.importorskip("mongomock")

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)

from ronin_mini.findings_store import FindingsStore, MissionNotFound  # noqa: E402


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setattr("ronin_mini.findings_store.MongoClient", mongomock.MongoClient)
    return FindingsStore(mongo_uri="mongodb://localhost:27017", db_name="ronin_test")


def test_create_mission_returns_id_and_stores_metadata(store):
    mission_id = store.create_mission("http://localhost:3000", "find sqli", budget_usd=5.0)

    mission = store.get_mission(mission_id)
    assert mission["target"] == "http://localhost:3000"
    assert mission["objective"] == "find sqli"
    assert mission["budget_usd"] == 5.0
    assert mission["findings"] == []
    assert mission["stage_usage"] == {}


def test_save_and_load_findings_round_trips(store):
    mission_id = store.create_mission("http://localhost:3000", "find sqli")
    findings = [{"id": "f1", "type": "sqli", "status": "new"}]

    store.save_findings(mission_id, findings)

    assert store.load_findings(mission_id) == findings


def test_save_findings_overwrites_wholesale_like_the_old_file_write(store):
    """Matches the old file-based _save_findings behavior: every save
    replaces the entire findings list, not a partial merge -- callers are
    expected to load, mutate the whole in-memory list, then save it back.
    """
    mission_id = store.create_mission("t", "o")
    store.save_findings(mission_id, [{"id": "f1", "status": "new"}])
    store.save_findings(mission_id, [{"id": "f1", "status": "claimed"}, {"id": "f2", "status": "new"}])

    findings = store.load_findings(mission_id)
    assert len(findings) == 2
    assert findings[0]["status"] == "claimed"


def test_load_findings_unknown_mission_raises(store):
    with pytest.raises(MissionNotFound):
        store.load_findings("does-not-exist")


def test_save_findings_unknown_mission_raises(store):
    with pytest.raises(MissionNotFound):
        store.save_findings("does-not-exist", [])


def test_record_stage_usage_stores_per_stage(store):
    mission_id = store.create_mission("t", "o")
    usage = {"input_tokens": 100, "output_tokens": 50, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}

    store.record_stage_usage(mission_id, "recon", usage)

    mission = store.get_mission(mission_id)
    assert mission["stage_usage"]["recon"] == usage


def test_get_budget_usd_returns_none_when_not_set(store):
    mission_id = store.create_mission("t", "o")
    assert store.get_budget_usd(mission_id) is None


def test_get_budget_usd_unknown_mission_raises(store):
    with pytest.raises(MissionNotFound):
        store.get_budget_usd("does-not-exist")


def test_get_mission_returns_none_for_unknown_id(store):
    assert store.get_mission("does-not-exist") is None


def test_create_mission_includes_empty_oob_sessions(store):
    mission_id = store.create_mission("t", "o")
    assert store.get_mission(mission_id)["oob_sessions"] == {}


def test_save_and_get_oob_session_round_trips(store):
    mission_id = store.create_mission("t", "o")
    session = {"secret_key": "sk", "private_key_pem": "pem", "server": "oast.fun", "created_at": "now"}

    store.save_oob_session(mission_id, "corr123", session)

    assert store.get_oob_session(mission_id, "corr123") == session


def test_get_oob_session_unknown_correlation_id_returns_none(store):
    mission_id = store.create_mission("t", "o")
    assert store.get_oob_session(mission_id, "does-not-exist") is None


def test_save_oob_session_unknown_mission_raises(store):
    with pytest.raises(MissionNotFound):
        store.save_oob_session("does-not-exist", "corr123", {})


def test_get_oob_session_unknown_mission_raises(store):
    with pytest.raises(MissionNotFound):
        store.get_oob_session("does-not-exist", "corr123")


def test_multiple_oob_sessions_coexist_on_one_mission(store):
    mission_id = store.create_mission("t", "o")
    store.save_oob_session(mission_id, "corr1", {"server": "oast.fun"})
    store.save_oob_session(mission_id, "corr2", {"server": "oast.pro"})

    assert store.get_oob_session(mission_id, "corr1")["server"] == "oast.fun"
    assert store.get_oob_session(mission_id, "corr2")["server"] == "oast.pro"
