"""findings_store.py -- MongoDB-backed persistence for mission findings,
replacing findings.json (Phase 3, see docs/roadmap.md).

Same claim-state-machine shape as before: a mission's findings are a plain
list of dicts, loaded, mutated in place by recon/exploit/verify's loop.py,
and rewritten wholesale on every save -- exactly what the old file-based
_write_findings/_save_findings did with json.dump. Only the persistence
mechanism changed here, not the schema or the state machine. Findings live
embedded in the mission document (one document per mission, in the
`missions` collection) rather than as separate per-finding documents --
nothing in the pipeline ever needed more granularity than "load the whole
list, mutate it, save the whole list back."

Used from two places: the host process (recon_agent/exploit_agent/
verify_agent's loop.py, run.py) and the MCP server subprocess
(ronin-tools-mcp/server.py, for replay_probe's read-only lookup) -- each
opens its own MongoClient, since they're separate processes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pymongo import MongoClient

DEFAULT_MONGO_URI = "mongodb://localhost:27017"
DEFAULT_DB_NAME = "ronin"
MISSIONS_COLLECTION = "missions"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MissionNotFound(ValueError):
    pass


class FindingsStore:
    def __init__(self, mongo_uri: str = DEFAULT_MONGO_URI, db_name: str = DEFAULT_DB_NAME):
        self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        self.db = self.client[db_name]
        self.missions = self.db[MISSIONS_COLLECTION]

    def create_mission(self, target: str, objective: str, budget_usd: float | None = None) -> str:
        mission_id = uuid.uuid4().hex[:12]
        self.missions.insert_one(
            {
                "_id": mission_id,
                "target": target,
                "objective": objective,
                "created_at": _now_iso(),
                "budget_usd": budget_usd,
                "findings": [],
                # stage name ("recon"/"exploit"/"verify") -> that stage's summed Usage dict.
                "stage_usage": {},
                # correlation_id -> {secret_key, private_key_pem, server, created_at} for
                # Phase 4's OOB (interactsh) sessions -- see categories/oob_interaction.py.
                # Embedded here, not a separate collection, same "one document per mission"
                # discipline as everything else in this store. Persisted (not kept in the
                # MCP server subprocess's memory) specifically so verify_agent's later
                # replay_probe call -- a completely separate subprocess spawned long after
                # exploit_agent's -- can still poll the same session.
                "oob_sessions": {},
            }
        )
        return mission_id

    def load_findings(self, mission_id: str) -> list[dict]:
        doc = self.missions.find_one({"_id": mission_id}, {"findings": 1})
        if doc is None:
            raise MissionNotFound(f"no mission with id {mission_id!r}")
        return doc.get("findings", [])

    def save_findings(self, mission_id: str, findings: list[dict]) -> None:
        result = self.missions.update_one({"_id": mission_id}, {"$set": {"findings": findings}})
        if result.matched_count == 0:
            raise MissionNotFound(f"no mission with id {mission_id!r}")

    def claim_next_finding(self, mission_id: str, from_status: str, to_status: str) -> dict | None:
        """Atomically claim one finding with status == from_status, setting it to
        to_status. Unlike save_findings' whole-array $set (last-writer-wins under
        concurrent callers), this is race-safe: MongoDB's update_one is atomic
        per-document, so a status-guarded $elemMatch update either wins the claim
        (modified_count == 1) or loses it to a concurrent caller (modified_count
        == 0) with no lost updates either way.

        Snapshots candidate ids once, then tries each in order until one claim
        succeeds or none remain. No retry-with-fresh-snapshot loop -- the
        findings list is fixed by the time exploit/verify starts (recon has
        already finished), so no new candidates can appear mid-stage.
        """
        doc = self.missions.find_one({"_id": mission_id}, {"findings.id": 1, "findings.status": 1})
        if doc is None:
            raise MissionNotFound(f"no mission with id {mission_id!r}")

        candidate_ids = [f["id"] for f in doc.get("findings", []) if f.get("status") == from_status]
        for finding_id in candidate_ids:
            result = self.missions.update_one(
                {"_id": mission_id, "findings": {"$elemMatch": {"id": finding_id, "status": from_status}}},
                {"$set": {"findings.$.status": to_status}},
            )
            if result.modified_count == 1:
                # Positional ($) projection isn't supported by mongomock (used in
                # tests), so fetch the whole document and filter in Python instead
                # of {"findings.$": 1} -- works identically against real MongoDB.
                claimed_doc = self.missions.find_one({"_id": mission_id}, {"findings": 1})
                return next(f for f in claimed_doc["findings"] if f["id"] == finding_id)
        return None

    def complete_finding(
        self, mission_id: str, finding_id: str, attempts_field: str, attempt: dict, new_status: str
    ) -> None:
        """Atomically append attempt onto findings.$.{attempts_field} and set
        findings.$.status -- the completion half of the claim_next_finding
        compare-and-swap pattern, matched by finding_id (not by from_status,
        since the caller already knows it holds this finding's claim)."""
        result = self.missions.update_one(
            {"_id": mission_id, "findings": {"$elemMatch": {"id": finding_id}}},
            {"$push": {f"findings.$.{attempts_field}": attempt}, "$set": {"findings.$.status": new_status}},
        )
        if result.matched_count == 0:
            raise MissionNotFound(f"no mission with id {mission_id!r} (or no finding with id {finding_id!r})")

    def record_stage_usage(self, mission_id: str, stage: str, usage: dict) -> None:
        result = self.missions.update_one({"_id": mission_id}, {"$set": {f"stage_usage.{stage}": usage}})
        if result.matched_count == 0:
            raise MissionNotFound(f"no mission with id {mission_id!r}")

    def get_mission(self, mission_id: str) -> dict | None:
        return self.missions.find_one({"_id": mission_id})

    def get_budget_usd(self, mission_id: str) -> float | None:
        doc = self.missions.find_one({"_id": mission_id}, {"budget_usd": 1})
        if doc is None:
            raise MissionNotFound(f"no mission with id {mission_id!r}")
        return doc.get("budget_usd")

    def save_oob_session(self, mission_id: str, correlation_id: str, session: dict) -> None:
        """Persist a Phase 4 OOB (interactsh) session's keys, keyed by its
        correlation_id, so it can be polled again later -- including by
        verify_agent's replay_probe, which runs in a separate subprocess
        spawned long after the one that created the session.
        """
        result = self.missions.update_one(
            {"_id": mission_id}, {"$set": {f"oob_sessions.{correlation_id}": session}}
        )
        if result.matched_count == 0:
            raise MissionNotFound(f"no mission with id {mission_id!r}")

    def get_oob_session(self, mission_id: str, correlation_id: str) -> dict | None:
        doc = self.missions.find_one({"_id": mission_id}, {f"oob_sessions.{correlation_id}": 1})
        if doc is None:
            raise MissionNotFound(f"no mission with id {mission_id!r}")
        return doc.get("oob_sessions", {}).get(correlation_id)

    def close(self) -> None:
        self.client.close()
