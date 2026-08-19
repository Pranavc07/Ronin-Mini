"""Unit tests for the attack_reference category (lookup_attack_technique) and
agent_core.load_skill()'s YAML frontmatter parsing.

No network, no Docker, no Anthropic API key needed -- the ATT&CK dataset is
a bundled static file (ronin-tools-mcp/data/attack_enterprise_slim.json).

Run with: pytest tests/test_attack_reference.py -v
"""

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin_mini", "ronin-tools-mcp"))

from ronin_mini import agent_core  # noqa: E402
from categories.attack_reference import run_lookup_attack_technique  # noqa: E402


def test_lookup_by_exact_technique_id():
    result = run_lookup_attack_technique("T1190")
    assert result["match_type"] == "exact_id"
    assert result["results"][0]["technique_id"] == "T1190"
    assert result["results"][0]["name"] == "Exploit Public-Facing Application"


def test_lookup_by_exact_technique_id_is_case_insensitive():
    result = run_lookup_attack_technique("t1190")
    assert result["match_type"] == "exact_id"
    assert result["results"][0]["technique_id"] == "T1190"


def test_lookup_by_keyword():
    result = run_lookup_attack_technique("exploit public")
    assert result["match_type"] == "keyword"
    assert any(r["technique_id"] == "T1190" for r in result["results"])


def test_lookup_no_match():
    result = run_lookup_attack_technique("definitely-not-a-real-technique-xyz")
    assert result["match_type"] == "none"
    assert result["results"] == []


def test_lookup_empty_query():
    result = run_lookup_attack_technique("   ")
    assert "error" in result


def test_load_skill_full_status_parses_frontmatter():
    doc = agent_core.load_skill("sqli")
    assert doc is not None
    assert doc.metadata["status"] == "full"
    assert doc.metadata["cwe"] == "CWE-89"
    assert doc.metadata["attack_technique"] == "T1190"
    assert "# SQL Injection" in doc.body
    assert "---" not in doc.body.split("\n")[0]  # frontmatter delimiter stripped


def test_load_skill_stub_status_parses_frontmatter(tmp_path, monkeypatch):
    """All 16 real skills/*.md files are status: full now (no stubs remain
    -- see docs/progress.md), so this test builds a synthetic stub-shaped
    file rather than depending on any specific real skill staying a stub.
    Still exercises the real code path: exploit_agent/loop.py's
    build_system_prompt nudges toward lookup_attack_technique whenever a
    matched skill's status is "stub", so that parsing must keep working
    even though no shipped skill exercises it today.
    """
    stub_file = tmp_path / "synthetic_stub_type.md"
    stub_file.write_text(
        "---\n"
        "status: stub\n"
        "cwe: CWE-000\n"
        "attack_technique: T1190\n"
        "attack_tactic: Initial Access\n"
        "---\n\n"
        "# Synthetic Stub\n\n"
        "No hand-authored methodology yet for this class. Call "
        "`lookup_attack_technique` for a relevant ATT&CK technique "
        "reference.\n"
    )
    monkeypatch.setattr(agent_core, "SKILLS_DIR", str(tmp_path))

    doc = agent_core.load_skill("synthetic_stub_type")

    assert doc is not None
    assert doc.metadata["status"] == "stub"
    assert doc.metadata["cwe"] == "CWE-000"
    assert "lookup_attack_technique" in doc.body


def test_load_skill_ssrf_is_now_full_with_real_methodology():
    """ssrf was a stub as recently as this test suite's last version --
    confirms it (and, by the same pattern, every other former stub) now
    carries real, non-generic methodology rather than the old fallback text.
    """
    doc = agent_core.load_skill("ssrf")
    assert doc is not None
    assert doc.metadata["status"] == "full"
    assert doc.metadata["cwe"] == "CWE-918"
    assert "## What to check, in order" in doc.body
    assert "## Response signatures" in doc.body
    assert "No hand-authored methodology yet" not in doc.body


def test_load_skill_missing_type_returns_none():
    assert agent_core.load_skill("not_a_real_finding_type") is None


def test_load_skill_all_have_status():
    skills_dir = os.path.join(_REPO_ROOT, "ronin_mini", "skills")
    finding_types = [f[:-3] for f in os.listdir(skills_dir) if f.endswith(".md")]
    assert len(finding_types) == 16  # 14 web-vuln classes + known_vulnerable_service + weak_credentials
    for finding_type in finding_types:
        doc = agent_core.load_skill(finding_type)
        assert doc is not None, finding_type
        assert doc.metadata.get("status") in ("full", "stub"), finding_type


def test_all_shipped_skills_are_full_with_real_methodology():
    """Regression guard: every skills/*.md file that ships in the repo is
    status: full with real methodology, not the old generic stub fallback.
    business_logic is the one deliberate exception on cwe/attack_technique/
    attack_tactic (kept null -- app-specific by nature, no single CWE/ATT&CK
    technique fits), but it must still be status: full with real content.
    """
    skills_dir = os.path.join(_REPO_ROOT, "ronin_mini", "skills")
    finding_types = [f[:-3] for f in os.listdir(skills_dir) if f.endswith(".md")]
    for finding_type in finding_types:
        doc = agent_core.load_skill(finding_type)
        assert doc.metadata.get("status") == "full", finding_type
        assert "No hand-authored methodology yet" not in doc.body, finding_type
        if finding_type != "business_logic":
            assert doc.metadata.get("cwe") is not None, finding_type
