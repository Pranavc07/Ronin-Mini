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
sys.path.insert(0, os.path.join(_REPO_ROOT, "ronin-tools-mcp"))

import agent_core  # noqa: E402
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


def test_load_skill_stub_status_parses_frontmatter():
    doc = agent_core.load_skill("ssrf")
    assert doc is not None
    assert doc.metadata["status"] == "stub"
    assert doc.metadata["cwe"] == "CWE-918"
    assert "lookup_attack_technique" in doc.body


def test_load_skill_missing_type_returns_none():
    assert agent_core.load_skill("not_a_real_finding_type") is None


def test_load_skill_all_have_status():
    skills_dir = os.path.join(_REPO_ROOT, "skills")
    finding_types = [f[:-3] for f in os.listdir(skills_dir) if f.endswith(".md")]
    assert len(finding_types) == 16  # 14 web-vuln classes + known_vulnerable_service + weak_credentials
    for finding_type in finding_types:
        doc = agent_core.load_skill(finding_type)
        assert doc is not None, finding_type
        assert doc.metadata.get("status") in ("full", "stub"), finding_type
