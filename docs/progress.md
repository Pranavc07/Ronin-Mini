# Progress log

Running log, most recent first. Keep entries to 3-5 lines. Update at the end of
each work session with: what changed, what's in progress, next concrete step.

---

## 2026-08-10 — Part 2 live-tested end-to-end: verify stage confirmed
- Ran `run.py` against Juice Shop (recon -> exploit -> verify, full pipeline,
  fresh findings.json). All 6 findings (2 sqli, 3 security_misconfig, 1
  path_traversal) went `new -> exploited -> verified`; `replay_probe` reproduced
  matching original-vs-replay output for every winning attempt.
- Confirms the isolation design works in practice, not just offline: verify_agent
  only ever called `replay_probe`, never invented new probes.
- Ready to commit everything from 2026-08-10 (Part 1 + Part 2 + this live test).
- NEXT: no committed next step. Candidate directions if resumed — DVWA session/
  cookie-jar support (the known limitation from 2026-08-09), the execute_python
  egress-allowlist network (Option B, deferred at 2026-08-09), or writing the
  remaining 10 skill stubs beyond sqli/idor/xss/auth_bypass.

## 2026-08-10 — Skills + externalized prompts (Part 1), verify agent (Part 2), incomplete status (C)
- Part 1 DONE & live-tested on DVWA: role prompts moved to `agents/*.md`, per-vuln
  methodology in `skills/*.md` (4 full: sqli/idor/xss/auth_bypass; 10 stubs),
  recon now types findings from a fixed 14-word vocabulary, exploit loads the
  matching skill (records `skill_loaded`). All verified in that run.
- Part 2 + C BUILT & verified offline, NOT yet live-tested: verify_agent (3rd loop,
  tool = only `replay_probe`, isolation confirmed at schema level); `replay_probe`
  literally re-runs a finding's winning attempt; run.py is now recon→exploit→verify.
  C: exploit_agent emits `incomplete` (not `dead-end`) when it never reaches a verdict.
- Surfaced: DVWA session/cookie limitation — exploit re-logs-in per finding and
  mostly `incomplete`s out fighting DVWA's CSRF login (Juice Shop unaffected). Deferred.
- NEXT: live-test Part 2 via `run.py` against Juice Shop (Docker up), confirm the
  `[verify]` stage produces verified/false_positive with real replay transcripts.
  Then commit (all changes uncommitted on `main`). Everything from 2026-08-09 IS committed.

## 2026-08-09 — MCP server + two-agent split + sandboxed execute_python
- Refactored the 4 in-process tools into a standalone MCP server
  (`ronin-tools-mcp/`) with category-based organization and centralized
  `scope.py` enforcement; added the two-agent recon→exploit flow (`run.py`,
  `recon_agent/`, `exploit_agent/`, shared `agent_core.py`) and a
  Docker-sandboxed `execute_python`.
- Validated end-to-end: Juice Shop (recon→exploit, all findings confirmed) and
  DVWA (11/11 exploited incl. blind SQLi, command injection, LFI). Merged to
  `main` and pushed; LinkedIn post drafted.
- Next: no committed next step. Candidate directions if resumed — a verification
  agent, cookie-jar/session support in the tools (DVWA needed manual cookie
  threading), or the execute_python egress-allowlist network (Option B).
