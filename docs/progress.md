# Progress log

Running log, most recent first. Keep entries to 3-5 lines. Update at the end of
each work session with: what changed, what's in progress, next concrete step.

---

## 2026-08-11 — Phase 0 (HITL gate + model-agnostic adapter) + Phase 1.5 (ATT&CK/CWE) built
- Phase 0: new `models/` package (`base.py`'s `ModelAdapter`/`Turn`/`ToolCall`/
  `ToolResult`/`ModelResponse`, `anthropic_adapter.py`'s `AnthropicAdapter`,
  `__init__.py`'s `build_adapter(provider, model)`); `agent_core.run_tool_loop`
  rewritten to talk only to the adapter, never `anthropic.AsyncAnthropic()`
  directly. HITL gate wired in via `manifest.yaml`'s new `categories:` block
  (`require_approval` on `web_exploit`/`exploit_runtime`/`verify`/
  `network_exploit`), with three modes (`--hitl-mode`, default `auto`):
  `auto` never prompts, `manual` prompts every gated call
  (`agent_core.confirm_tool_call`, `[y/n/edit]`), `plan` prompts once per
  run/finding (`agent_core.confirm_plan_for_run`) and reuses that decision
  for the rest of the run -- added after initial build once live-testing
  surfaced that per-call manual prompts were too much friction for routine
  runs. All 4 agent loops + `main.py`/`run.py` (`--provider`, `--hitl-mode`
  flags) updated. 23 unit tests pass (HITL scenarios incl. all 3 modes,
  manifest resolution, Turn<->Anthropic-block translation with a mocked
  client) plus a real-MCP-server integration check with a fake adapter
  (dns_lookup ran ungated, no HITL prompt, transcript/extract_blocks
  intact). NOT yet live-tested interactively with a real model (needs a
  human at the `[y/n/edit]`/plan prompt to sanity-check the UX feel).
- Phase 1.5: skills tagged with CWE/ATT&CK frontmatter, `lookup_attack_technique`
  MCP tool + local slim ATT&CK dataset, exploit_agent fallback for `stub`
  skills. 9 unit tests pass. NOT yet live-tested against DVWA (prepared
  `findings_dvwa_test.json` with a reset stub-type + full-type finding,
  handed to user to run since it needs `ANTHROPIC_API_KEY`).
- Both roadmap copies (`docs/roadmap.md`, `Downloads/ronin-roadmap.md`)
  updated: Phase 1 marked shipped, Phase 1.5 added, Phase 0 expanded with
  the adapter layer.
- Both live checks DONE: user ran `run.py` against DVWA end-to-end
  (`findings_dvwa_live.json`, gitignored). Confirms Phase 0's adapter
  rewrite is functionally transparent (full recon->exploit->verify pipeline
  completed on real API calls) AND Phase 1.5's fallback works live -- every
  stub-type finding that reached a verdict (command_injection,
  path_traversal, csrf, file_upload, security_misconfig) called
  `lookup_attack_technique` before probing and was independently confirmed
  `verified` by verify_agent. `business_logic` correctly got
  `attack_technique: None`. The `incomplete` results match DVWA's documented
  session/login limitation, not a regression.
- Ready to commit: everything from 2026-08-11 (Phase 0 + Phase 1.5) is
  implemented, unit-tested, and now live-verified.

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
