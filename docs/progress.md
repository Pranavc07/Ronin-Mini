# Progress log

Running log, most recent first. Keep entries to 3-5 lines. Update at the end of
each work session with: what changed, what's in progress, next concrete step.

---

## 2026-08-19 — Packaged the core as a real pip library; stood up ronin-pro (Track B split)
- User decision: split into two repos. `ronin-mini` (this repo) stays the
  public BSL core; a new, proprietary `ronin-pro` repo holds the
  agentic-AI-security + SOC 2 compliance-mapping direction ("Track B"),
  depending on `ronin-mini` as a real pip package rather than a fork --
  chosen specifically so core bugfixes never need manual porting between
  repos.
- Planned in `/plan` mode first; the initial draft (flat `py-modules` +
  `package_data` for `agents/`/`skills/`/`ronin-tools-mcp/` as bare
  sibling dirs) was reviewed and rejected before implementation -- two real
  risks: `package_data` doesn't reliably pull in directories that aren't
  nested inside a declared package (silent missing-files risk), and
  top-level `py-modules` named `run`/`main`/`loop` are a real global-import
  collision risk once installed alongside other packages. Revised to a
  proper namespaced `ronin_mini/` package before writing any code.
- Moved `agent_core.py`, `models/`, `recon_agent/`, `exploit_agent/`,
  `verify_agent/`, `findings_store.py`, `loop.py`, `agents/`, `skills/`,
  and `ronin-tools-mcp/` into `ronin_mini/`; fixed every import site --
  relative imports inside the package, updated bare imports across all
  ~18 affected test files. Root `run.py`/`main.py` are now 3-line shims
  delegating into `ronin_mini.run`/`ronin_mini.main`, so the documented
  `python run.py`/`python main.py` workflow keeps working unchanged for a
  direct clone.
- Verified rigorously, not just "pip install . worked": built a real wheel
  (`python -m build`), installed it into a clean venv in an unrelated temp
  directory, and ran a smoke script from there with zero proximity to the
  source tree -- confirmed `from ronin_mini import agent_core` works and
  the MCP server spawns from its packaged `site-packages` location,
  completing a real `initialize()`/`list_tools()` handshake returning all
  16 tools. Full test suite: 214 passed, same 2 pre-existing unrelated
  failures (stale tool-list assertion, Docker not running in-session).
- Tagged `v0.5.0`, committed (`3a19ce6`), pushed. `ronin-pro` created
  private (`gh repo create Pranavc07/ronin-pro --private`), scaffolded
  (`pyproject.toml` pinning `ronin-mini` at the actual commit SHA
  `3a19ce6a661196b5a12363a26775326293df803d`, not just the mutable tag;
  proprietary `LICENSE`; empty `src/ronin_pro/`), and its dependency on
  this repo proven with a committed regression test there
  (`tests/test_ronin_mini_dependency.py`) -- a real MCP-server spawn from
  `ronin-pro`'s own venv, resolving `ronin-mini`'s `server.py` from its
  installed location.
- `docs/roadmap.md` updated with a pointer to `ronin-pro`'s own
  `docs/roadmap.md` for the Track B phase plan (B0-B6) -- nothing from
  Track B lands in this repo.
- NEXT: known, deliberately deferred gap -- `CLAUDE.md` and `README.md`
  still describe file paths without the new `ronin_mini/` prefix (e.g.
  "agent_core.py" instead of "ronin_mini/agent_core.py"). Cosmetically
  stale, nothing functionally wrong; worth a doc sweep next session. The
  two still-open Track A items from the original Track B plan's Phase B0
  (the case-study doc for the redirect-scope/prompt-injection fixes, and
  the pending Metasploitable live-pipeline check) remain open, tracked in
  this file's earlier entries.

## 2026-08-19 — Live-tested Phase 3 against DVWA; fixed a Unicode crash and a real pricing bug
- Follow-up to Phase 3's build (below): live-tested it against real DVWA
  with two OpenRouter models (Qwen3.6 Plus, GLM 5.2), at the user's request
  to compare them. Confirms the Mongo-backed pipeline works end-to-end on
  real runs, not just mongomock unit tests -- mission creation, `--mission-id`
  resume after a mid-run crash, per-stage `stage_usage` recording, and
  `replay_probe`'s Mongo-backed lookup from the separate MCP-server
  subprocess all worked correctly across multiple real runs.
- **Real bug #1**: `agent_core._live_print` crashed the whole run with
  `UnicodeEncodeError` the first time a model's reasoning text contained a
  character outside Windows console's `cp1252` codepage (e.g. `→`) --
  killed the Qwen run mid-exploit-stage. Fixed with an encode-with-replace
  fallback so the terminal degrades gracefully instead of crashing; the
  JSONL log still gets the original untruncated text either way. One
  regression test (`tests/test_live_logging.py`) reproduces the exact
  failure via a fake cp1252-emulating stdout.
- **Real bug #2**, caught while sanity-checking a suspiciously-perfect
  $0.0000 total cost on the GLM run: `models/pricing.py` had no entry for
  the paid `z-ai/glm-5.2` id, so `_rates_for`'s old bidirectional substring
  fallback matched it against the unrelated `"z-ai/glm-5.2:free"` entry
  (`"z-ai/glm-5.2" in "z-ai/glm-5.2:free"` is `True`) and silently priced a
  run with over a million real tokens at the free tier's $0 rate. Separately,
  `qwen/qwen3.6-plus` wasn't in the table at all, so every Qwen run fell
  through to the Sonnet-tier `_DEFAULT_RATES` -- roughly a 9x overestimate.
  Fixed by adding real rates for both models (looked up live via
  openrouter.ai's model pages, not guessed) and tightening `_rates_for`'s
  substring match to require a `/`/`:`/end-of-string boundary rather than a
  bare substring check -- the exact class of bug that let the GLM case slip
  through. 3 new regression tests in `tests/test_usage_tracking.py`,
  including one that directly encodes the fixed boundary-check behavior.
- With corrected pricing, real costs for the two DVWA comparison runs:
  Qwen3.6 Plus ~$0.34 total (1 finding reached `verified`, but that run was
  confounded by an initial too-tight recon budget, the Unicode crash, and
  Docker degrading mid-run -- not a clean read on the model itself), GLM 5.2
  ~$0.88 total on a clean run (7/12 findings reached `verified`). GLM's cost
  per verified finding (~$0.125) came out cheaper than Qwen's (~$0.34)
  despite higher raw token usage, because it converted far more of its
  exploration into confirmed results -- it recovered from an identical
  initial tool-usage mistake (calling `ronin_target.request` like a
  `requests.Session`) in 1-2 calls via introspecting the function signature,
  where Qwen repeatedly retried variations and burned its per-finding
  budget more often.
- **Also found and fixed, unrelated to any of the above**: mid-session,
  Docker Desktop on Windows crashed on startup with `initializing Inference
  manager: ... remove ...\dockerInference: The file cannot be accessed by
  the system` -- a stale AF_UNIX socket reparse point left in a state only a
  full OS reboot could release (confirmed via Docker Desktop's own
  `monitor.log`; `Remove-Item`/`fsutil` both failed with the same underlying
  Windows error even elevated). Diagnosed from Docker Desktop's log files
  rather than guessing, since "docker hangs forever" has many unrelated
  causes; a machine reboot resolved it cleanly with no data loss (Mongo/DVWA
  containers just needed restarting after).
- Full suite: 221/222 pass (only the pre-existing, unrelated
  `test_mcp_server_full_flow` failure remains; `test_execute_python.py`
  passed this time since Docker was actually up).
- NEXT: no committed next step for Phase 3 itself -- it's live-verified.
  Fair Qwen-vs-GLM rerun under clean, uninterrupted conditions would be the
  real next step if a conclusive model-capability comparison (not just
  today's infra-confounded one) is wanted.

## 2026-08-19 — Phase 3: MongoDB mission storage, replaces findings.json
- User asked to move to the next roadmap phase. Flagged one real tension
  before starting: `CLAUDE.md`'s "Deliberate non-goals" section said "no
  Postgres/database... state is files", which reads as a standing
  constraint against exactly what Phase 3 (MongoDB) proposes -- confirmed
  with the user this was the planned exception (roadmap.md always specified
  it), not a conflict to resolve first.
- New `findings_store.py`: `FindingsStore` wraps `pymongo.MongoClient`, one
  document per mission in `ronin.missions` (`target`, `objective`,
  `budget_usd`, `findings`, `stage_usage`). `save_findings` rewrites the
  whole embedded list on every call (`$set`) -- deliberately mirrors the old
  file-based `_save_findings`'s "load, mutate, rewrite" pattern exactly, so
  the claim-state-machine logic in `recon_agent`/`exploit_agent`/
  `verify_agent`'s `loop.py` needed zero changes beyond swapping the I/O
  calls (`store.load_findings`/`store.save_findings` for `json.load`/
  `json.dump` on a path). No per-finding documents, no migration tooling --
  nothing in the pipeline ever needed more granularity than that.
- Added the mission-level budget tracking the roadmap also asked for:
  `stage_usage.<stage>` on the mission doc via `store.record_stage_usage`;
  `run.py --budget-usd` checks cumulative estimated cost (same
  `models.estimate_cost_usd` the existing per-stage print lines already use)
  between stages and stops before starting one that would exceed the cap.
  `run.py` now creates a mission at startup and prints its id;
  `--mission-id` resumes an existing mission (skips recon if it already has
  findings) -- a real resume path `findings.json` never had, since starting
  over meant literally starting over.
- The one non-trivial wrinkle: `categories/verify.py`'s `replay_probe`
  (which looks up a finding's winning attempt to replay) runs inside
  `ronin-tools-mcp/server.py`'s spawned subprocess -- a separate process
  with no access to the host's `FindingsStore` instance. Decoupled
  `run_replay_probe`/`register()` from storage entirely instead of teaching
  them about Mongo: they now take an already-loaded findings list / a
  zero-arg `findings_loader` callable, called fresh on every invocation.
  `server.py`'s `build_server` is the only place that constructs a real
  `FindingsStore`, from new `--mongo-uri`/`--mission-id` CLI args
  (deferred-imported so recon/exploit's server spawns, which pass neither,
  never need `pymongo` importable at all). `agent_core.mcp_server_params`
  takes `mongo_uri`/`mission_id` in place of the old `findings_path`.
- `docker-compose.yml` added (`docker-compose up -d mongo`) for a one-line
  local instance; README/CLAUDE.md updated throughout (setup steps, CLI
  flag tables, the "what this is not" section's non-goals framing, the
  Phase 3 section in CLAUDE.md written in the same voice/detail as every
  other architecture section, not just a changelog blurb).
- Test blast radius was smaller than the refactor looked: only
  `test_verify.py`/`test_replay_coverage.py` called `run_replay_probe`
  directly with a path (updated to pass an in-memory findings list instead,
  matching the new signature) -- no test called `run_recon_agent`/
  `run_exploit_agent`/`run_verify_agent` directly, so the `store`/
  `mission_id` parameter rename didn't ripple further. New
  `tests/test_findings_store.py` (9 tests, `pytest.importorskip("mongomock")`
  so it runs without a real MongoDB -- `mongomock.MongoClient` monkeypatched
  in for `pymongo.MongoClient`): mission creation, findings round-trip,
  wholesale-overwrite-not-merge semantics, unknown-mission errors on every
  method, stage usage recording, budget defaults. `pymongo`/`mongomock`
  installed; `pymongo` added to `requirements.txt` (`mongomock` left out --
  it's test-only and this repo has no separate dev-requirements file, same
  as `pytest` itself). Full suite: 209/211 pass (the same 2 pre-existing,
  unrelated failures as every prior session -- `test_execute_python.py`'s
  Docker-down guard gap, `test_mcp_server_full_flow`'s stale expected-tool
  list -- neither touched by this change; Docker wasn't running this
  session so those couldn't be re-checked either way).
- NEXT: not live-tested against a real MongoDB instance or a real target --
  Docker/Mongo were both down this session. First real check should be a
  live `run.py` run against an already-validated target (Juice Shop/DVWA/
  Metasploitable) confirming the full pipeline behaves identically to the
  `findings.json`-backed runs it replaces, plus exercising `--mission-id`
  resume and `--budget-usd` for real (both only unit-tested via mongomock
  so far, never against actual multi-stage token spend).

## 2026-08-19 — Hardened two security gaps from a review: redirect scope bypass + prompt injection
- User-driven security hardening pass, scoped explicitly to two items from a
  broader review (persistence/CI/adversarial-suite/benchmarking tracked
  separately, out of scope here).
- **Redirect scope bypass**: `executor.run_http` let `requests` follow
  redirects automatically -- the destination was never re-validated, so an
  in-scope URL could redirect Ronin to an out-of-scope host. Fixed by
  driving redirects manually (`allow_redirects=False` per real request),
  calling `scope.validate_host` on every hop including the first,
  `MAX_REDIRECTS = 5`, rejecting non-http(s) schemes, and recording every
  hop (validated or rejected) in a `redirect_chain` field. Single
  chokepoint -- `http_request`, `probe_variant`, and `replay_probe`
  (via `run_probe_variant`) all funnel through this one function, fixed
  once. Found and fixed a SECOND, independent copy of the identical bug in
  `categories/exploit_runtime.py`'s `_HELPER_TEMPLATE` (the `ronin_target.py`
  helper generated into every `execute_python` sandbox container, which
  can't import the real `scope.py` since it runs in an isolated container)
  -- extended with the same algorithm, returns a real `requests.Response`
  with `.history` populated rather than breaking its documented interface.
- **Prompt injection**: target-controlled content (tool output, and
  `finding_evidence`/`claimed_evidence` interpolated directly into
  exploit_agent's/verify_agent's system prompts) had no framing
  distinguishing it from trusted instructions. Fixed with
  `agent_core.new_injection_token()` (a fresh, unpredictable
  `secrets.token_hex(16)` per agent conversation) and
  `agent_core.wrap_untrusted_data()`, applied at `run_tool_loop`'s
  tool-result construction (one chokepoint, covers all three agents and
  every tool automatically) and at the two evidence-interpolation points
  found while reading the actual prompts (not originally flagged, but the
  same category of risk, arguably higher since it lands in the system
  prompt itself). User specifically required a **random per-run token, not
  a fixed delimiter** -- a static boundary string is guessable, letting an
  adversarial response spoof a fake closing tag followed by fake
  instructions; a token the target can't predict closes that specific
  trick. All three role prompts + the legacy single-agent template carry a
  matching paragraph announcing the real token so the model has a genuine
  reference value.
- Two things checked and found NOT to be live bugs, reported honestly
  rather than silently "fixed": (1) whether `finding_evidence`/
  `claimed_evidence` containing literal `{`/`}` could break `.format()` --
  empirically verified it can't (`str.format()` does single-pass
  substitution, doesn't re-scan substituted values for placeholders); (2)
  whether `MAX_REDIRECTS = 5` could reintroduce the documented DVWA
  session/login budget-burning issue -- reasoned through DVWA's actual
  login mechanic (one 302 on successful POST) as very likely fine, but
  Docker wasn't running this session so this is NOT a live-verified
  regression check, flagged explicitly as reasoned-not-measured.
- 63 new tests across two new files: `tests/test_redirect_scope.py` (25 --
  out-of-scope HTTP/HTTPS redirects, relative/absolute/protocol-relative
  redirects, chained redirects, redirect loops terminating via the cap,
  disallowed schemes, malformed Location headers, IP-obfuscation bypass
  attempts, both copies of the algorithm including the real registered
  `http_request`/`probe_variant` closures, not just the underlying
  function) and `tests/test_prompt_injection.py` (15 -- token
  generation/uniqueness, wrapping content, the specific spoofed-boundary
  scenario, real `run_tool_loop` integration proving injected tool output
  is actually wrapped in what reaches the model, per-agent evidence
  wrapping, the brace/`.format()` regression guard). Full suite: 200/201
  pass (one pre-existing, unrelated `test_mcp_server_full_flow` failure,
  same as every prior session).
- NEXT: live DVWA regression check for the `MAX_REDIRECTS` sanity concern
  once Docker/DVWA is up. No other follow-up from this pass -- both items
  from the review are considered closed within their stated (and
  documented) scope.

## 2026-08-19 — Completed all 10 stub skill files to `status: full`
- User feedback: the skills directory was materially uneven — 6 of 16 files
  (`sqli`/`idor`/`xss`/`auth_bypass` from Phase 1, `known_vulnerable_service`/
  `weak_credentials` from Phase 2) had real, hand-authored testing
  methodology; the other 10 were `status: stub` — a one-paragraph
  definition plus a generic "call `lookup_attack_technique` and use
  `execute_python`" fallback, no actual technique guidance. User wanted all
  10 brought up to the same bar.
- Discussed and declined grouping skills into `skills/web/`/`skills/network/`
  subfolders in the same pass — at today's 12:2 web:network ratio it doesn't
  meaningfully improve on a flat 14-file directory, and would need either a
  recursive glob in `agent_core.load_skill()` (fine, but unneeded right now)
  or a hand-maintained finding-type→folder map (the drift-prone pattern
  this codebase already hit and fixed twice this session, with
  `REPLAYABLE_TOOLS` and the manifest `replayable` field). Revisit once a
  third category actually exists.
- Wrote real methodology for all 10 (`command_injection`, `path_traversal`,
  `csrf`, `ssrf`, `xxe`, `ssti`, `deserialization`, `file_upload`,
  `security_misconfig`, `business_logic`), matching the established
  template exactly: framing paragraph, numbered "what to check, in order"
  steps with concrete payloads/signals (not generic advice), "response
  signatures" split into real-finding vs false-positive bullets, and a
  "tooling" section mapping steps to `probe_variant` vs `execute_python`.
  Each genuinely differs in technique -- e.g. `ssrf`/`xxe` both explicitly
  flag blind/out-of-band variants as unconfirmable with current tooling
  (no Collaborator-style callback infra until Phase 4) rather than
  pretending the skill covers them; `ssti` scopes itself to
  detection+math-confirmation and explicitly defers gadget-chain RCE
  escalation as engine-specific and out of depth; `deserialization` leans
  on error-differential signatures (malformed vs non-serialized garbage)
  since generic gadget-chain construction isn't something `execute_python`
  can do from scratch; `business_logic` uses a scenario checklist instead
  of a single technique (negative-quantity, workflow-skip, coupon abuse,
  race conditions) since it's inherently app-specific — kept `cwe`/
  `attack_technique`/`attack_tactic` as `null`, unchanged from the original
  stub's own reasoning, now just backed by real methodology instead of a
  fallback note.
- Fixed one now-stale test caught by the full suite:
  `test_attack_reference.py::test_load_skill_stub_status_parses_frontmatter`
  hardcoded `ssrf` as an example stub file, which broke the moment `ssrf`
  became `full`. Rewrote it against a synthetic tmp-dir stub file
  (`monkeypatch.setattr(agent_core, "SKILLS_DIR", ...)`) so the stub-parsing
  code path (still real, exploit_agent's prompt still nudges toward
  `lookup_attack_technique` for any future `stub` skill) stays tested
  without depending on any specific shipped file staying a stub. Added two
  new regression tests: one confirming `ssrf` specifically now carries real
  methodology, one confirming *all* 16 shipped skills are `status: full`
  with no leftover "No hand-authored methodology yet" text (the
  `business_logic` `cwe: null` exception excluded from the CWE-presence
  check, everything else must have one).
- `CLAUDE.md`/`README.md`/`docs/roadmap.md` updated — roadmap.md's
  historical Phase 1/1.5 status blocks kept as-is (accurate for what was
  true when those phases shipped) with forward-pointer notes added rather
  than rewritten, consistent with treating it as a running log.
- 160/161 tests pass (same pre-existing, unrelated `test_mcp_server_full_flow`
  failure). No code/architecture changes — content + one test fix only.
- NEXT: none of the 10 newly-full skills have been live-tested against a
  real target yet (the original 4 were validated against Juice Shop/DVWA
  live runs before being marked full; these 10 were authored to the same
  template/rigor but not yet exercised end-to-end). Worth a live check
  next time a target surfaces findings in these classes — bWAPP is
  specifically suited for xxe/ssti/deserialization per `docs/roadmap.md`.

## 2026-08-18 — Switched license from MIT to BSL 1.1
- User decision, not a code change: source stays fully visible and free to
  clone/run/modify/fork/use for almost any purpose (including commercial),
  with one carve-out -- can't offer Ronin, or a substantially similar
  derivative, as a hosted/managed/as-a-service pentesting product to third
  parties without a commercial license. Converts automatically to Apache
  License 2.0 on the Change Date, 2030-08-18 (4 years from today). Goal:
  keep the project genuinely open for use/contribution/portfolio visibility
  during the job search while protecting the option to commercialize later.
- Fetched the actual canonical BSL 1.1 template text (cross-verified against
  both mariadb.com/bsl11 -- the license's origin -- and CockroachDB's real
  BSL adoption on GitHub, word-for-word identical on the Terms/Covenants/
  Notice sections) rather than reconstructing it from memory, given how hard
  licensing mistakes are to undo. Filled in the Parameters block only
  (Licensor, Licensed Work, Additional Use Grant, Change Date, Change
  License) -- the operative legal text is untouched boilerplate.
- Flagged one real ambiguity in the user-provided Additional Use Grant
  wording: "offer... as a hosted, managed, or otherwise as-a-service
  penetration-testing product or service" could, read strictly, arguably
  sweep in a consultant using Ronin as an internal tool to deliver a paid
  pentest engagement (which is explicitly meant to be allowed) versus
  actually SaaS-ifying Ronin itself and reselling access to it (the actual
  target). User's call on whether to tighten the wording. Also noted (not
  blocking, industry-standard practice per CockroachDB/Sentry/Materialize
  all doing the same): BSL 1.1's own Covenant #1 nominally asks for a
  GPLv2-compatible Change License, and Apache 2.0 is technically not
  GPLv2-compatible -- a well-known, widely-ignored tension in real BSL
  adoptions, not something enforced against the Licensor.
- Updated `README.md` (BSL badge/note under the title + a full plain-language
  "What the license means in practice" section) and `CLAUDE.md`. No code,
  architecture, or functionality changed.
- NEXT: user should confirm the Additional Use Grant wording as-is or adopt
  the tightening suggested above, and confirm the commercial-licensing
  contact email in `LICENSE` (used `pranavc6969@gmail.com` on file, not
  separately confirmed for this purpose).

## 2026-08-18 — Real-time live logging across the whole pipeline
- User request, directly motivated by pain hit repeatedly this session:
  every agent call was silent until its stage finished, so watching a
  long-running Metasploitable sweep gave zero signal on whether it was
  progressing or actually stuck (came up multiple times with the GLM/Qwen
  runs -- had to manually diff terminal scrollback and log-file timestamps
  each time to tell). Also closes a documented gap from 2026-08-16's
  progress entry: recon's own reasoning/tool-call transcript was discarded
  entirely once `run_recon_agent` returned only its extracted findings --
  no way to inspect *how* recon reached a given finding count after the
  fact.
- `agent_core.run_tool_loop` gained `label` (prefixes every printed line --
  `"recon"`, `"exploit:f3"`, `"verify:f9"`) and `log_path` (optional).
  Every model turn's reasoning text and every tool call/result now print
  immediately, flushed, truncated for the terminal (`_short`) but logged
  untruncated. `log_path`, if set, gets the same events appended as JSON
  lines (`_append_log`, opened/closed per write so a crash mid-run still
  leaves a complete partial log). `agent_core.new_run_log_path(target)`
  generates the default path (`logs/run_<slugified-target>_<timestamp>.jsonl`);
  `run.py`/`main.py` create one per invocation and thread it through every
  stage, so a full recon->exploit->verify run lands in one chronological
  file -- overridable via the new `--log-path` flag on both entry points.
- Small cleanups along the way: `agent_core.slugify()` now shared by
  `run.py`/`main.py`/`new_run_log_path` (was duplicated in `main.py` only,
  `run.py` had no filename-generation need until this); fixed the
  `[total] estimated cost` line's hardcoded "verify against
  console.anthropic.com billing" to name the right dashboard for whichever
  `--provider` actually ran (flagged during the Qwen-run findings review,
  fixed here since it was a two-line change adjacent to what was already
  being touched).
- 13 new unit tests (`tests/test_live_logging.py`): `_short` truncation,
  `_append_log` no-op/write behavior, live-print output for reasoning/tool
  calls/errors (with and without a label), JSONL persistence content and
  opt-in-ness, `slugify`/`new_run_log_path`. 158/159 tests pass (same
  pre-existing unrelated `test_mcp_server_full_flow` failure).
- NEXT: not live-tested yet against a real multi-stage run (only a scripted
  adapter + a manual one-off script confirming the print/log format looks
  right). Next live Metasploitable run (whichever provider) will be the
  first real end-to-end check that this holds up across recon -> exploit ->
  verify without excessive terminal noise at real tool-call volumes.

## 2026-08-17 — Fixed replay_probe crashing on non-Anthropic tool-call types
- First live run against a non-Anthropic provider (Qwen3.6 Plus via
  OpenRouter, `--provider openrouter`) against real Metasploitable, using
  the same broad-coverage recon objective and budgets as the Claude
  full-pwn run for comparison. Recon self-terminated (`end_turn`) at 75/120
  tool calls with 25 findings -- notably less thorough than Claude's
  119/120-call, 54-finding run on an identical budget, a real behavioral
  difference between the two models, not a resource constraint. Full
  pipeline completed for all 25 findings before the OpenRouter account ran
  out of credits (real cost: ~$11.12 per our own tracking). Result: 1
  verified (WebDAV at `/dav/`, matching the Claude runs' finding -- now
  found independently by two different model providers, which is stronger
  evidence it's real local environment drift than a single model's
  hallucination), 11 dead-end, 7 incomplete, 6 unverifiable. One likely
  inaccurate finding surfaced too: `f4` claimed "ProFTPD 1.3.1" on port 21,
  which conflicts with `f1`'s (correct) vsftpd 2.3.4 on the same port --
  Metasploitable 2 doesn't run ProFTPD at all; looks like a fabricated
  banner rather than something nmap actually observed. Not investigated
  further this session.
- All 6 `unverifiable` findings turned out to share one real cause, not the
  "no declared replay path" scenario built yesterday (that mechanism
  wasn't triggered at all here): `replay_probe` was crashing outright with
  real Python `TypeError`s. Root cause: Qwen, unlike Claude's native tool
  use, didn't always emit correctly-typed nested tool-call arguments
  matching the declared JSON schema -- a `metasploit` call's `port`/`lport`
  recorded as strings ("3632"/"44440"), a `probe_variant` call's headers as
  JSON-encoded strings instead of objects. The original `exploit_agent`
  calls likely succeeded because the MCP server layer coerces types before
  the registered tool function runs; replay calls the raw `run_*` function
  directly, bypassing that coercion. `verify_agent` correctly read the
  crash as `unverifiable`, not disproof -- the system worked as designed
  even under a failure mode nobody anticipated -- but the crash itself was
  a genuine bug.
- Fixed with `_coerce_dict`/`_coerce_int` helpers in `categories/verify.py`,
  applied at the specific dispatch sites that lacked defensive casting
  (`probe_variant`'s header/params fields, `metasploit`'s `port`/`lport`/
  `options`). `run_sqlmap`'s `level`/`risk` already wrapped `int(...)`
  internally, so needed no change -- checked each tool's actual signature
  before assuming where the fix belonged, rather than coercing everywhere
  defensively. 10 new regression tests in `tests/test_verify.py` reproduce
  the exact recorded shapes (`f3`'s stringified metasploit lport/port,
  `f6`'s stringified probe_variant headers) from the live run that crashed.
  145/146 tests pass (same pre-existing unrelated `test_mcp_server_full_flow`
  failure).
- NEXT: the `f4` ProFTPD-vs-vsftpd discrepancy and the "console.anthropic.com"
  hardcoded string in `run.py`'s cost-estimate print (wrong for a
  non-Anthropic run) were flagged but not fixed this session -- both minor,
  neither blocking. No live re-run against Qwen done yet to confirm the fix
  holds against real (not just reconstructed) data; would need more
  OpenRouter credits.

## 2026-08-17 — Generalized the OpenRouter provider from "glm" to "openrouter"
- Live-tested `--provider glm --model glm-5.2` end to end against real
  OpenRouter -- surfaced that the model id needed the `z-ai/` provider
  prefix, and that the specific route (`z-ai/glm-5.2:free`) doesn't support
  tool calling at all (a known, common OpenRouter free-tier limitation, not
  a bug in our adapter -- confirmed via web research, not assumption).
  Investigating paid alternatives, also caught and corrected two more wrong
  assumptions live: an initial DeepSeek V4 Pro price quote sourced from a
  blog turned out stale, and a specific DeepSeek endpoint
  (`deepseek/deepseek-v4-pro-0813`) explicitly does NOT support tools per
  its own OpenRouter FAQ data, despite looking usable at a glance. Verified
  the next four candidates (Muse Glimmer 30B, Qwen3.6 Plus, GLM 5.2 paid,
  DeepSeek V4 Pro `-0423`) directly against OpenRouter's own structured FAQ
  data (JSON-LD, not marketing copy or search snippets) before trusting any
  of them -- all four genuinely support tools.
- User wants to try Qwen3.6 Plus next, same OpenRouter account/key as the
  GLM attempt. Since OpenRouter is one account/key/endpoint fronting many
  models, having a separate `"glm"` provider name (and a `GLM_API_KEY` env
  var) was needlessly narrow -- renamed to a generic `"openrouter"`
  provider backed by `OPENROUTER_API_KEY`, with the actual model selected
  entirely via `--model` (`qwen/qwen3.6-plus`, `z-ai/glm-5.2`,
  `deepseek/deepseek-v4-pro`, etc.). No new adapter logic, purely a rename
  (`models/__init__.py`, `.env`, docs, one test comment). 136/137 tests
  still pass (same pre-existing unrelated failure).
- NEXT: user is getting an OpenRouter key set up to actually run
  `--provider openrouter --model qwen/qwen3.6-plus` against Metasploitable.
  No live run completed yet with any non-Anthropic provider.

## 2026-08-17 — Second model provider: GLM via OpenAI-compatible adapter
- User has a GLM (glm-5.2) API key via OpenRouter and wants to test it
  against the same Metasploitable pipeline -- exactly the scenario the
  Phase 0 adapter layer was built to make cheap. Confirmed it is: new file
  + one `build_adapter` branch, no `agent_core.py`/agent-loop changes.
- `models/openai_compatible_adapter.py`'s `OpenAICompatibleAdapter` speaks
  OpenAI's chat-completions wire format (tools/tool_calls, one `role:
  "tool"` message per result rather than Anthropic's single
  user-turn-with-multiple-blocks shape). Kept generic on purpose --
  `base_url`/`api_key_env` are constructor params, not hardcoded -- so it's
  not GLM-specific, it's "any OpenAI-compatible provider." `finish_reason`
  values normalized to Anthropic's vocabulary (`tool_calls`→`tool_use`,
  `stop`→`end_turn`) so `run.py`'s printed stop_reason stays consistent
  across providers.
- `models/__init__.py`'s `"glm"` provider registers a small factory
  function pointing the adapter at OpenRouter
  (`https://openrouter.ai/api/v1`, key from `GLM_API_KEY` env var) --
  confirmed with the user which endpoint/model-id string to use rather than
  guessing (OpenRouter vs GLM/Zhipu direct use different base URLs and the
  key wouldn't authenticate against the wrong one).
- 7 new unit tests (`tests/test_openai_compatible_adapter.py`): message
  translation (incl. the multi-tool-result expansion difference from
  Anthropic's shape), tool schema translation, response parsing (tool
  calls, usage, finish_reason normalization), malformed tool-call-argument
  JSON defaults to `{}` rather than crashing. `openai` added to
  requirements.txt. 135/136 tests pass (same one pre-existing unrelated
  `test_mcp_server_full_flow` failure).
- NEXT: user needs to add `GLM_API_KEY=...` to `.env` and run
  `run.py --provider glm --model glm-5.2 ...` themselves (live pentest runs
  against a real target are blocked by the harness's own auto-mode
  classifier when attempted via the assistant's own tool calls -- same
  restriction hit earlier in the Metasploitable full-pwn session). Live
  check against Metasploitable not yet done.

## 2026-08-16 — Structural fix: `unverifiable` status + manifest-declared replay coverage
- Follow-up to the false-positive replay bug fixed 2026-08-15. That fix
  (extending `REPLAYABLE_TOOLS` to cover `network_exploit` + `metasploit`)
  addressed the specific tools involved, but left the *mechanism* unfixed:
  `REPLAYABLE_TOOLS` was still a hand-maintained tuple that happened to be
  kept in sync by one regression test -- a new tool landing in a category
  `exploit_agent` can reach, without anyone updating that tuple, would
  silently reopen the identical bug. Worth noting: by the time this session
  started, `metasploit` already had real replay support (confirmed by
  reading the current code before touching anything) -- the user's initial
  framing described the pre-fix symptom, which no longer matches what's in
  the repo; flagged and corrected before writing any code.
- New finding status `unverifiable`, distinct from `false_positive`: means
  the verification tooling has no way to confirm or refute a claim (a
  coverage gap), never a disproof. `categories/verify.py`'s
  `run_replay_probe` (refactored out of the `register()` closure into a
  testable module-level function, matching every other category's `run_*`
  pattern) now walks every recorded call in a winning attempt and returns
  either a real replay (tool has dispatch support) or an explicit
  `{"replayable": false, "reason": ...}` stub (tool doesn't) -- every call
  from the original transcript is visible in the output, none silently
  vanish. `agents/verify.md` updated: `false_positive` is reserved for "a
  replay actually ran and contradicted the claim"; `unverifiable` for
  everything else. `verify_agent/loop.py` recognizes `unverifiable` as a
  terminal verdict status.
- `manifest.yaml` now requires every tool to declare
  `replayable: "true" | "false" | "partial"`; `manifest.py` reads it via
  required-key indexing (`entry["replayable"]`, not `.get()`), so a tool
  added without deciding this fails loudly at `load_manifest()` time --
  every code path that loads the manifest, not just a dedicated test.
  `categories/verify.py`'s replayable-tool set is now *derived* from this
  field instead of hand-maintained, structurally preventing the drift that
  caused the original bug. Audited and declared for all 17 existing tools:
  11 `"true"` (deterministic/idempotent -- probe_variant, execute_python,
  the 6 idempotent network_exploit scans/lookups, lookup_attack_technique),
  2 `"partial"` (hydra, metasploit -- real dispatch exists and genuinely
  re-executes, but replay fidelity has a known live-environment caveat:
  account lockout/rate-limiting for hydra, one-shot exploit triggers and
  LHOST/network-topology dependence for metasploit), 4 `"false"`
  (http_request, dns_lookup, code_search, file_read, replay_probe itself --
  all structurally unreachable by exploit_agent, so replay coverage is moot
  for them, not a gap).
- `tests/test_replay_coverage.py` (new, 8 tests): asserts every manifest
  tool declares a valid `replayable` value; `load_manifest()` raises
  (behaviorally tested, not just inspected) on a missing or invalid
  `replayable` field; every `"true"`/`"partial"` tool `exploit_agent` can
  reach has a real `_replay_call` dispatch case (parametrized per tool,
  fails with a specific message naming the missing case); `"false"` tools
  never reach real dispatch. `tests/test_verify.py` gained 4 more:
  regression-checks the *original* bug against current code (a
  reconstructed CVE-2011-2523-shaped metasploit winning attempt dispatches
  to real replay, not a stub -- proving that bug stays fixed); a synthetic
  undeclared-tool case proving the *new* unverifiable mechanism actually
  fires (metasploit itself can't exercise this path anymore since it's
  already replayable -- used a synthetic tool name instead, and said so
  explicitly rather than silently substituting); a mixed-calls case;
  existing `test_every_exploit_agent_tool_is_replayable` generalized to
  allow a legitimately-declared `"false"` tool rather than requiring every
  exploit-agent tool be replayable. 128/129 tests pass (Docker/live-API
  tests skipped as usual); the one failure is the pre-existing, unrelated
  `test_mcp_server_full_flow` stale-tool-list issue, already flagged as a
  separate background task.
- NEXT: no committed next step for this fix. Two related, explicitly
  out-of-scope items surfaced but not built: (1) real metasploit-module
  replay improvements (this pass only prevents mislabeling, doesn't improve
  live-replay fidelity) -- a real feature deserving its own scoped design;
  (2) the separate, still-open problem of a *genuinely-run* live replay
  failing for one-shot/network-topology reasons and getting conflated with
  a real `false_positive` -- `"partial"` flags this in-band now but doesn't
  solve it. Awaiting user decision on whether/when to commit this change.

## 2026-08-16 — Token usage + cost tracking
- Added after a live Metasploitable full-pwn run hit `credit balance too low`
  mid-exploit-stage, and there was no way to answer "how much has this
  actually cost" beyond guessing from tool-call counts -- the harness never
  tracked tokens anywhere.
- `models/base.py`'s `ModelResponse` now carries a `usage: Usage` field
  (input/output/cache tokens); `AnthropicAdapter` populates it from the real
  API response, getattr-guarded so mocked responses default to zero instead
  of raising. `agent_core.run_tool_loop` sums usage across every model call
  in one invocation and returns it; each `run_*_agent()` threads it through
  (recon: run-level; exploit/verify: per-finding on each attempt record,
  plus a run-level total via new `models.sum_usage`). `models/pricing.py`
  converts a usage dict to a dollar estimate via a static, maintained
  pricing table (Sonnet-tier fallback for unrecognized model ids) --
  explicitly not a live lookup, Anthropic doesn't expose one. `run.py`
  prints per-stage + total tokens/cost; `main.py` prints the same for
  single-agent runs. Every cost line is labeled approximate and points at
  `console.anthropic.com` as the real source of truth.
- 11 new unit tests (`tests/test_usage_tracking.py`): Usage arithmetic,
  pricing table lookup + unknown-model fallback + missing-key defaults,
  adapter usage extraction (present and absent), run_tool_loop accumulation
  across single and multiple model calls. Full suite still passes (109/110;
  the one failure, `test_mcp_server_full_flow`, is pre-existing and
  unrelated -- a stale expected-tool-name set that predates the Kali/
  Metasploit tools, flagged separately, not fixed here).
- NEXT: no committed next step. The interrupted Metasploitable full-pwn run
  (54 findings, 12 processed before the credit error) is still sitting in
  `findings_metasploitable_fullpwn.json`, gitignored -- resume once credits
  are topped up. `run.py` has no resume-from-partial-file support yet
  (reruns recon from scratch), worth a look if this comes up again.

## 2026-08-15 — Live Metasploitable run + fixed a real verify bug it found
- Ran the full `recon -> exploit -> verify` pipeline against real
  Metasploitable (192.168.56.5) with `--objective` explicitly asking for
  exploitation, not just enumeration. Results: recon made 40 real tool
  calls (nmap/enum4linux/etc, its own tool_use turns) and produced 11
  candidate findings; exploit_agent processed all 11, reaching real
  Metasploit-confirmed exploits including a root shell via
  `exploit/multi/samba/usermap_script` (CVE-2007-2447) and a real backdoor
  session via `exploit/unix/ftp/vsftpd_234_backdoor` (CVE-2011-2523) --
  full proof the recon-agent-access fix and `metasploit` tool both work
  end-to-end through the real agent pipeline, not just tool-level.
- Found and fixed a real bug this run surfaced: `categories/verify.py`'s
  `replay_probe` only ever replayed `probe_variant`/`execute_python` calls
  -- a filter that predates network_exploit/metasploit. 3 genuinely
  exploited findings (the two CVEs above + a Ghostcat/CVE-2020-1938 file
  read) got marked `false_positive` purely because replay found zero calls
  it knew how to run, not because the exploits weren't real. Fixed by
  extending `REPLAYABLE_TOOLS`/`_replay_call` to cover all 7 network_exploit
  tools + `metasploit` + `lookup_attack_technique`, with a regression-guard
  test (`test_every_exploit_agent_tool_is_replayable`) that diffs
  exploit_agent's actual toolset against what verify can replay, so this
  can't silently drift again when a tool is added.
- Confirmed the fix works mechanically (replaying f2/f3's real metasploit
  calls now genuinely re-attempts them, where before it found nothing to
  run) -- but also surfaced a *separate*, not-a-bug nuance while doing so:
  live-exploit replay can legitimately fail a second time for reasons
  outside the code (vsftpd's backdoor is one-shot on the target; LHOST for
  reverse payloads is host network topology, not a container-internal IP).
  Documented both distinctly in CLAUDE.md so they don't get conflated later.
- 104 tests pass (7 new in test_verify.py). Committed.
- NEXT: no committed next step. The `false_positive`s from this specific
  run stay as historical record in findings_metasploitable.json (gitignored,
  not committed) -- a fresh pipeline run would now verify them correctly
  for the repeatable exploits (Samba/Ghostcat), modulo the live-replay
  caveat above.

## 2026-08-15 — Added metasploit (exploit_agent-only)
- New `metasploit_exploit` category (separate from `network_exploit` so it
  can go to `exploit_agent` only, not `recon_agent` -- explicit user
  direction). `categories/metasploit.py`'s `metasploit` tool runs a real
  Metasploit module against a scope-validated target inside the same
  long-lived Kali container, via a generated resource script (`docker exec
  -i ... tee` to write it in, no bind mount available on this container).
- Two explicit, deliberate exceptions to this repo's usual discipline, by
  user choice after I proposed narrower alternatives and they declined
  both: `module` is free-text (no curated allowlist), and reverse-shell
  payloads are supported (`payload`/`lhost`/`lport`). What's still
  enforced: scope validation, a resource-script newline-injection guard,
  and `lport` must fall in a fixed published range
  (`executor.KALI_LPORT_RANGE`, 44440-44450) -- `ensure_kali_container_ready()`
  now publishes that range and recreates the container if an existing one
  predates it (Docker can't add port publishing after creation).
- `skills/known_vulnerable_service.md` + `agents/exploit.md` updated:
  prefer `metasploit` over hand-rolled `execute_python` when a matching
  module exists, `execute_python` stays the fallback.
- 13 new unit tests (mocked) + a Docker-integration test file (metasploit-
  framework installed, a real module run against a closed port completes
  without hanging). Image rebuild with `metasploit-framework` (~4.3GB+)
  kicked off; still running as of this entry -- confirm it finished and the
  integration test actually passes before considering this shipped.
- NEXT: once the image build finishes, run the full suite + the new
  integration tests, then the live check -- exploit_agent should call
  `metasploit` with `exploit/unix/ftp/vsftpd_234_backdoor` against the real
  Metasploitable box and get a real session-opened result. Everything here
  is uncommitted on `main`, stacked on top of the also-uncommitted
  recon-agent-access fix below.

## 2026-08-14 — Closed the recon->network_exploit reachability gap
- Reconsidered the Phase 2 boundary decision after the user pushed back:
  `recon_agent.ALLOWED_CATEGORIES` now includes `network_exploit` (real
  agent-level tool access, same mechanism exploit_agent already had) --
  recon decides itself which of the 7 Kali tools fit the target's scope,
  real `tool_use` turns, not host-code-triggered. Superseded the original
  "recon stays HTTP/DNS-only" note in `docs/roadmap.md` explicitly rather
  than leaving it stale; HITL gating (`require_approval` on
  `network_exploit`) is what actually keeps this safe, unchanged.
- Two new finding types (`known_vulnerable_service` -> `searchsploit`,
  `weak_credentials` -> `hydra`), both `status: full` skills with real
  CWE/ATT&CK tags verified against `attack_enterprise_slim.json` (T1210
  Lateral Movement, T1110 Credential Access -- first genuine ATT&CK
  differentiation from T1190 since Phase 1.5 promised it would happen).
  `agents/recon.md` and `agents/exploit.md` updated with tool guidance.
- 4 new wiring tests + full regression suite pass (77 tests; Docker Desktop
  was down for this run so `test_execute_python.py`/the 3 Kali integration
  tests didn't execute -- pre-existing documented behavior, not a
  regression).
- NEXT: live check handed to user -- run `run.py` against real
  Metasploitable (192.168.56.5) and confirm recon_agent itself calls
  nmap/enum4linux/etc. (visible in its own transcript) and produces
  known_vulnerable_service/weak_credentials findings that exploit_agent
  then validates. This is what actually closes the gap end-to-end.
  Everything here is uncommitted on `main`.

## 2026-08-13 — Phase 2 (Kali attack box) built and integration-tested
- New `ronin-tools-mcp/docker/kali-tools.Dockerfile` (kalilinux/kali-rolling
  + nmap/nikto/sqlmap/hydra/wordlists/seclists/gobuster/enum4linux-ng/
  exploitdb, ~4.3GB built image). `executor.py` gained
  `ensure_kali_container_ready()`/`run_in_kali_container()` for a long-lived
  container (`ronin-kali-box`, `docker exec` per call) rather than
  execute_python's ephemeral-per-call pattern.
- `categories/network_exploit.py`: 7 tools (nmap, nikto, sqlmap, hydra,
  gobuster, enum4linux, searchsploit), all structured params/enums, no raw
  flags. Started at the roadmap's original 4, extended to 7 after
  identifying concrete gaps (content discovery, SMB enum, exploit-db
  lookup) -- each got the same parameter-design review/sign-off as the
  original four before any code was written.
- Real bugs caught by the Docker-integration test (not the mocked unit
  tests): nmap's `-F` and `-p` flags are mutually exclusive -- fixed by
  dropping `-F` when explicit ports are given; gobuster's guessed "medium"
  wordlist filename was wrong (actual: `DirBuster-2007_directory-list-2.3-
  medium.txt`) -- fixed by listing the real installed seclists tree instead
  of guessing. Also added loopback-host translation
  (`localhost`->`host.docker.internal`) since these tools run inside the
  Kali container, not through a scope-checked helper like execute_python --
  without it every scan would hit the Kali box itself instead of DVWA/Juice
  Shop.
- 32 unit tests (mocked `run_in_kali_container`) + 3 real Docker/DVWA
  integration tests all pass. Both roadmap copies + CLAUDE.md updated.
- Metasploitable live check DONE (2026-08-13, user stood up a real
  Metasploitable at 192.168.56.5): ran the 7 tools directly (tool-level, not
  through an agent -- see the gap noted below) against a real target.
  `nmap default_scripts` correctly fingerprinted vsftpd 2.3.4, anonymous FTP,
  Samba 3.0.20, and every classic Metasploitable open port; `enum4linux-ng`
  pulled real domain/OS info and all 5 SMB shares (incl. the world-writable
  `tmp` share); `searchsploit "vsftpd 2.3.4"` found the actual CVE-2011-2523
  backdoor exploit off nmap's own output -- exactly the gap that tool was
  added to close; `hydra` confirmed real connectivity and a real attack
  in-flight against SSH (didn't finish within a bounded timeout against
  10k real password attempts -- expected, not a bug).
- GAP SURFACED, not yet fixed: `recon_agent` has no `network_exploit`
  access and the 14-word finding-type vocabulary is entirely web-vuln-class
  -- there is currently no path for a full `recon -> exploit -> verify`
  pipeline run to ever hand `exploit_agent` a finding that would make it
  reach for `nmap`/`hydra`/etc. Today's Kali tools are real and tested at
  the tool level, but not yet reachable through the actual agent pipeline
  end-to-end. Needs its own scoped pass (network-layer finding types +
  either recon getting narrow nmap-discovery access, or a way to seed
  network-layer findings directly) -- not done as part of Phase 2.

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
