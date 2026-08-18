---
status: full
cwe: CWE-78
attack_technique: T1190
attack_tactic: Initial Access
---

# OS Command Injection

Confirming command injection means showing that input reaches a shell and
gets executed as a command — not just that the app behaved oddly on unusual
input.

## What to check, in order

1. **Identify a parameter that plausibly reaches a shell.** Fields that name
   a host/IP, filename, or invoke a system utility (ping, DNS lookup,
   file-conversion, image processing) are the classic candidates.
2. **In-band probe first.** Append a metacharacter chain that would run a
   second, harmless-but-observable command if the input reaches a shell:
   - `; id` / `&& id` / `| id` (Unix, semicolon/AND/pipe chaining)
   - `` `id` `` / `$(id)` (Unix, command substitution)
   - `& whoami` (Windows)
   Compare the response against the baseline (unmodified input). New content
   in the response matching command output (e.g. `uid=33(www-data)
   gid=33(www-data)`) confirms in-band execution.
3. **If nothing reflects, go blind/time-based.** Inject a sleep and measure:
   - `; sleep 5` / `&& sleep 5` / `| sleep 5` (Unix)
   - `& ping -n 6 127.0.0.1` (Windows, ~5s)
   A reliable, repeatable multi-second delay on the sleep payload vs baseline
   confirms execution even with no visible output.
4. **Try multiple separators if the first fails.** Different shells/contexts
   accept different chaining characters — a filtered `;` doesn't mean the
   parameter isn't injectable, just that separator is blocked. Try `|`,
   `&&`, newline (`\n`), and backticks/`$()` before concluding dead-end.
5. **Confirm impact, not just a delay.** Where possible, escalate from a
   sleep to an in-band read (e.g. `; id`, `; cat /etc/passwd` if the context
   allows) so the evidence is a concrete command result, not just timing.

## Response signatures

**Real finding:**
- Response body contains real command output (`uid=`, `gid=`, file listing,
  hostname) that only appears with the injected payload, not the baseline.
- A sleep payload produces a consistent, repeatable multi-second delay; the
  equivalent non-sleep payload (same syntax, no `sleep`) does not.

**False positive / not confirmed:**
- A generic error/500 with no command-related content — could be any
  malformed-input handling, not evidence of shell execution.
- Delay that also appears on other slow/unrelated inputs (e.g. large
  payloads generally slow the endpoint) — vary only the sleep duration and
  confirm the delay scales with it before trusting a timing signal.
- Special characters are visibly stripped/escaped in the reflected input
  (if the app echoes it back) — the app may be sanitizing before use.

## Tooling

- `execute_python` (via `ronin_target.request`) is the primary tool here —
  command injection needs custom payload construction and, for blind
  confirmation, timing measurement around the request. Send the baseline
  and injected requests back to back and compare.
- `probe_variant` can work for the simple in-band case (baseline = clean
  value, variant = value + metacharacter chain) if the vulnerable parameter
  is a straightforward query/header value — use it when the payload doesn't
  need timing logic.
