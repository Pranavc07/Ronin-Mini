---
status: full
cwe: CWE-89
attack_technique: T1190
attack_tactic: Initial Access
---

# SQL Injection

Confirming a SQL injection means showing the input reaches a SQL query in a way
that changes how the query is parsed — not just that an error appeared.

## What to check, in order

1. **Error-based probe first.** Send a single quote (`'`) in the suspect
   parameter and compare against the clean value. A raw SQL error in the
   response body (see signatures) is the strongest cheap signal.
2. **Boolean differential.** Send a condition that's always true vs always
   false, appended to the original value:
   - true:  `<orig>' OR '1'='1`  (or `<orig>')) OR (('1'='1` etc. depending on quoting/parens)
   - false: `<orig>' AND '1'='2`
   Compare responses. A true-payload that returns MORE rows / a different
   result set than the false-payload confirms the input is being parsed as SQL.
3. **UNION, only once boolean is confirmed.** Determine column count
   (`ORDER BY n` climbing until it errors, or `UNION SELECT 1,2,...` until it
   succeeds), then select real data. Full confirmation = attacker-chosen values
   or table data appearing in the response.
4. **Blind (boolean/time) only if no output reflects.** Boolean: infer from a
   true/false response difference. Time-based: `... AND SLEEP(5)` (MySQL) /
   `... AND 1=(SELECT 1 FROM PG_SLEEP(5))` (Postgres) — a reliable delay on the
   true payload and none on the false payload confirms it.

## Response signatures

**Real finding:**
- Raw DB error naming the engine/syntax: `SQLITE_ERROR: near "...": syntax error`,
  `You have an error in your SQL syntax` (MySQL), `unterminated quoted string` /
  `syntax error at or near` (Postgres).
- Boolean differential: true-payload and false-payload produce reliably
  *different* result sets (row count, specific records) while the base request
  is unchanged.
- UNION: your injected constants (e.g. `1,2,3`) or real table data appear in the
  rendered response.
- Time-based: consistent multi-second delay on the true payload, ~baseline on
  the false payload, repeatable.

**False positive / not confirmed:**
- A generic HTTP 500 or app error page with NO SQL-specific text — could be any
  server-side exception. Don't call it SQLi on a 500 alone.
- Row-count differences that also appear when you change the value *without* any
  SQL metacharacter (i.e. it's just normal filtering, not injection).
- A WAF/error page that's byte-identical for both true and false payloads — the
  input isn't reaching the parser.
- Reflected input in the body is XSS territory, not SQLi, unless it changes query
  results.

## Tooling

- `probe_variant` fits steps 1–2 directly: baseline = clean value, variant =
  injected value, then read the diff (status change, body-length delta,
  identical-body flag). This is the preferred path for error-based and
  boolean-differential confirmation.
- Fall back to `execute_python` for: determining UNION column count iteratively,
  time-based blind (needs timing measurement), or multi-step extraction where you
  parse one response to build the next request. Use `ronin_target.request` for
  all network calls in that code.
