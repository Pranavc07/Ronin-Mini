---
status: full
cwe: CWE-521
attack_technique: T1110
attack_tactic: Credential Access
---

# Weak / Default Credentials

A reachable login service (ssh, ftp) was identified during recon as worth
testing for weak or default credentials -- e.g. a service running on a host
where default/vendor credentials or common weak passwords are plausible.

## What to check, in order

1. **Identify the service and confirm it's reachable.** The finding's
   evidence should name the service (ssh/ftp) and the port. If recon
   observed a hint about a likely username (e.g. a default account name
   associated with the platform/product), use it.
2. **Call `hydra`** with `service` set to the identified service:
   - If a specific likely username is known, pass it as `username`.
   - Otherwise, pass `username_wordlist: "top_usernames"`.
   - Start with `password_wordlist: "common_top100"` -- fast, and covers the
     most common weak/default passwords. Only escalate to `"rockyou"` if the
     per-finding time budget genuinely allows a much longer run; a full
     rockyou pass against a real service can easily exceed typical budgets.
3. **Judge the outcome honestly.** Hydra either reports a valid
   username/password pair or it doesn't -- there's no partial credit.
   - A valid pair found = `exploited`, cite the exact credentials in
     evidence (they're needed for the verify pass to reproduce the finding).
   - No valid pair in the tested list = `dead-end` if the run completed, or
     `incomplete` if it hit the time budget before finishing (these are
     different -- `dead-end` means "tested and not found," `incomplete`
     means "didn't finish testing"). Don't call an unfinished run a
     confirmed negative.

## Response signatures

**Real finding (exploited):**
- hydra reports `[service] host: ... login: ... password: ...` for a
  successful attempt.

**Dead-end:**
- hydra completes its full wordlist run with no successful login.

**Incomplete:**
- hydra is still running / hasn't finished the wordlist when the finding's
  time budget runs out -- don't guess at the outcome.

## Tooling

- `hydra` is the only tool for this -- wordlists come from fixed enums
  (`rockyou`, `common_top100`, `top_usernames`), never a raw path.
