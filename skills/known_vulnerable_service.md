---
status: full
cwe: CWE-1104
attack_technique: T1210
attack_tactic: Lateral Movement
---

# Known-Vulnerable Service

A network/service-layer scan (typically nmap) identified a service running a
specific version that has a documented public exploit -- e.g. `vsftpd 2.3.4`,
which has a well-known backdoor (CVE-2011-2523). The finding's evidence should
cite the exact service+version string that triggered this.

## What to check, in order

1. **Look up the exact version string.** Call `searchsploit` with the service
   name and version exactly as observed (e.g. `"vsftpd 2.3.4"`). A hit gives
   you an exploit title and a path/reference, not a working payload -- it
   tells you an exploit *exists*, not that you've confirmed anything yet.
2. **A searchsploit hit alone is not confirmed exploitation.** It identifies
   real exposure (a matching CVE for the exact running version), but the
   verdict distinction matters:
   - If you can actually trigger the documented behavior (e.g. a known
     backdoor command sequence, confirmable via `execute_python` using
     `ronin_target.request`/raw socket access) and observe the expected
     effect (shell access, a distinguishing response), that's `exploited`.
   - If searchsploit finds a real match but you have no way to actually
     trigger or confirm it with the tools available, the honest verdict is
     `dead-end` -- state clearly in your evidence that a known exploit
     exists for this version but active exploitation wasn't confirmed. Do
     not call it `exploited` on a version match alone.
3. **No searchsploit match** doesn't mean the finding is worthless -- an
   outdated/unusual version with no public exploit can still be worth noting
   as a `dead-end` with the version info as evidence, in case a future scan
   reveals something.

## Response signatures

**Real finding (exploited):**
- searchsploit returns a matching exploit for the exact version, AND you
  independently triggered/confirmed the documented behavior.

**Dead-end:**
- searchsploit returns a match but there's no way to confirm exploitability
  with the current toolset -- still worth recording as evidence of exposure,
  just not an exploited verdict.
- No searchsploit match for the version.

## Tooling

- `searchsploit` is the primary tool -- offline, fast, no network access.
- `execute_python` (via `ronin_target.request` or raw socket access for
  non-HTTP protocols) is the fallback for actually attempting to trigger a
  documented exploit behavior, when one is simple enough to reproduce.
