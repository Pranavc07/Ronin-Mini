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
   - If a matching Metasploit module exists for the exploit searchsploit
     found, prefer `metasploit` to actually run it over hand-rolling the
     exploit in `execute_python` -- a matched tool call is faster and more
     reliable than reimplementing a known exploit's protocol behavior from
     scratch. A real session opening (`"Command shell session N opened"` /
     `"Meterpreter session N opened"` in the returned output) is strong,
     concrete evidence -- that's `exploited`.
   - If no suitable module exists, `execute_python` (via
     `ronin_target.request`/raw socket access) is the fallback for
     reproducing a simple documented exploit behavior by hand -- still
     `exploited` if you observe the expected effect.
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

- `searchsploit` finds whether a known exploit exists -- offline, fast, no
  network access. Always the first step.
- `metasploit` is the preferred way to actually run a known exploit when a
  matching module exists (e.g. `exploit/unix/ftp/vsftpd_234_backdoor` for
  the vsftpd 2.3.4 backdoor). Judge the outcome from the returned
  msfconsole output, not a pre-judged verdict from the tool itself.
- `execute_python` (via `ronin_target.request` or raw socket access for
  non-HTTP protocols) is the fallback for attempting to trigger a
  documented exploit behavior by hand, when no Metasploit module fits.
