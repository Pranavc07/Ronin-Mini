---
status: full
cwe: CWE-1336
attack_technique: T1190
attack_tactic: Initial Access
---

# Server-Side Template Injection (SSTI)

Confirming SSTI means showing the server *evaluated* an expression you
injected (the math actually computed) — not just that your input was
reflected back verbatim.

## What to check, in order

1. **Identify a parameter reflected into rendered output** — name fields,
   search terms, comments, error messages, anything that ends up in an
   HTML/text response and plausibly passes through a template engine
   (common in profile names, email templates, PDF-generation-from-template
   features, custom report builders).
2. **Reflection baseline.** Send a unique benign marker and confirm it
   appears verbatim in the response, same first step as XSS — SSTI needs
   reflection too, just evaluated rather than raw.
3. **Polyglot math probe.** Send an expression that's valid syntax across
   several common engines at once, so one probe covers multiple
   possibilities:
   `${7*7}{{7*7}}<%= 7*7 %>#{7*7}[[${7*7}]]`
   If **any** `49` appears in the response in place of one of these
   sub-expressions, that sub-expression's syntax is being evaluated —
   note which one fired, it tells you the likely engine (`{{ }}` → Jinja2/
   Twig, `${ }` → Freemarker/Velocity-family, `#{ }` → Ruby/JSF-family).
4. **Confirm it's evaluation, not just reflection.** `7*7` reflecting back
   as literal text `7*7` (not `49`) means the syntax is being echoed, not
   run — not SSTI. Only a computed `49` counts.
5. **Note escalation is engine-specific and out of this skill's depth.**
   Once math evaluation is confirmed, further escalation to file read or
   RCE requires engine-specific gadget chains (e.g. Jinja2's
   `{{ self.__init__.__globals__... }}` chains) that vary significantly by
   engine/version/sandbox. Detecting and confirming expression evaluation
   is the bar for this skill — record which polyglot fragment fired as the
   evidence; deeper exploitation is a follow-up, not required for a valid
   `exploited` verdict here.

## Response signatures

**Real finding:**
- The response contains a computed `49` in place of one of the polyglot's
  math sub-expressions (not the literal text of the expression).
- Different, engine-specific error messages appear when you break the
  syntax deliberately (e.g. a Jinja2-specific `TemplateSyntaxError`) —
  supporting evidence even before a clean `49` is achieved.

**False positive / not confirmed:**
- The literal expression text (`{{7*7}}`, `${7*7}`, etc.) reflects back
  unevaluated — this is template syntax being treated as plain text, not
  injection.
- The math evaluates client-side only (check response Content-Type and
  confirm the `49` is present in the raw server response, not just what
  renders after client-side JS runs).

## Tooling

- `probe_variant` fits the detection phase well: baseline = benign marker,
  variant = the polyglot payload, then inspect whether `49` appears in the
  variant's body where it didn't in the baseline.
- Fall back to `execute_python` for anything beyond initial detection —
  engine-fingerprinting follow-up probes, or constructing an engine-specific
  payload once you know which syntax fired.
