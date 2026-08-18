---
status: full
cwe: null
attack_technique: null
attack_tactic: null
---

# Business Logic Flaws

Confirming a business logic flaw means demonstrating a real, observable
effect that violates an assumption the application's rules depend on — a
purchase completing at an impossible price, a step being skipped and the
outcome still counting, a limit actually being exceeded. There's no single
payload for this class; each scenario below is its own test. `cwe`/
`attack_technique` are deliberately left `null` here — this class is
app-specific by nature and doesn't map onto a single generic weakness or
ATT&CK technique the way an injection class does; forcing one on wouldn't
be more accurate. `lookup_attack_technique` is unlikely to return anything
useful for this finding type.

## Scenarios to check (pick what's relevant to the finding)

1. **Negative or zero quantity/price manipulation.** If a quantity or price
   value is client-influenced (form field, hidden input, API parameter),
   try a negative number, zero, or a fractional value where an integer is
   expected. Confirm by completing the flow and checking the actual charged
   amount/resulting balance, not just that the request was accepted.
2. **Workflow step skipping.** If a multi-step process (e.g. checkout:
   cart → address → payment → confirm) is enforced only by the UI showing
   steps in order, call a later step's endpoint directly without
   completing the earlier ones. Confirm by checking whether the final
   state (order placed, action completed) is reached and valid.
3. **Coupon/discount abuse.** Try applying the same one-time-use code
   twice in the same or parallel requests (see race conditions below), or
   combining codes that should be mutually exclusive. Confirm via the
   actual final price/discount applied, not just an "applied" message.
4. **Quantity/limit bypass.** If a resource has a stated per-user limit
   (one redemption, max N items), try exceeding it via parallel requests,
   re-adding after removal, or a parameter that lets you specify quantity
   beyond the intended single-unit action. Confirm by checking the actual
   count/state afterward.
5. **Race conditions on one-time-use resources.** For any action meant to
   happen exactly once (redeem a coupon, claim a reward, submit a vote,
   withdraw a balance), fire multiple identical requests concurrently
   (not sequentially — the window that matters is real parallelism) and
   check whether the effect happened more than once. This is the one
   sub-case where `execute_python` genuinely needs concurrent requests, not
   a single request/response pair.
6. **Price/parameter tampering across a multi-request flow.** If a price or
   other server-trusted value is calculated on one request and only
   referenced (not recalculated) on a later one, try modifying it on the
   later request directly.

## Response signatures

**Real finding:**
- The actual final state (balance charged, order total, redemption count)
  reflects the manipulated value — not just that the manipulated request
  returned a 200.
- A parallel-request race produces more successful effects than the
  one-time-use limit should allow, confirmed by checking the resulting
  count/state, not the individual response codes.

**False positive / not confirmed:**
- The manipulated request is accepted (200) but the final state is
  server-recalculated correctly regardless (e.g. price is always
  recomputed from server-side catalog data, ignoring the client-sent
  value) — always verify the *actual resulting state*, not the request's
  own response.
- A skipped step's endpoint rejects the call outside the expected sequence
  (checks server-side session/state, not just UI flow).
- A race condition attempt produces exactly the intended single effect
  even under concurrent requests — proper locking is in place.

## Tooling

- `execute_python` (via `ronin_target.request`) is the primary tool for
  this class — most scenarios need either a multi-step flow with state
  carried between requests, or genuine concurrent requests for the race
  condition case, neither of which fits `probe_variant`'s single
  baseline-vs-variant shape.
- `probe_variant` can work for the simplest single-request cases (e.g. a
  straightforward negative-quantity parameter tamper with no multi-step
  flow involved) — baseline = legitimate value, variant = manipulated
  value.
