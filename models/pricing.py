"""Static USD-per-million-token pricing for cost estimation.

Anthropic doesn't expose a pricing API, so this is a maintained table, not a
live lookup -- treat every number here as approximate and verify against
https://console.anthropic.com (Plans & Billing / usage dashboard) or the
current Anthropic pricing page before relying on it for real budgeting.
Update PRICING when rates change or a new model is added.

Rates are (input, output, cache_write, cache_read), each $ per million tokens.
"""

from __future__ import annotations

PRICING: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-4-6": (15.00, 75.00, 18.75, 1.50),
    "claude-sonnet-4-6": (3.00, 15.00, 3.75, 0.30),
    "claude-haiku-4-5": (0.80, 4.00, 1.00, 0.08),
    # OpenRouter's free tier for this model -- confirmed genuinely $0 via the
    # model's OpenRouter page ("Price: Free"), distinct from the paid
    # "z-ai/glm-5.2" (no ":free" suffix). NOTE: if the paid variant is ever
    # added here too, _rates_for's substring fallback would need tightening
    # first -- "z-ai/glm-5.2" is literally a substring of
    # "z-ai/glm-5.2:free", so an exact-match miss on the paid id could fall
    # through to these $0 rates. Harmless today since only the free entry
    # exists, but worth remembering before adding the paid one.
    "z-ai/glm-5.2:free": (0.0, 0.0, 0.0, 0.0),
}

# Fallback for a model id not in PRICING (e.g. a new release): Sonnet-tier
# rates, so cost comes back as a reasonable estimate instead of silently 0.
_DEFAULT_RATES = (3.00, 15.00, 3.75, 0.30)


def _rates_for(model: str) -> tuple[float, float, float, float]:
    if model in PRICING:
        return PRICING[model]
    for name, rates in PRICING.items():
        if name in model or model in name:
            return rates
    return _DEFAULT_RATES


def estimate_cost_usd(model: str, usage: dict) -> float:
    """usage is a plain dict with input_tokens/output_tokens/
    cache_creation_input_tokens/cache_read_input_tokens keys (the shape
    Usage.as_dict() and every agent loop's aggregated usage produce) --
    missing keys default to 0 rather than raising.
    """
    in_rate, out_rate, cache_write_rate, cache_read_rate = _rates_for(model)
    return (
        usage.get("input_tokens", 0) / 1_000_000 * in_rate
        + usage.get("output_tokens", 0) / 1_000_000 * out_rate
        + usage.get("cache_creation_input_tokens", 0) / 1_000_000 * cache_write_rate
        + usage.get("cache_read_input_tokens", 0) / 1_000_000 * cache_read_rate
    )


def sum_usage(*usages: dict) -> dict:
    keys = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
    return {k: sum(u.get(k, 0) for u in usages) for k in keys}
