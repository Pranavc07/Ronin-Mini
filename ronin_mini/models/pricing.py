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
    # "z-ai/glm-5.2" (no ":free" suffix) below.
    "z-ai/glm-5.2:free": (0.0, 0.0, 0.0, 0.0),
    # Real per-OpenRouter-page rates for the paid variant, confirmed 2026-08-19
    # (openrouter.ai/z-ai/glm-5.2). This is also a live bug fix: before this
    # entry existed, _rates_for's substring fallback below matched the paid
    # id against the free-tier entry above ("z-ai/glm-5.2" in
    # "z-ai/glm-5.2:free" is True), silently pricing real paid usage at $0 --
    # caught live-testing this model against DVWA, where a run with over a
    # million real tokens reported $0.0000. Cache-write rate isn't published
    # by OpenRouter for this model; approximated as equal to the input rate
    # (the observed run never triggered a cache write either way, so this is
    # currently untested against real data).
    "z-ai/glm-5.2": (0.50, 3.15, 0.50, 0.115),
    # Real per-OpenRouter-page rates, confirmed 2026-08-19
    # (openrouter.ai/qwen/qwen3.6-plus). Also a bug fix: this model wasn't in
    # PRICING at all, so every run fell through to the Sonnet-tier
    # _DEFAULT_RATES below -- roughly a 9x overestimate versus its real,
    # much cheaper rates.
    "qwen/qwen3.6-plus": (0.325, 1.95, 0.4063, 0.0325),
}

# Fallback for a model id not in PRICING (e.g. a new release): Sonnet-tier
# rates, so cost comes back as a reasonable estimate instead of silently 0.
_DEFAULT_RATES = (3.00, 15.00, 3.75, 0.30)


def _rates_for(model: str) -> tuple[float, float, float, float]:
    """Exact match first; then a substring fallback for versioned/prefixed
    variants of a known model id. The substring check requires the shorter
    string to end at a '/' or ':' boundary in the longer one (not just any
    substring) -- a bare `in` check would match "z-ai/glm-5.2" against
    "z-ai/glm-5.2:free" and silently apply that unrelated model's rate,
    which is exactly the real bug this guarded against (see the PRICING
    comment above). Falls back to Sonnet-tier _DEFAULT_RATES, not $0, for a
    genuinely unknown id.
    """
    if model in PRICING:
        return PRICING[model]
    for name, rates in PRICING.items():
        if name.startswith(model) and name[len(model):len(model) + 1] in ("/", ":", ""):
            return rates
        if model.startswith(name) and model[len(name):len(name) + 1] in ("/", ":", ""):
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
