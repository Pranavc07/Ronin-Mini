"""Loads manifest.yaml -- the registry of every tool the MCP server exposes,
grouped by category. Used by the server (per-tool timeouts) and by clients
(building a category-based tool allowlist).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import yaml

DEFAULT_TIMEOUT_SECONDS = 15
REPLAYABLE_VALUES = ("true", "false", "partial")
_MANIFEST_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "manifest.yaml")


@dataclass(frozen=True)
class ToolMeta:
    name: str
    category: str
    description: str
    timeout_seconds: int
    require_approval: bool
    replayable: str  # "true" | "false" | "partial" -- see manifest.yaml's header comment


def load_manifest(path: str = _MANIFEST_PATH) -> dict[str, ToolMeta]:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    categories = raw.get("categories") or {}

    tools: dict[str, ToolMeta] = {}
    for name, entry in (raw.get("tools") or {}).items():
        category = entry["category"]
        category_cfg = categories.get(category) or {}
        # Required, not .get() with a default: a tool landing in manifest.yaml
        # without an explicit replayable decision must fail loudly here, at
        # load time (every code path that loads the manifest, not just a
        # dedicated test) -- see manifest.yaml's header comment for why this
        # field exists.
        replayable = entry["replayable"]
        if replayable not in REPLAYABLE_VALUES:
            raise ValueError(
                f"manifest.yaml tool {name!r}: replayable must be one of {REPLAYABLE_VALUES}, got {replayable!r}"
            )
        tools[name] = ToolMeta(
            name=name,
            category=category,
            description=(entry.get("description") or "").strip(),
            timeout_seconds=int(entry.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
            require_approval=bool(category_cfg.get("require_approval", False)),
            replayable=replayable,
        )
    return tools
