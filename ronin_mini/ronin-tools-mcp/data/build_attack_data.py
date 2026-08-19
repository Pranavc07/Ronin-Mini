#!/usr/bin/env python3
"""One-off generator for attack_enterprise_slim.json.

Downloads MITRE's public Enterprise ATT&CK STIX bundle (CTI repo, CC-BY 4.0)
and filters it down to just the technique-level fields the lookup_attack_technique
tool needs: technique id, name, tactics, description, url. Dropping
relationships/groups/software/mitigations/data-sources shrinks the ~48MB raw
bundle to a low-single-digit-MB static file, and lets the tool stay fully
offline at runtime -- no live third-party dependency.

Not run automatically; re-run manually if the ATT&CK dataset needs refreshing:
    python build_attack_data.py
"""

from __future__ import annotations

import json
import os
import urllib.request

RAW_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
_DATA_DIR = os.path.dirname(os.path.realpath(__file__))
RAW_BUNDLE_PATH = os.path.join(_DATA_DIR, "enterprise-attack-raw.json")
SLIM_OUTPUT_PATH = os.path.join(_DATA_DIR, "attack_enterprise_slim.json")


def download_raw_bundle(path: str = RAW_BUNDLE_PATH) -> None:
    print(f"Downloading {RAW_BUNDLE_URL} -> {path}")
    urllib.request.urlretrieve(RAW_BUNDLE_URL, path)


def build_slim_dataset(raw_path: str = RAW_BUNDLE_PATH, out_path: str = SLIM_OUTPUT_PATH) -> int:
    with open(raw_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = next(
            (ref["external_id"] for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if not technique_id:
            continue

        url = next(
            (ref["url"] for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"),
            None,
        )
        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"]

        techniques.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "tactics": tactics,
                "description": (obj.get("description") or "").split("\n\n")[0].strip(),
                "url": url,
            }
        )

    techniques.sort(key=lambda t: t["technique_id"])
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2)

    return len(techniques)


if __name__ == "__main__":
    if not os.path.isfile(RAW_BUNDLE_PATH):
        download_raw_bundle()
    count = build_slim_dataset()
    print(f"Wrote {count} techniques -> {SLIM_OUTPUT_PATH}")
