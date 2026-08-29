"""Load and version the governance policy.

Scaffold only (ticket 02): reads the YAML and exposes its version. Ticket 05 defines the
full predicate/blast-radius/ladder schema and a pure `decide()` that consults it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# policy.yaml lives at the repo root, two levels above this package's src root.
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[3] / "policy.yaml"


def load_policy(path: Path | None = None) -> dict[str, Any]:
    """Load the policy document. Returns an empty mapping if the file is absent."""
    policy_path = path or DEFAULT_POLICY_PATH
    if not policy_path.exists():
        return {}
    loaded = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def policy_version(path: Path | None = None) -> str:
    """The version string a decision record must cite."""
    return str(load_policy(path).get("version", "unset"))
