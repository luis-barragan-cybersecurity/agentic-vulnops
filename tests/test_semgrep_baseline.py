"""Semgrep baseline scorer: portable finding paths and class-aware precision."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[1]
_SEMGREP = _REPO / "evals" / "baseline" / "semgrep"
_FOREIGN_PREFIX = "/tmp/other-clone/agentic-vulnops/target/dvrestaurant"


def _score_mod() -> Any:
    spec = importlib.util.spec_from_file_location(
        "ave_semgrep_baseline_score", _SEMGREP / "score.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _catalog_rel(path: str) -> str:
    text = path.replace("\\", "/")
    marker = "app/apis/"
    idx = text.find(marker)
    assert idx >= 0, path
    return text[idx:]


def _frozen_results() -> list[dict[str, Any]]:
    raw = json.loads((_SEMGREP / "semgrep-findings.json").read_text())
    assert isinstance(raw, list)
    return raw


def _assert_known_hit_sets(res: dict[str, Any]) -> None:
    assert res["location_scoring"]["instances_hit"] == ["I-01", "I-02", "I-03", "I-08"]
    assert res["class_aware_scoring"]["instances_hit"] == ["I-01", "I-03", "I-08"]
    assert res["false_positives"]["decoys"] == ["D-05"]
    assert res["false_positives"]["unlabelled"] == [
        "app/apis/referrals/service.py:apply_referral_code"
    ]
    assert res["false_positives"]["wrong_class"] == ["I-02"]
    assert res["class_aware_scoring"]["precision"] == {
        "tp": 3,
        "precision_vs_decoys": 0.75,
        "precision_all_flags": 0.5,
    }
    assert res["location_scoring"]["precision"]["precision_all_flags"] == 0.667


def test_score_survives_foreign_absolute_prefix() -> None:
    score = _score_mod().score
    remapped = []
    for row in _frozen_results():
        copy = dict(row)
        copy["path"] = f"{_FOREIGN_PREFIX}/{_catalog_rel(row['path'])}"
        remapped.append(copy)

    _assert_known_hit_sets(score({"results": remapped}))


def test_score_accepts_target_relative_paths() -> None:
    score = _score_mod().score
    relative = []
    for row in _frozen_results():
        copy = dict(row)
        copy["path"] = _catalog_rel(row["path"])
        relative.append(copy)

    _assert_known_hit_sets(score({"results": relative}))
