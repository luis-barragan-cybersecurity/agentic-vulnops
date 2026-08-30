#!/usr/bin/env python3
"""Score the role-pattern Semgrep baseline against the target catalog (build ticket 07).

This is the comparator the AVE scoreboard measures the agent against: the numbers a
competent *pattern* scanner can reach on the vendored target, so "AVE beats Semgrep on
the semantic ownership cases" is a measured claim, not a slogan.

It runs the sibling rule (`rules/missing-role-checker.yaml`) over the vendored target,
resolves each finding to the route handler that encloses it, and scores those handlers
against `target/catalog.json`: the 8 instances are the positives (the same answer key as
`ave.adapters.python_authz.catalog.ground_truth()`), the 5 decoys are labelled negatives,
and any other handler flagged is an unlabelled false positive.

Two scorings are reported, because they answer different questions:

  * location — a flag counts if it lands anywhere on an instance's handler, ignoring
    what it claims. This is the standard, *generous* SAST-benchmark measure.
  * class-aware — a flag counts as a recall hit only if its class (this rule emits BFLA)
    matches the instance's family. A BFLA "add a role check" verdict on a BOLA ownership
    gap is not a detection (wrong-reason coincidence: applying it would not remove the
    flaw) and is a wrong-class false positive for precision. This is the honest number
    for the semantic comparison.

Finding paths are stored and scored as TARGET_APP-relative `app/apis/...` keys, the same
form as catalog `file` fields. Live semgrep may emit absolute paths; those are stripped
on the way in and on the way out so frozen findings replay on any checkout.

Run with semgrep on PATH (or point AVE_SEMGREP at the binary); with neither, it scores the
committed `semgrep-findings.json` so the baseline is reproducible offline / in CI.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
# evals/baseline/semgrep/score.py -> repo root is three parents up.
REPO_ROOT = HERE.parents[2]
RULE = HERE / "rules" / "missing-role-checker.yaml"
CATALOG = REPO_ROOT / "target" / "catalog.json"
TARGET_APP = REPO_ROOT / "target" / "dvrestaurant"
SCAN_ROOT = TARGET_APP / "app" / "apis"
FROZEN_FINDINGS = HERE / "semgrep-findings.json"
RESULTS = HERE / "results.json"

# This rule detects one class only: missing function-level (role) authorization.
RULE_CLASS = "BFLA"
_APIS_MARKER = "app/apis/"


def _semgrep_bin() -> str | None:
    return os.environ.get("AVE_SEMGREP") or shutil.which("semgrep")


def run_semgrep(binary: str) -> dict[str, Any]:
    """Run the baseline rule over the vendored target and return semgrep's JSON."""
    proc = subprocess.run(
        [binary, "--config", str(RULE), str(SCAN_ROOT),
         "--json", "--quiet", "--metrics=off"],
        capture_output=True, text=True, check=False,
    )
    # semgrep exits non-zero when it finds matches; only a parse failure is fatal.
    try:
        return json.loads(proc.stdout)  # type: ignore[no-any-return]
    except json.JSONDecodeError:
        sys.stderr.write(proc.stderr)
        raise


def finding_rel_path(raw: str) -> str:
    """Return a TARGET_APP-relative posix path in catalog `file` form (`app/apis/...`)."""
    text = raw.replace("\\", "/")
    idx = text.find(_APIS_MARKER)
    if idx >= 0:
        return text[idx:]
    p = Path(raw)
    try:
        resolved = p.resolve() if p.is_absolute() else (TARGET_APP / p).resolve()
        return resolved.relative_to(TARGET_APP.resolve()).as_posix()
    except ValueError:
        raise ValueError(f"finding path is not under the target app: {raw}") from None


def portable_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy Semgrep result rows with paths rewritten to catalog-relative form."""
    out: list[dict[str, Any]] = []
    for row in results:
        copy = dict(row)
        copy["path"] = finding_rel_path(str(row["path"]))
        out.append(copy)
    return out


def enclosing_symbol(rel_path: str, line: int) -> str | None:
    """Name of the def/async-def whose span (decorators included) contains `line`."""
    src = (TARGET_APP / rel_path).read_text()
    tree = ast.parse(src)
    best: tuple[int, str] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        starts = [node.lineno] + [d.lineno for d in node.decorator_list]
        start, end = min(starts), (node.end_lineno or node.lineno)
        if start <= line <= end and (best is None or start >= best[0]):
            best = (start, node.name)
    return best[1] if best else None


def score(sg: dict[str, Any]) -> dict[str, Any]:
    cat = json.loads(CATALOG.read_text())
    instances = cat["instances"]
    decoys = cat["decoys"]
    by_key = {(i["file"], i["symbol"]): i for i in instances}
    decoy_files = {d["file"]: d for d in decoys}

    detected: dict[str, str] = {}       # instance id -> handler symbol hit
    decoy_fps: list[str] = []           # decoy ids wrongly flagged
    unlabelled_fps: list[str] = []      # flagged handlers absent from the catalog

    for r in sg.get("results", []):
        rel = finding_rel_path(str(r["path"]))
        sym = enclosing_symbol(rel, r["start"]["line"])
        inst = by_key.get((rel, sym))
        if inst is not None:
            detected[inst["id"]] = sym or "?"
        elif rel in decoy_files:
            decoy_fps.append(decoy_files[rel]["id"])
        else:
            unlabelled_fps.append(f"{rel}:{sym}")

    def recall(ids: list[str]) -> dict[str, Any]:
        hit = [i for i in ids if i in detected]
        return {"hit": sorted(hit), "n": len(ids), "recall": round(len(hit) / len(ids), 3)}

    bola = [i["id"] for i in instances if i["family"] == "BOLA"]
    bfla = [i["id"] for i in instances if i["family"] == "BFLA"]

    # Class-aware: a BFLA rule only truly detects BFLA instances. A hit on a BOLA
    # instance is a wrong-reason location overlap, not a recall hit, and a
    # wrong-class false positive for precision.
    class_hits = sorted(i for i in detected if by_key_family(instances, i) == RULE_CLASS)
    wrong_class = sorted(i for i in detected if by_key_family(instances, i) != RULE_CLASS)
    loc_hits = sorted(detected)

    n_decoy_fp = len(decoy_fps)
    n_unlab_fp = len(unlabelled_fps)
    n_wrong_class = len(wrong_class)

    def precision(tp: int, *, include_wrong_class: bool) -> dict[str, Any]:
        extra = n_wrong_class if include_wrong_class else 0
        labelled = tp + n_decoy_fp
        overall = tp + n_decoy_fp + n_unlab_fp + extra
        return {
            "tp": tp,
            "precision_vs_decoys": round(tp / labelled, 3) if labelled else None,
            "precision_all_flags": round(tp / overall, 3) if overall else None,
        }

    return {
        "flagged_handlers": len(sg.get("results", [])),
        "detected_instances": detected,
        "false_positives": {
            "decoys": sorted(set(decoy_fps)),
            "unlabelled": sorted(unlabelled_fps),
            "wrong_class": wrong_class,
        },
        "location_scoring": {
            "note": "generous: any flag overlapping an instance handler, class ignored",
            "instances_hit": loc_hits,
            "overall": recall([i["id"] for i in instances]),
            "bola": recall(bola),
            "bfla": recall(bfla),
            "precision": precision(len(loc_hits), include_wrong_class=False),
        },
        "class_aware_scoring": {
            "note": f"honest: a flag is a recall hit only where its class ({RULE_CLASS}) "
                    "matches the instance family; a role verdict on an ownership gap is "
                    "a wrong-class false positive",
            "instances_hit": class_hits,
            "overall": {"hit": class_hits, "n": len(instances),
                        "recall": round(len(class_hits) / len(instances), 3)},
            "bola": {"hit": [], "n": len(bola), "recall": 0.0,
                     "why": "a syntactic pattern cannot express object-ownership. I-04 is "
                            "unmatched (role checker present, no get_current_user). I-06 "
                            "and I-07 stay unmatched because GET is out of scope"},
            "bfla": recall(bfla),
            "precision": precision(len(class_hits), include_wrong_class=True),
        },
    }


def by_key_family(instances: list[dict[str, Any]], inst_id: str) -> str:
    for i in instances:
        if i["id"] == inst_id:
            return str(i["family"])
    return "?"


def _recall_line(label: str, r: dict[str, Any], tail: str) -> str:
    return f"  {label:5} recall : {r['recall']:.0%}  ({len(r['hit'])}/{r['n']})  {tail}"


def _precision_line(p: dict[str, Any]) -> str:
    return f"  precision : {p['precision_vs_decoys']} vs decoys, {p['precision_all_flags']} all"


def _block(title: str, s: dict[str, Any], bola_tail: str) -> list[str]:
    return [
        title,
        _recall_line("all", s["overall"], f"hit={s['overall']['hit']}"),
        _recall_line("BFLA", s["bfla"], f"hit={s['bfla']['hit']}"),
        _recall_line("BOLA", s["bola"], bola_tail),
        _precision_line(s["precision"]),
    ]


def render(res: dict[str, Any]) -> str:
    la, ca = res["location_scoring"], res["class_aware_scoring"]
    detected = ", ".join(f"{k} ({v})" for k, v in sorted(res["detected_instances"].items()))
    fp = res["false_positives"]
    lines = [
        "AVE role-pattern Semgrep baseline — score vs target catalog",
        "=" * 60,
        f"handlers flagged: {res['flagged_handlers']}",
        f"instances detected: {detected or 'none'}",
        f"decoy false positives: {', '.join(fp['decoys']) or 'none'}",
        f"unlabelled false positives: {', '.join(fp['unlabelled']) or 'none'}",
        f"wrong-class false positives: {', '.join(fp['wrong_class']) or 'none'}",
        "",
        *_block("LOCATION scoring (generous: overlap only)", la, f"hit={la['bola']['hit']}"),
        "",
        *_block("CLASS-AWARE scoring (honest: class match)", ca, "hit=[] (structurally blind)"),
        "",
        "This is the bar AVE must clear: rediscover the ownership (BOLA) gaps a pattern",
        "scanner is structurally blind to, at no worse precision.",
    ]
    return "\n".join(lines)


def main() -> int:
    binary = _semgrep_bin()
    if binary:
        sg = {"results": portable_findings(run_semgrep(binary).get("results", []))}
        FROZEN_FINDINGS.write_text(json.dumps(sg["results"], indent=2) + "\n")
        source = "live semgrep"
    elif FROZEN_FINDINGS.exists():
        sg = {"results": json.loads(FROZEN_FINDINGS.read_text())}
        source = f"frozen {FROZEN_FINDINGS.name}"
    else:
        sys.stderr.write("semgrep not found and no frozen findings to score\n")
        return 2

    res = score(sg)
    RESULTS.write_text(json.dumps(res, indent=2) + "\n")
    print(render(res))
    print(f"\n[scored from: {source}; wrote {RESULTS.name}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
