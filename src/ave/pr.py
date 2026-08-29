"""Render the PR body — "the PR is the product".

The reviewer-facing artifact every AVE run produces: the finding, the decision record
that authorizes the fix, the blast radius, the patch, and the verification ladder. This
is the skeleton's plain-markdown version; ticket 06 designs the blast-radius / deployment-
ring visual that goes here, and ticket 05 firms the decision-record fields it renders.
"""

from __future__ import annotations

from typing import Any

from ave.state import AVEState

_LADDER_LABELS = {
    "t0_build": "T0 build",
    "t1_exploit_oracle_flipped": "T1 exploit oracle flipped",
    "t2_full_suite": "T2 full suite",
    "reattack_clean": "re-attack clean",
}


def render_pr_body(state: AVEState) -> str:
    finding = state.get("selected_finding") or {}
    decision = state.get("decision_record") or {}
    change: dict[str, Any] = state.get("prepared_change") or {}
    blast = change.get("blast_radius", {})
    ladder = state.get("verification", {})
    ready = bool(state.get("ready_to_merge"))

    lines: list[str] = []
    lines.append(f"# AVE fix: {change.get('summary', '(no change)')}")
    lines.append("")
    lines.append(
        f"**Finding** `{finding.get('id')}` — {finding.get('kind')} "
        f"at `{finding.get('location')}`"
    )
    lines.append(
        f"**Target** `{state.get('target_ref')}` · pack `{state.get('target_ref_pack')}` · "
        f"policy `{state.get('policy_version')}`"
    )
    lines.append("")
    lines.append("## Why (decision record)")
    lines.append(str(decision.get("rationale") or "—"))
    predicate = decision.get("authorization", {}).get("predicate")
    lines.append(f"_Authorized by:_ {predicate or '—'}")
    lines.append("")
    lines.append("## Blast radius")
    lines.append(f"- changed symbol: `{blast.get('changed_symbol', '?')}`")
    lines.append(f"- callers: {', '.join(blast.get('callers', [])) or '—'}")
    lines.append(f"- rings: {', '.join(blast.get('rings', [])) or '—'}")
    lines.append("")
    lines.append("## Patch")
    lines.append("```diff")
    lines.append((change.get("patch") or "").rstrip("\n"))
    lines.append("```")
    lines.append("")
    lines.append("## Verification ladder")
    for key, label in _LADDER_LABELS.items():
        mark = "x" if ladder.get(key) else " "
        lines.append(f"- [{mark}] {label}")
    lines.append("")
    lines.append(f"**Ready to merge: {'yes' if ready else 'no'}**")
    lines.append("")
    return "\n".join(lines)
