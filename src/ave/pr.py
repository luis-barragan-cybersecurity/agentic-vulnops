"""Render the PR body — "the PR is the product".

The reviewer-facing artifact every AVE run produces, in the shape ticket 06 locked and
ticket 09 lands. The order is the contract:

  1. **The attack exchange** — the *captured* request and the *actual* deny the oracle
     flipped to (a 404 stays a 404, never prettied into a 403).
  2. **The verification ladder table**, on the first screen. Honest empties: an unrun
     rung is never painted green.
  3. **The four blast-radius blocks** — what makes blast radius more than a caller
     graph: one fact + how-sure (1-5, or "unproven"); Still open with `file:line`;
     Cleared; Before-you-merge as runnable commands. All four are emitted by the same
     pass that measures files/dependents/routes (the pack's `blast_radius()`), so the
     renderer draws them from that dict and renders **honest empties** for any block the
     pass cannot fill yet — it never fabricates one.
  4. **The decision record collapsed** in `<details>`; rings one sentence.

Vetoed shapes stay out: no router/file-tree mermaid diagrams as "blast radius" — the
counts sit in a small table, and Still open / Cleared are tables, not pictures. The
patch rides in `<details>` after the record (the PR's own diff view is the primary
rendering; the body carries the pack's caveat when the patch is a model, not an
applicable diff).
"""

from __future__ import annotations

from typing import Any

from ave.policy import load_policy
from ave.state import AVEState

# Rung key -> (label, one-line meaning). Order is the ladder's order.
_LADDER_ROWS: list[tuple[str, str]] = [
    ("t0_build", "T0 — target builds"),
    ("t1_exploit_oracle_flipped", "T1 — exploit oracle flipped (green → red)"),
    ("t2_full_suite", "T2 — target's own suite"),
    ("reattack_clean", "Re-attack — original attack replayed post-fix"),
]

_NOT_CAPTURED = (
    "> **Exchange not captured by this run.** The exploit oracle ran through the pack's "
    "harness, which proves the flip but does not record a request/response transcript. "
    "When Execute/Verify run the bound by-path oracle in the target's own environment, "
    "the captured request and the actual deny render here verbatim — a 404 stays a 404."
)


def _oracle_ref(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence")
    oracle = evidence.get("oracle", {}) if isinstance(evidence, dict) else {}
    if not isinstance(oracle, dict) or not oracle.get("path"):
        return ""
    test = oracle.get("test")
    return f"{oracle['path']}::{test}" if test else str(oracle["path"])


def _endpoint(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence")
    endpoint = evidence.get("endpoint") if isinstance(evidence, dict) else None
    return str(endpoint) if endpoint else ""


def _attack_exchange(finding: dict[str, Any], change: dict[str, Any]) -> list[str]:
    """Section 1 — the captured request and the actual deny. Honest empty until the
    harness that captures a real transcript exists; never a fabricated one."""
    lines = ["## The attack, and the deny that replaced it", ""]
    exchange = change.get("attack_exchange")
    if isinstance(exchange, dict) and exchange.get("request"):
        lines.append("Captured while the target was vulnerable:")
        lines.append("")
        lines.append("```http")
        lines.append(str(exchange["request"]).rstrip("\n"))
        lines.append("")
        lines.append(str(exchange.get("before_response", "")).rstrip("\n"))
        lines.append("```")
        lines.append("")
        lines.append("The same request after this fix — the actual deny, unprettied:")
        lines.append("")
        lines.append("```http")
        lines.append(str(exchange.get("after_response", "")).rstrip("\n"))
        lines.append("```")
    else:
        lines.append(_NOT_CAPTURED)
        lines.append("")
        facts: list[str] = []
        endpoint = _endpoint(finding)
        if endpoint:
            facts.append(f"- Endpoint under attack: `{endpoint}`")
        oracle = _oracle_ref(finding)
        if oracle:
            facts.append(
                f"- Bound exploit oracle (inverted polarity): `{oracle}` — it *passes* "
                "by succeeding at the attack, so a fix must flip it red."
            )
        facts.append(
            "- What this run proved: see **T1** in the ladder below — the flip is the "
            "evidence, and nothing beyond it is claimed."
        )
        lines.extend(facts)
    lines.append("")
    return lines


def _ladder(finding: dict[str, Any], ladder: dict[str, Any], ready: bool) -> list[str]:
    """Section 2 — the ladder table, first screen, honest empties for unrun rungs."""
    oracle = _oracle_ref(finding)
    lines = ["## Verification ladder", ""]
    lines.append("| Rung | Status | Evidence |")
    lines.append("|---|---|---|")
    for key, label in _LADDER_ROWS:
        green = bool(ladder.get(key))
        status = "✅" if green else "⬜ not green"
        evidence = "—"
        if key == "t1_exploit_oracle_flipped" and green and oracle:
            evidence = f"`{oracle}` flipped green → red"
        lines.append(f"| {label} | {status} | {evidence} |")
    lines.append("")
    lines.append(
        "An unrun rung is never painted green — “⬜ not green” means the rung did not "
        "run or did not pass, and is not claimed."
    )
    lines.append("")
    lines.append(f"**Ready to merge: {'yes' if ready else 'no'}**")
    lines.append("")
    return lines


def _counts_table(blast: dict[str, Any], policy_version: str) -> list[str]:
    limits = load_policy().get("blast_radius", {})
    if not isinstance(limits, dict):
        limits = {}

    def cell(value: Any) -> str:
        return "unmeasured" if value is None else str(value)

    def limit(key: str) -> str:
        return str(limits[key]) if key in limits else "—"

    return [
        f"| Dimension | Measured | Limit (policy `{policy_version}`) |",
        "|---|---|---|",
        f"| Files changed | {cell(blast.get('files'))} | {limit('max_files')} |",
        f"| Dependent call sites | {cell(blast.get('dependents'))} "
        f"| {limit('max_dependents')} |",
        f"| Routes affected | {cell(blast.get('routes'))} | {limit('max_routes')} |",
    ]


def _one_fact(blast: dict[str, Any]) -> list[str]:
    lines = ["### The one fact", ""]
    fact = blast.get("fact")
    if isinstance(fact, dict) and fact.get("statement"):
        how_sure = fact.get("how_sure", "unproven")
        sure = f"{how_sure}/5" if isinstance(how_sure, int) else str(how_sure)
        lines.append(str(fact["statement"]))
        lines.append("")
        lines.append(f"*How sure: **{sure}** — {fact.get('proof', 'no proof step given')}*")
    else:
        lines.append(
            "**Unproven.** The blast-radius pass that emits this fact with a proof step "
            "does not exist yet; no claim is made in its place."
        )
    lines.append("")
    return lines


def _still_open(
    findings: list[dict[str, Any]], selected: dict[str, Any]
) -> list[str]:
    """Other instances this run surfaced and this PR does not fix. Drawn from the run's
    own finding sources only — never from the catalog's answer key."""
    lines = ["### Still open", ""]
    others = [f for f in findings if f.get("id") != selected.get("id")]
    if others:
        lines.append("| Instance | Where |")
        lines.append("|---|---|")
        for f in others:
            lines.append(f"| `{f.get('id', '?')}` | `{f.get('location', '?')}` |")
    else:
        lines.append(
            "This run's finding sources surfaced no other instances. (v1 surfaces the "
            "loop anchor only; the find-stage fills this block from what it actually "
            "finds — the catalog's answer key stays off this path.)"
        )
    lines.append("")
    return lines


def _cleared(blast: dict[str, Any]) -> list[str]:
    lines = ["### Cleared", ""]
    cleared = blast.get("cleared")
    if isinstance(cleared, list) and cleared:
        lines.append("| Ruled out | How |")
        lines.append("|---|---|")
        for item in cleared:
            if isinstance(item, dict):
                lines.append(
                    f"| {item.get('ruled_out', '?')} | {item.get('how', '?')} |"
                )
    else:
        lines.append(
            "Nothing was checked-and-ruled-out by this run, so nothing is listed. "
            "(Fills with the find-stage blast-radius pass.)"
        )
    lines.append("")
    return lines


def _before_you_merge(blast: dict[str, Any]) -> list[str]:
    lines = ["### Before you merge", ""]
    commands = blast.get("before_you_merge")
    if isinstance(commands, list) and commands:
        lines.append("Runnable by the reviewer, and allowed to fail:")
        lines.append("")
        for item in commands:
            if not isinstance(item, dict) or not item.get("command"):
                continue
            expect = item.get("expect")
            if expect:
                lines.append(f"```bash\n# expect: {expect}\n{item['command']}\n```")
            else:
                lines.append(f"```bash\n{item['command']}\n```")
    else:
        lines.append(
            "No reviewer-runnable commands were emitted for this change — none are "
            "invented in their place."
        )
    lines.append("")
    return lines


def _blast_radius_blocks(
    finding: dict[str, Any],
    findings: list[dict[str, Any]],
    blast: dict[str, Any],
    policy_version: str,
) -> list[str]:
    """Section 3 — the counts table plus the four blocks that make blast radius more
    than a caller graph."""
    lines = ["## Blast radius", ""]
    lines.extend(_counts_table(blast, policy_version))
    lines.append("")
    lines.extend(_one_fact(blast))
    lines.extend(_still_open(findings, finding))
    lines.extend(_cleared(blast))
    lines.extend(_before_you_merge(blast))
    return lines


def _decision_details(decision: dict[str, Any]) -> list[str]:
    """Section 4 — the two-part record, collapsed; rings one sentence."""
    response = decision.get("response", {})
    execution = decision.get("execution", {})
    citations = decision.get("citations", {})
    ring_plan = execution.get("ring_plan") or []
    rings = " → ".join(f"`{r}`" for r in ring_plan) if ring_plan else "`(none)`"

    lines: list[str] = []
    lines.append(
        f"**Rings:** this change is planned for {rings}; each advance is gated by the "
        "policy's stop criteria, and the last named ring is the last one executed."
    )
    lines.append("")
    lines.append("<details>")
    lines.append(
        "<summary><b>Decision record</b> (two-part: response × execution) — CI "  # noqa: RUF001
        "re-derives this from <code>policy.yaml</code></summary>"
    )
    lines.append("")
    lines.append("**Part 1 — Response decision**")
    lines.append(f"- Classification: {response.get('classification', '—')}")
    lines.append(
        f"- Disposition: **{response.get('disposition', '—')}** · "
        f"Severity: {response.get('severity', '—')}"
    )
    lines.append(f"- Remediation: {response.get('remediation', '—')}")
    lines.append(f"- Scope (the class removed): {response.get('scope', '—')}")
    lines.append("")
    lines.append("**Part 2 — Execution route**")
    route = execution.get("route", "—")
    hitl_route = execution.get("hitl_route")
    lines.append(
        f"- Route: **{route}**"
        + (f" · HITL route fired: **{hitl_route}**" if hitl_route else " · HITL route fired: none")
    )
    lines.append(f"- Rule matched: `{decision.get('rule_matched', '—')}`")
    radius = execution.get("blast_radius", {})
    lines.append(
        f"- Blast radius (measured): files {radius.get('files')} / dependents "
        f"{radius.get('dependents')} / routes {radius.get('routes')}"
    )
    ladder_required = execution.get("verification_ladder_required") or []
    lines.append(
        "- Ladder required: " + (", ".join(f"`{r}`" for r in ladder_required) or "—")
    )
    lines.append(f"- Decided by: {decision.get('decided_by', '—')} "
                 f"at {decision.get('decided_at', '—')}")
    lines.append("")
    lines.append(f"Rationale: {decision.get('rationale', '—')}")
    lines.append("")
    lines.append(
        f"Cites: policy `{decision.get('policy_version', '—')}` · oracle "
        f"`{citations.get('oracle', '—')}` · ground truth "
        f"`{citations.get('ground_truth', '—')}`"
    )
    lines.append("")
    lines.append("</details>")
    lines.append("")
    return lines


def _patch_details(change: dict[str, Any]) -> list[str]:
    patch = (change.get("patch") or "").rstrip("\n")
    if not patch:
        return []
    lines = ["<details>", "<summary><b>Patch</b></summary>", ""]
    caveat = change.get("patch_caveat")
    if caveat:
        lines.append(f"> {caveat}")
        lines.append("")
    lines.append("```diff")
    lines.append(patch)
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    return lines


def render_pr_body(state: AVEState) -> str:
    """Emit the PR body in the locked order from (run record material, decision record,
    blast-radius output) as threaded through the final graph state."""
    finding: dict[str, Any] = dict(state.get("selected_finding") or {})
    findings: list[dict[str, Any]] = [dict(f) for f in state.get("findings") or []]
    decision: dict[str, Any] = state.get("decision_record") or {}
    change: dict[str, Any] = state.get("prepared_change") or {}
    blast: dict[str, Any] = change.get("blast_radius") or {}
    ladder: dict[str, Any] = dict(state.get("verification") or {})
    ready = bool(state.get("ready_to_merge"))
    policy_version = str(state.get("policy_version", "unset"))
    run_id = str(state.get("run_record_id", "unset"))

    lines: list[str] = []
    lines.append(f"# AVE fix: {change.get('summary', '(no change)')}")
    lines.append("")
    lines.append(
        f"**Finding** `{finding.get('id')}` — {finding.get('kind')} at "
        f"`{finding.get('location')}`"
    )
    lines.append(
        f"**Target** `{state.get('target_ref')}` · pack `{state.get('target_ref_pack')}` "
        f"· policy `{policy_version}`"
    )
    lines.append("")
    lines.extend(_attack_exchange(finding, change))
    lines.extend(_ladder(finding, ladder, ready))
    lines.extend(_blast_radius_blocks(finding, findings, blast, policy_version))
    lines.extend(_decision_details(decision))
    lines.extend(_patch_details(change))
    lines.append("---")
    lines.append(
        f"*Generated by AVE from run `{run_id}`. No fix is claimed, ever — the ladder "
        "and the record above are what “fixed” means.*"
    )
    lines.append("")
    return "\n".join(lines)
