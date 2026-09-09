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

import json
import re
from typing import Any, cast
from urllib.parse import unquote_plus

from ave.findings import all_sources
from ave.policy import load_policy
from ave.state import AVEState, Finding, PinnedExploitResult

# Rung key -> (label, one-line meaning). Order is the ladder's order.
_LADDER_ROWS: list[tuple[str, str]] = [
    ("t0_build", "T0 — target builds"),
    ("t1_exploit_oracle_flipped", "T1 — exploit oracle flipped (green → red)"),
    ("t2_full_suite", "T2 — target's own suite"),
    ("reattack_clean", "Re-attack — original attack replayed post-fix"),
]

_NOT_CAPTURED = (
    "> **Exchange not captured by this run.** No complete, validated HTTP request and "
    "response pair is available. The ladder below shows what this run proved; no "
    "transcript is inferred."
)

# The captured attack exchange is untrusted input, even from AVE's own pinned-env harness:
# it is HTTP text that ends up inside the public PR body verbatim. The renderer fail-closes
# — a captured exchange is rendered ONLY when it is a complete, secret-free, injection-free
# transcript. Anything else falls back to "not captured" rather than leaking a header or
# breaking out of the fenced block. (The harness redacts at capture; this is the independent
# second gate at the boundary.)
_EXCHANGE_FIELDS: tuple[str, ...] = ("request", "before_response", "after_response")
_EXCHANGE_MAX_FIELD_LEN = 4000
_FENCE = "```"
_SECRET_HEADERS: tuple[str, ...] = (
    "authorization:",
    "proxy-authorization:",
    "cookie:",
    "set-cookie:",
    "api-key:",
    "x-api-key:",
    "x-auth-token:",
    "x-access-token:",
)
_BEARER = "bearer "
_CREDENTIAL_KEYS = {
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "apikey",
    "clientsecret",
    "jwt",
    "authorization",
    "proxyauthorization",
    "xapikey",
    "xauthtoken",
    "xaccesstoken",
    "password",
    "secret",
    "session",
    "cookie",
}
_PINNED_PR_REASON: dict[str, str] = {
    "not_flipped": "Pinned execution completed, but the generated patch did not flip the oracle.",
    "unavailable": "Pinned execution was requested but the environment is not available.",
    "launch_failed": "Pinned execution was requested but the environment failed to launch.",
    "patch_failed": "Pinned execution was requested but the generated patch did not apply.",
    "test_failed": "Pinned execution was requested but the capture harness failed.",
    "malformed": "Pinned execution was requested but the capture was malformed.",
    "unsafe_capture": "Pinned execution was requested but the capture failed the redaction gate.",
}


def _has_disallowed_control(value: str) -> bool:
    return any(
        (ord(ch) < 32 or 127 <= ord(ch) <= 159) and ch not in "\r\n\t"
        for ch in value
    )


def _is_credential_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return normalized in _CREDENTIAL_KEYS


def _query_or_form_credentials(value: str) -> bool:
    return any(
        _is_credential_key(match.group(1))
        for match in re.finditer(
            r"(?:^|[?&#;\s])([A-Za-z0-9_.-]+)=",
            unquote_plus(value),
        )
    )


def _walk_credential_keys(obj: Any) -> bool:
    if isinstance(obj, dict):
        for key, child in obj.items():
            if _is_credential_key(str(key)):
                return True
            if _walk_credential_keys(child):
                return True
        return False
    if isinstance(obj, list):
        return any(_walk_credential_keys(item) for item in obj)
    return False


def _json_credential_fields(value: str) -> bool:
    if any(
        _is_credential_key(match.group(1))
        for match in re.finditer(r'"([^"]+)"\s*:', value)
    ):
        return True
    candidates = [value]
    parts = re.split(r"\r?\n\r?\n", value, maxsplit=1)
    if len(parts) == 2:
        candidates.append(parts[1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if _walk_credential_keys(parsed):
            return True
    return False


def _field_is_unsafe(value: str) -> bool:
    if _has_disallowed_control(value) or _FENCE in value:
        return True
    lowered = value.lower()
    if any(header in lowered for header in _SECRET_HEADERS) or _BEARER in lowered:
        return True
    if _query_or_form_credentials(value):
        return True
    return _json_credential_fields(value)


def _safe_attack_exchange(change: dict[str, Any]) -> dict[str, str] | None:
    """Return the captured exchange only if it is safe to render verbatim, else None.

    Independent renderer gate. Fences, disallowed control characters, secret-bearing
    headers, bearer values, query/form credential keys, and structured JSON credential
    fields reject the whole exchange. The rejected value is not rendered.
    """
    exchange = change.get("attack_exchange")
    if not isinstance(exchange, dict):
        return None
    cleaned: dict[str, str] = {}
    for key in _EXCHANGE_FIELDS:
        value = exchange.get(key)
        if not isinstance(value, str):
            return None
        stripped = value.strip("\n")
        if not stripped.strip() or len(value) > _EXCHANGE_MAX_FIELD_LEN:
            return None
        if _field_is_unsafe(value):
            return None
        cleaned[key] = stripped
    return cleaned


def _found_by(finding: dict[str, Any]) -> str:
    sources = all_sources(cast("Finding", finding))
    text = f"found by `{sources[0]}`"
    if len(sources) > 1:
        text += ", corroborated by " + ", ".join(f"`{s}`" for s in sources[1:])
    return text


def _selection(finding: dict[str, Any], rationale: dict[str, Any]) -> list[str]:
    """Why *this* finding, out of everything the run ingested. Quotes the run's own
    recorded rationale and never reconstructs one."""
    if not rationale:
        return [
            "**Selected** without a recorded selection rationale — this run did not say "
            "why this finding was chosen.",
        ]
    candidates = rationale.get("candidates", "?")
    noun = "finding" if candidates == 1 else "findings"
    lines = [
        f"**Selected** 1 of {candidates} ingested {noun} — "
        f"{rationale.get('why', 'no reason recorded')}; {_found_by(finding)}.",
        f"*Rank function: {rationale.get('rank_function', 'unstated')}; dependents "
        f"measured for {rationale.get('dependents_measured', '?')} of {candidates}.*",
    ]
    return lines


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


def _captured_transcript(safe: dict[str, str], *, flipped: bool) -> list[str]:
    lines = [
        "The pinned runner captured this exchange verbatim:",
        "",
        "**The attack request**",
        "```http",
        safe["request"],
        "```",
        "",
        "**Before the generated patch, the target answered:**",
        "```http",
        safe["before_response"],
        "```",
        "",
    ]
    if flipped:
        lines.append("**After the generated patch, the same request is denied:**")
    else:
        lines.append("**After the generated patch, the target answered:**")
    lines.extend(["```http", safe["after_response"], "```", ""])
    return lines


def _attack_exchange(
    finding: dict[str, Any],
    change: dict[str, Any],
    pinned: PinnedExploitResult | None = None,
) -> list[str]:
    flipped = bool(
        pinned is not None
        and pinned.get("status") == "success"
        and pinned.get("flipped")
    )
    heading = (
        "## The attack exchange"
        if pinned is not None and pinned.get("status") == "not_flipped"
        else "## The attack, and the deny that replaced it"
    )
    lines = [heading, ""]
    safe = _safe_attack_exchange(change)
    if safe is not None:
        lines.extend(_captured_transcript(safe, flipped=flipped))
    else:
        lines.append(_NOT_CAPTURED)
        lines.append("")
        status = pinned.get("status") if pinned is not None else None
        reason = _PINNED_PR_REASON.get(str(status), "") if status else ""
        if reason:
            lines.append(f"> **{reason}**")
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
    facts.append("- What this run proved appears in the verification ladder below.")
    lines.extend(facts)
    lines.append("")
    return lines


def _ladder(
    finding: dict[str, Any],
    ladder: dict[str, Any],
    ready: bool,
    pinned: PinnedExploitResult | None,
) -> list[str]:
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
            if pinned is not None and pinned.get("status") == "success":
                evidence = f"`{oracle}` flipped after the generated patch"
            else:
                evidence = (
                    "hermetic in-process model flipped; generated patch was not "
                    "executed by this run"
                )
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


def _measurement(value: Any) -> str:
    return "unmeasured" if value is None else str(value)


def _counts_table(blast: dict[str, Any], policy_version: str) -> list[str]:
    policy = load_policy()
    current_version = str(policy.get("version", "unset"))
    limits = policy.get("blast_radius", {}) if current_version == policy_version else {}
    if not isinstance(limits, dict):
        limits = {}

    def limit(key: str) -> str:
        return str(limits[key]) if key in limits else "—"

    lines = [
        f"| Dimension | Measured | Limit (policy `{policy_version}`) |",
        "|---|---|---|",
        f"| Files changed | {_measurement(blast.get('files'))} | {limit('max_files')} |",
        f"| Dependent call sites | {_measurement(blast.get('dependents'))} "
        f"| {limit('max_dependents')} |",
        f"| Routes affected | {_measurement(blast.get('routes'))} "
        f"| {limit('max_routes')} |",
    ]
    if current_version != policy_version:
        lines.extend(
            [
                "",
                f"> Limits unavailable: run cites policy `{policy_version}`; current "
                f"checkout has `{current_version}`.",
            ]
        )
    return lines


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
            "**Unproven.** This run emitted no measured blast-radius fact, so no claim "
            "is made in its place."
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
        lines.append("| Instance | Where | Found by |")
        lines.append("|---|---|---|")
        for f in others:
            sources = ", ".join(f"`{s}`" for s in all_sources(cast("Finding", f)))
            lines.append(f"| `{f.get('id', '?')}` | `{f.get('location', '?')}` | {sources} |")
    else:
        lines.append(
            "This run's finding sources surfaced no other instances. (v1 surfaces the "
            "loop anchor only; the find-stage fills this block from what it actually "
            "finds — the catalog's answer key stays off this path.)"
        )
    lines.append("")
    return lines


def _escape_md_cell(value: object) -> str:
    """Escape model-authored table cells so pipes, newlines, and raw HTML cannot break
    the PR body. Citation validation does not make Markdown safe."""
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _ruled_out_rows(finding: dict[str, Any]) -> list[tuple[str, str]]:
    evidence = finding.get("evidence")
    review = evidence.get("counter_review") if isinstance(evidence, dict) else None
    if not isinstance(review, dict) or review.get("basis") != "validated":
        return []
    rows: list[tuple[str, str]] = []
    for hypothesis in review.get("hypotheses") or []:
        if not isinstance(hypothesis, dict) or hypothesis.get("kind") != "ruled_out":
            continue
        claim = str(hypothesis.get("claim", "")).strip()
        if not claim:
            continue
        rows.append((claim, _hypothesis_how(hypothesis)))
    return rows


def _hypothesis_how(hypothesis: dict[str, Any]) -> str:
    citations = hypothesis.get("citations") or []
    if not isinstance(citations, list) or not citations:
        return "cited at the cull boundary"
    first = citations[0] if isinstance(citations[0], dict) else {}
    file = first.get("file", "?")
    start = first.get("start_line", "?")
    end = first.get("end_line", start)
    span = f"{file}:{start}" if start == end else f"{file}:{start}-{end}"
    contains = first.get("contains", "")
    return f"`{span}` — {contains}"


def _cleared(finding: dict[str, Any]) -> list[str]:
    lines = ["### Cleared", ""]
    rows = _ruled_out_rows(finding)
    if rows:
        lines.append("| Ruled out | How |")
        lines.append("|---|---|")
        for ruled_out, how in rows:
            lines.append(f"| {_escape_md_cell(ruled_out)} | {_escape_md_cell(how)} |")
    else:
        lines.append(
            "Nothing was checked-and-ruled-out by this run, so nothing is listed."
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
    lines.extend(_cleared(finding))
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
        f"**Rings:** planned for {rings}. This run does not execute deployment rings or "
        "enforce their stop criteria."
    )
    lines.append("")
    lines.append("<details>")
    lines.append(
        "<summary><b>Decision record</b> (two-part: response × execution)</summary>"  # noqa: RUF001
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
        f"- Blast radius: files {_measurement(radius.get('files'))} / dependents "
        f"{_measurement(radius.get('dependents'))} / routes "
        f"{_measurement(radius.get('routes'))}"
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
    pinned = state.get("pinned_exploit")

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
    lines.extend(_selection(finding, dict(state.get("selection_rationale") or {})))
    lines.append("")
    lines.extend(_attack_exchange(finding, change, pinned))
    lines.extend(_ladder(finding, ladder, ready, pinned))
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
