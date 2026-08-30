"""The pure policy decision — `decide()` — the predicate machine `policy.yaml` describes.

AVE proposes a `(finding, FixPlan, BlastRadius)`; `decide()` consults the policy and returns
either `Autonomous` (standing preauthorization holds — the human at the interrupt() gate
reviews but need not act) or `Escalation` naming exactly one of the four HITL routes. It
never returns "merge": the verification ladder and the invariant do that.

`decide()` is **pure** — no I/O, no real clock (a timestamp is passed in), no PR side
effects. Same inputs yield the same `Decision`, so CI can re-derive the verdict from the
committed decision record. The clock, the PR, and the exploit oracle live in the
Execute/Verify nodes, never here. The shape is language- and vuln-family-neutral (D3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any

from ave.records.decision_record import DecisionRecord, ExecutionRoute, ResponseDecision
from ave.state import Finding

_LADDER_REQUIRED = [
    "t0_build",
    "t1_exploit_oracle_flipped",
    "t2_full_suite",
    "reattack_clean",
]


@dataclass
class FixPlan:
    """AVE's *proposed* remediation, before the concrete patch. The thing the policy's fix
    predicates are evaluated over. `changed_paths` are the repo-relative files the
    class-level fix would touch (glob-matched against the policy's allow/forbid lists)."""

    changed_paths: list[str] = field(default_factory=list)
    is_class_level: bool = False
    preserves_legitimate_access: bool = False


@dataclass
class BlastRadius:
    """Measured impact of the fix plan, in the policy's dimensions. Any `None` dimension
    means the radius could not be measured -> `unknown_blast_radius`."""

    files: int | None
    dependents: int | None
    routes: int | None


@dataclass
class Autonomous:
    """Standing preauthorization holds — the fix ships without a mandatory human ruling."""

    record: DecisionRecord


@dataclass
class Escalation:
    """One of the four HITL routes fired — a human must rule at the interrupt() gate."""

    route: str
    record_draft: DecisionRecord


Decision = Autonomous | Escalation


def _matches_glob(path: str, globs: list[str]) -> bool:
    return any(fnmatch(path, g) for g in globs)


def _helper_only(fix_plan: FixPlan, helper_only_diff: dict[str, Any]) -> bool:
    """Every changed path falls inside an allowed helper surface and none is forbidden."""
    allow = helper_only_diff.get("allow_globs", [])
    forbid = helper_only_diff.get("forbid_globs", [])
    if not fix_plan.changed_paths:
        return False
    return all(_matches_glob(p, allow) for p in fix_plan.changed_paths) and not any(
        _matches_glob(p, forbid) for p in fix_plan.changed_paths
    )


def _limit_breached(blast: BlastRadius, limits: dict[str, Any]) -> bool:
    """Does any *measured* dimension exceed its hard limit? Unmeasured (`None`) dimensions
    are skipped here — they are the `unknown_blast_radius` gate's business, not this one —
    so this stays total even when `require_all_dimensions_measured` is false."""
    checks = (
        (blast.files, "max_files"),
        (blast.dependents, "max_dependents"),
        (blast.routes, "max_routes"),
    )
    return any(
        value is not None and key in limits and value > limits[key]
        for value, key in checks
    )


# The rule a record cites: the grant on a standing decision, else the check that escalated.
_RULE_FOR_ROUTE = {
    "out_of_policy_change": "fix_predicates.require_all (a fix predicate failed)",
    "blast_radius_exceeded": "blast_radius.max_files/max_dependents/max_routes",
    "unknown_blast_radius": "blast_radius.require_all_dimensions_measured",
}


def _rule_matched(route_kind: str, hitl_route: str | None) -> str:
    if route_kind == "standing_preauthorized":
        return "helper_only_diff + class_level + within_blast_radius"
    return _RULE_FOR_ROUTE.get(hitl_route or "", "out_of_policy")


def decide(
    finding: Finding,
    fix_plan: FixPlan,
    blast: BlastRadius,
    policy: dict[str, Any],
    *,
    now: str,
) -> Decision:
    """Evaluate the policy over a proposed fix. PURE — no I/O, no real clock, no PR effects.

    Order matters: an unmeasured radius is asked about before an oversized one, and both
    before the fix-predicate check, because the human is asked a different question at each
    gate. Exactly one route is named on an `Escalation`.
    """
    require_all = _predicates_by_id(policy)
    limits = policy.get("blast_radius", {})

    def record(route_kind: str, hitl_route: str | None, decided_by: str) -> DecisionRecord:
        return _build_record(finding, fix_plan, blast, policy, route_kind, hitl_route,
                             decided_by, now)

    # unknown_blast_radius — a dimension could not be measured.
    if limits.get("require_all_dimensions_measured", True) and None in (
        blast.files, blast.dependents, blast.routes
    ):
        return Escalation(
            "unknown_blast_radius",
            record("hitl_approved", "unknown_blast_radius", "agent"),
        )

    # blast_radius_exceeded — a hard limit is breached. Compare only measured dimensions,
    # so a false `require_all_dimensions_measured` can't crash on a None (it escalates
    # elsewhere or ships); the assert above no longer guards this branch.
    if _limit_breached(blast, limits):
        return Escalation(
            "blast_radius_exceeded",
            record("hitl_approved", "blast_radius_exceeded", "agent"),
        )

    # out_of_policy_change — a fix predicate fails.
    helper_only = _helper_only(fix_plan, require_all.get("helper_only_diff", {}))
    if not (helper_only and fix_plan.is_class_level and fix_plan.preserves_legitimate_access):
        return Escalation(
            "out_of_policy_change",
            record("hitl_approved", "out_of_policy_change", "agent"),
        )

    # Standing preauthorization holds.
    return Autonomous(record("standing_preauthorized", None, "agent"))


def ring_stop_criterion(
    policy: dict[str, Any], ring: str, ladder_state: dict[str, bool]
) -> str | None:
    """The `before_execute` companion to `decide()`: does `ring`'s stop criterion hold?

    `decide()` answers the three `before_prepare` HITL routes; the fourth,
    `failed_stop_criterion`, gates advancing a change past a ring (policy section 4). Pure:
    given a ring name and the boolean ladder state (the verification rungs plus
    `decision_record_present` / `within_blast_radius`), return the route name if a required
    rung is unmet, else `None`. Unknown ring -> no criterion -> `None`.
    """
    spec = policy.get("rings", {}).get("stop_criteria", {}).get(ring)
    if not isinstance(spec, dict):
        return None
    for key in spec.get("require", []):
        if not ladder_state.get(key):
            return str(spec.get("on_fail", "failed_stop_criterion"))
    return None


def _predicates_by_id(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    preds = policy.get("fix_predicates", {}).get("require_all", [])
    return {p["id"]: p for p in preds if isinstance(p, dict) and "id" in p}


def _build_record(
    finding: Finding,
    fix_plan: FixPlan,
    blast: BlastRadius,
    policy: dict[str, Any],
    route_kind: str,
    hitl_route: str | None,
    decided_by: str,
    now: str,
) -> DecisionRecord:
    kind = finding.get("kind", "unknown")
    location = finding.get("location", "unknown")
    evidence = finding.get("evidence", {})
    oracle = evidence.get("oracle", {}) if isinstance(evidence, dict) else {}
    oracle_ref = oracle.get("path", "unknown") if isinstance(oracle, dict) else "unknown"

    standing = route_kind == "standing_preauthorized"
    return DecisionRecord(
        finding_id=finding.get("id", "unknown"),
        policy_version=str(policy.get("version", "unset")),
        rule_matched=_rule_matched(route_kind, hitl_route),
        response=ResponseDecision(
            classification=kind,
            disposition="fix",
            severity="high",
            # D3-neutral: describe the *shape* of the class-level fix, not the family's
            # remedy. The language-specific sentence ("guard non-owners", etc.) belongs to
            # the pack / PR body, never to this compounding core export.
            remediation=(
                f"Close the whole {kind} class at {location} in one class-level change, "
                f"not the single instance, without regressing legitimate access."
            ),
            scope=f"the whole {kind} class, not just {location}",
        ),
        execution=ExecutionRoute(
            route="standing_preauthorized" if standing else "hitl_approved",
            ring_plan=list(policy.get("rings", {}).get("order", ["caller", "pr"])),
            blast_radius={
                "files": blast.files,
                "dependents": blast.dependents,
                "routes": blast.routes,
            },
            verification_ladder_required=list(
                policy.get("verification_ladder", {}).get("require_all", _LADDER_REQUIRED)
            ),
            hitl_route=hitl_route,
        ),
        citations={
            "finding": finding.get("id", "unknown"),
            "oracle": oracle_ref,
            "ground_truth": f"catalog.ground_truth()#{finding.get('id', 'unknown')}",
        },
        rationale=(
            "Helper-only, class-level diff within blast-radius limits => the fix removes "
            "the class and cannot regress a legitimate caller."
            if standing
            else "Fix falls outside standing preauthorization; a human must rule at the gate."
        ),
        decided_by="agent" if decided_by == "agent" else "human",
        decided_at=now,
    )
