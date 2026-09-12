"""Many findings in, one remediated out — the neutral core of the run shape.

`match()` fans in every finding source a run consults, `assess()` remediates exactly one
of them, and the run record keeps an honest lifecycle for the rest. The three
responsibilities here are language-neutral (D3), so they live in the core once rather than
in every pack:

  1. **Attribution** — every finding names the source that produced it (`ave:<finder>` for
     AVE's own, `sarif:<tool>` for an external feed). The scoreboard reports recall *per
     source*, so an external feed must never inflate AVE's own number.
  2. **De-dup merge** — findings from different sources that name the same flaw fold into
     one, keeping *both* sources and the higher confidence. The identity is
     `(location key, kind)`. Reading a location into a stable `file:symbol` is the one
     language-specific step, so that is the pack's (`LanguagePack.dedup_key`); the
     grouping and the fold are core.
  3. **Ranked head selection** — a thin, deterministic, *stated* rank function picks the
     one finding this run drives and says why, in a rationale the run record and the PR
     body carry verbatim. It is the placeholder M3's risk-based prioritisation replaces;
     it is not a scoring model.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any, cast

from ave.state import Finding

#: Stamped on a finding whose producer set no `source`. A named value rather than a blank,
#: so a forgotten attribution is *visible* in the run record and the PR body.
UNATTRIBUTED_SOURCE = "unattributed"

#: The rank function, stated once and quoted verbatim into the run record and the PR body
#: so a reader never infers it from behaviour. Fewer measured dependents rank *first*:
#: the smallest blast radius is the safest change to drive autonomously in one run.
RANK_FUNCTION = (
    "confidence desc → measured dependents asc (unmeasured last) → location asc → "
    "ingest order"
)

#: finding id -> measured dependent call sites (None = unmeasured).
Dependents = Mapping[str, int | None]


def all_sources(finding: Finding) -> list[str]:
    """Every source that stands behind `finding`: the primary first, then the sources a
    merge folded in, sorted. This is what per-source recall counts."""
    primary = str(finding.get("source") or UNATTRIBUTED_SOURCE)
    folded = sorted({str(s) for s in finding.get("corroborated_by", []) if s != primary})
    return [primary, *folded]


def attribute(findings: Iterable[Finding], *, default_source: str) -> list[Finding]:
    """Backfill `source` on any finding whose producer left it unset; findings that already
    carry one pass through unchanged."""
    out: list[Finding] = []
    for finding in findings:
        if finding.get("source"):
            out.append(finding)
        else:
            out.append(cast("Finding", {**finding, "source": default_source}))
    return out


def merge_findings(
    findings: Iterable[Finding], *, location_key: Callable[[Finding], str]
) -> list[Finding]:
    """Fold findings that name the same flaw into one.

    Identity is `(location_key(finding), kind)`. Within a group the highest `confidence`
    wins, ties to first-seen; every losing finding's sources land in the winner's
    `corroborated_by`. Output keeps first-seen order so a later ingest-order tie-break is
    stable.
    """
    winners: dict[tuple[str, str], Finding] = {}
    order: list[tuple[str, str]] = []
    for finding in findings:
        key = (location_key(finding), str(finding.get("kind", "")))
        current = winners.get(key)
        if current is None:
            winners[key] = finding
            order.append(key)
            continue
        if _confidence(finding) > _confidence(current):
            winner, loser = finding, current
        else:
            winner, loser = current, finding
        primary = str(winner.get("source") or UNATTRIBUTED_SOURCE)
        folded = set(winner.get("corroborated_by", [])) | set(all_sources(loser))
        folded.discard(primary)
        merged: dict[str, Any] = {**winner, "corroborated_by": sorted(folded)}
        evidence = _union_evidence(winner, loser)
        if evidence is not None:
            merged["evidence"] = evidence
        winners[key] = cast("Finding", merged)
    return [winners[key] for key in order]


def _union_evidence(winner: Finding, loser: Finding) -> dict[str, Any] | None:
    winner_ev = winner.get("evidence")
    loser_ev = loser.get("evidence")
    winner_dict = dict(winner_ev) if isinstance(winner_ev, dict) else {}
    loser_dict = loser_ev if isinstance(loser_ev, dict) else {}
    if not winner_dict and not loser_dict:
        return None
    merged = dict(winner_dict)
    if isinstance(loser_dict, dict):
        for key, value in loser_dict.items():
            if key not in merged:
                merged[key] = value
    return merged


def rank_findings(
    findings: Iterable[Finding], *, dependents: Dependents | None = None
) -> list[Finding]:
    """Order findings by `RANK_FUNCTION`. `dependents` carries what the blast-radius pass
    measured; absent means nothing was, and the dependents term is inert."""
    measured: Dependents = dependents or {}

    def key(item: tuple[int, Finding]) -> tuple[float, int, int, str, int]:
        index, finding = item
        count = measured.get(str(finding.get("id")))
        return (
            -_confidence(finding),
            0 if count is not None else 1,
            count if count is not None else 0,
            str(finding.get("location", "")),
            index,
        )

    return [finding for _, finding in sorted(enumerate(findings), key=key)]


def select_head(
    findings: Iterable[Finding], *, dependents: Dependents | None = None
) -> tuple[Finding | None, dict[str, Any]]:
    """Pick the one finding this run remediates, and say why.

    The rationale is plain data the run record and the PR body quote: the rank function
    itself, how many candidates it ranked, how many had a measured dependents count, and
    the full ranking with each candidate's sources.
    """
    measured: Dependents = dependents or {}
    ranked = rank_findings(findings, dependents=measured)
    head = ranked[0] if ranked else None
    rationale: dict[str, Any] = {
        "rank_function": RANK_FUNCTION,
        "candidates": len(ranked),
        "dependents_measured": sum(
            1 for f in ranked if measured.get(str(f.get("id"))) is not None
        ),
        "selected": head.get("id") if head is not None else None,
        "why": _why(ranked, measured),
        "ranking": [
            {
                "id": f.get("id"),
                "confidence": _confidence(f),
                "dependents": measured.get(str(f.get("id"))),
                "location": f.get("location"),
                "sources": all_sources(f),
            }
            for f in ranked
        ],
    }
    return head, rationale


def _confidence(finding: Finding) -> float:
    value = finding.get("confidence")
    return float(value) if isinstance(value, (int, float)) else 0.0


def _why(ranked: list[Finding], measured: Dependents) -> str:
    """One sentence naming the rank term that separated the head from the runner-up."""
    if not ranked:
        return "no findings were ingested"
    if len(ranked) == 1:
        return "the only finding this run ingested"
    head, runner_up = ranked[0], ranked[1]
    head_conf, runner_conf = _confidence(head), _confidence(runner_up)
    if head_conf > runner_conf:
        return f"highest confidence ({head_conf:g} against {runner_conf:g} for the runner-up)"
    head_deps = measured.get(str(head.get("id")))
    runner_deps = measured.get(str(runner_up.get("id")))
    if head_deps != runner_deps:
        if runner_deps is None:
            return f"fewest measured dependents ({head_deps}; the runner-up is unmeasured)"
        return f"fewest measured dependents ({head_deps} against {runner_deps})"
    if str(head.get("location", "")) != str(runner_up.get("location", "")):
        return "confidence and dependents tied with the runner-up; first location in sort order"
    return "confidence, dependents and location tied with the runner-up; first ingested"
