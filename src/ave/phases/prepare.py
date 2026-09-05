"""Phase 5 — Prepare.

After the human approves at the gate, prepare the class-level change — a fix that removes
the whole class of the flaw, not one instance — via the language pack's fix template. The
change carries a real unified-diff patch and its blast radius. No finding selected => no
change (the loop stays honest).

When the run opts in (`use_pinned_env`) **and** the pack can stand up the target's pinned
environment, this phase also runs the selected instance's by-path oracle in that env and
threads the captured attack exchange into `prepared_change["attack_exchange"]` — so the PR
body's opener renders a verbatim transcript instead of "not captured". The full result is
kept in `pinned_exploit` for Verify to read (`flipped` becomes T1). Absent the opt-in or the
env, nothing changes: the exchange stays uncaptured and Verify falls back to the hermetic
oracle. The capture never fabricates — a `ran=False` result leaves the exchange absent.
"""

from __future__ import annotations

from typing import Any

from ave.adapters import get_default_pack
from ave.adapters.base import PinnedEnvCapable
from ave.records.store import make_span, now_iso
from ave.state import AVEState


def prepare(state: AVEState) -> AVEState:
    started = now_iso()
    selected = state.get("selected_finding")
    pack = get_default_pack()
    change = pack.prepare_fix(selected) if selected is not None else None

    pinned: dict[str, Any] | None = None
    if (
        change is not None
        and selected is not None
        and state.get("use_pinned_env")
        and isinstance(pack, PinnedEnvCapable)
        and pack.pinned_env_available()
    ):
        pinned = dict(pack.run_pinned_exploit(selected))
        exchange = pinned.get("attack_exchange")
        if exchange is not None:
            change["attack_exchange"] = exchange

    return {
        "prepared_change": change,
        "pinned_exploit": pinned,
        "pr_ref": None,
        "spans": [
            make_span(
                "prepare",
                started,
                {
                    "prepared": change is not None,
                    "pinned_ran": bool(pinned and pinned.get("ran")),
                    "attack_exchange_captured": bool(
                        pinned and pinned.get("attack_exchange")
                    ),
                },
            )
        ],
    }
