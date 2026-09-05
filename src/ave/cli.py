"""AVE command-line entrypoint.

Backs the Makefile verbs and the `ave` console script.

  ave run         -> walk the seven-phase graph on one seeded instance, write artifacts
  ave break       -> report the semantic flaws already seeded in the target (demo step 1)
  ave eradicate   -> break -> run -> HITL approve -> PR (demo steps 1-3)
  ave scoreboard  -> regenerate the results table from run records (demo step 4)

The walking skeleton (ticket 03) makes `run` real end to end: it walks all seven phases
and writes a run record + PR bundle under `results/runs/<id>/`. Ticket 04 pointed the pack
at the real vendored target (`target/catalog.json`, 8 authorization instances). `run`
drives the one instance the pack declares, the anchor I-04, on a hermetic oracle; the
other seven stay ground truth for scoring. The HITL gate is in the graph; the CLI
auto-approves and does not pause. `break` and `scoreboard` stay thin until the
metrics/schema work (ticket 05).
"""

from __future__ import annotations

import argparse
import os

from ave.policy.loader import policy_version
from ave.runner import persist_run, run_once
from ave.state import AVEState
from ave.telemetry import setup_tracing


def _pinned_env_opt_in() -> bool:
    """Opt into the pinned-env exploit runner from the environment. Off by default, so a
    machine without the target's pinned Poetry env behaves exactly as before (the hermetic
    oracle drives the loop and the attack exchange stays 'not captured')."""
    return os.environ.get("AVE_PINNED_ENV", "").strip().lower() in ("1", "true", "yes")


def _run(_: argparse.Namespace) -> int:
    tracer = setup_tracing()
    with tracer.start_as_current_span("ave.run"):
        initial: AVEState = {
            "target_ref": "target/dvrestaurant@d32d0997",
            "policy_version": policy_version(),
            "use_pinned_env": _pinned_env_opt_in(),
        }
        print("run: walking seven phases; HITL gate auto-approves (no pause).")
        final = run_once(initial, auto_approve=True)
        artifacts = persist_run(final)
    print("run complete.")
    print(f"  human_approved = {final.get('human_approved')}")
    print(f"  ready_to_merge = {final.get('ready_to_merge')}")
    print(f"  pr_ref         = {final.get('pr_ref')}")
    for name, path in artifacts.items():
        print(f"  {name:11} -> {path}")
    return 0


def _break(_: argparse.Namespace) -> int:
    print("break: the vendored target already carries the seeded catalog (target/CATALOG.md,")
    print("       8 authorization instances + decoys). `run` drives the BOLA anchor (I-04).")
    return 0


def _eradicate(args: argparse.Namespace) -> int:
    _break(args)
    print("eradicate: break then run. HITL gate auto-approves (no pause).")
    return _run(args)


def _scoreboard(_: argparse.Namespace) -> int:
    print("scoreboard: would regenerate the results table from run records (ticket 05).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ave", description="Autonomous Vulnerability Eradication."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, help_text in (
        ("run", _run, "walk the seven-phase graph on one seeded instance, write artifacts"),
        ("break", _break, "report the semantic flaws already seeded in the target"),
        ("eradicate", _eradicate, "break -> run -> HITL approve -> PR (demo)"),
        ("scoreboard", _scoreboard, "regenerate the results table from run records"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(handler=handler)

    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
