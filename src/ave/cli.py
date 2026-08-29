"""AVE command-line entrypoint.

Backs the Makefile verbs and the `ave` console script.

  ave run         -> walk the seven-phase graph on one seeded instance, write artifacts
  ave break       -> seed a semantic ownership flaw into the target (demo step 1)
  ave eradicate   -> break -> run -> HITL approve -> PR (demo steps 1-3)
  ave scoreboard  -> regenerate the results table from run records (demo step 4)

The walking skeleton (ticket 03) makes `run` real end to end against the `python_authz`
pack's single synthetic instance: it walks all seven phases through the HITL gate and
writes a run record + PR bundle under `results/runs/<id>/`. `break` and `scoreboard`
stay thin until the real target (ticket 04) and the metrics/schema work (ticket 05).
"""

from __future__ import annotations

import argparse

from ave.policy.loader import policy_version
from ave.runner import persist_run, run_once
from ave.state import AVEState
from ave.telemetry import setup_tracing


def _run(_: argparse.Namespace) -> int:
    tracer = setup_tracing()
    with tracer.start_as_current_span("ave.run"):
        initial: AVEState = {
            "target_ref": "skeleton://python_authz/bola-order-owner",
            "policy_version": policy_version(),
        }
        print("run: walking Intake..Decide, pausing at the HITL interrupt() gate...")
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
    print("break: would seed a semantic ownership flaw into the real target (ticket 04).")
    print("       the skeleton run uses the python_authz pack's built-in BOLA instance.")
    return 0


def _eradicate(args: argparse.Namespace) -> int:
    _break(args)
    print("eradicate: the money-shot demo pauses at the HITL interrupt() gate.")
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
        ("break", _break, "seed a semantic ownership flaw into the target (demo step 1)"),
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
