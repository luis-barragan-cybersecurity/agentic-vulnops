"""AVE command-line entrypoint.

Backs the Makefile verbs and the `ave` console script. Every command here is a **stub**
that exercises real structure (the graph builds and runs; tracing is on) without doing the
real work yet — later tickets fill each in.

  ave run         -> run the seven-phase graph on a seeded instance (stub loop)
  ave break       -> seed a semantic ownership flaw into the target (demo step 1)
  ave eradicate   -> break -> run -> HITL approve -> PR (demo steps 1-3)
  ave scoreboard  -> regenerate the results table from run records (demo step 4)
"""

from __future__ import annotations

import argparse

from ave.policy.loader import policy_version
from ave.runner import run_once
from ave.state import AVEState
from ave.telemetry import setup_tracing


def _run(_: argparse.Namespace) -> int:
    tracer = setup_tracing()
    with tracer.start_as_current_span("ave.run"):
        initial: AVEState = {
            "target_ref": "d32d0997",
            "policy_version": policy_version(),
        }
        print("run: pausing at the HITL interrupt() gate for approval... (stub auto-approves)")
        final = run_once(initial, auto_approve=True)
    print("run complete (stub).")
    print(f"  human_approved = {final.get('human_approved')}")
    print(f"  ready_to_merge = {final.get('ready_to_merge')}")
    print(f"  pr_ref         = {final.get('pr_ref')}")
    return 0


def _break(_: argparse.Namespace) -> int:
    print("break: would seed a semantic ownership flaw into the target (stub).")
    return 0


def _eradicate(args: argparse.Namespace) -> int:
    _break(args)
    print("eradicate: the money-shot demo pauses at the HITL interrupt() gate (stub).")
    return _run(args)


def _scoreboard(_: argparse.Namespace) -> int:
    print("scoreboard: would regenerate the results table from run records (stub).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ave", description="Autonomous Vulnerability Eradication."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, help_text in (
        ("run", _run, "run the seven-phase graph on a seeded instance (stub loop)"),
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
