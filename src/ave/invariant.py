"""CI-side re-validation of the invariant, independent of the in-graph gate.

The invariant: *no PR is ready to merge without a green verification ladder (T0 build,
T1 flipped exploit oracle, T2 full suite, + re-attack) and a two-part decision record
citing the policy version.* CI re-checks this from the run record so it is enforced at a
second boundary — never by a prompt.

Scaffold (ticket 02): a runnable `--check` entrypoint that passes when there is no run
record to contradict the invariant. Ticket 05 wires it to the real run-record store.
"""

from __future__ import annotations

import argparse
import sys

from ave.records.run_record import RunRecord


def invariant_holds(record: RunRecord) -> bool:
    """A run record satisfies the invariant iff a ready-to-merge outcome is backed by a
    decision record. (The ladder detail is checked from spans in ticket 05.)"""
    if not record.ready_to_merge:
        return True  # nothing claimed -> invariant cannot be violated
    return record.decision_record_present


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-validate the AVE invariant.")
    parser.add_argument(
        "--check", action="store_true", help="Check and exit non-zero on violation."
    )
    args = parser.parse_args(argv)
    if not args.check:
        parser.print_help(sys.stderr)
        return 2

    # No run-record store yet (ticket 05). With nothing to contradict it, the invariant
    # holds vacuously — but the entrypoint is real so CI wiring is exercised now.
    violations: list[str] = []
    if violations:
        for v in violations:
            print(f"INVARIANT VIOLATION: {v}", file=sys.stderr)
        return 1
    print("invariant: OK (no run records to validate yet)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
