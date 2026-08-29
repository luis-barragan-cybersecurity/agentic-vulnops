"""The invariant holds structurally: a ready-to-merge outcome requires a decision record."""

from __future__ import annotations

from pytest import CaptureFixture

from ave.invariant import invariant_holds, main
from ave.records.run_record import RunRecord


def _record(*, ready: bool, has_record: bool) -> RunRecord:
    return RunRecord(
        run_id="r0",
        target_ref="d32d0997",
        policy_version="0",
        ready_to_merge=ready,
        decision_record_present=has_record,
    )


def test_nothing_claimed_is_always_valid() -> None:
    assert invariant_holds(_record(ready=False, has_record=False)) is True


def test_ready_without_decision_record_violates() -> None:
    assert invariant_holds(_record(ready=True, has_record=False)) is False


def test_ready_with_decision_record_holds() -> None:
    assert invariant_holds(_record(ready=True, has_record=True)) is True


def test_ci_entrypoint_passes_with_no_records(capsys: CaptureFixture[str]) -> None:
    assert main(["--check"]) == 0
    assert capsys.readouterr().out == "invariant: OK (no run records to validate yet)\n"


def test_without_check_flag_does_not_run_ci_mode(capsys: CaptureFixture[str]) -> None:
    # --check is the CI switch: without it, do not print the vacuous OK or exit 0.
    assert main([]) == 2
    captured = capsys.readouterr()
    assert "invariant: OK" not in captured.out
    assert "--check" in captured.err or "--check" in captured.out
