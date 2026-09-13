from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import pytest

from ave.adapters import get_default_pack
from ave.adapters.python_authz import catalog
from ave.adapters.python_authz._binding import BindingConflict, BindingError, _ExploitBinder
from ave.adapters.python_authz.llm_finder import OWNERSHIP_GAP, ROLE_GAP
from ave.adapters.python_authz.pack import _PATCH_REL
from ave.phases.verify import verify
from ave.state import Finding

_GET_ORDER = catalog.anchor_location()
_UPDATE_PROFILE = "app/apis/auth/services/update_profile_service.py:update_profile"
_HANDLER = {"method": "GET", "path": "/orders/{order_id}"}


def _finding(
    *,
    location: str = _GET_ORDER,
    kind: str = OWNERSHIP_GAP,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    return cast(
        "Finding",
        {
            "id": "ave-llm-get_order_service-get_order",
            "kind": kind,
            "location": location,
            "confidence": 0.9,
            "source": "ave:llm-finder",
            "evidence": evidence if evidence is not None else {"handler": dict(_HANDLER)},
        },
    )


def _binder(tmp_path: Path) -> _ExploitBinder:
    binder = _ExploitBinder(patch_rel=_PATCH_REL)
    binder.bind_run(tmp_path)
    return binder


def test_ensure_bound_writes_bound_file_and_returns_stamp(tmp_path: Path) -> None:
    binder = _binder(tmp_path)
    stamp = binder.ensure_bound(_finding())
    expected = tmp_path / "bound" / "_ave_bound.py"
    assert expected.is_file()
    assert stamp["test"] == "test_authorization_boundary"
    assert stamp["path"].endswith("bound/_ave_bound.py")
    source = expected.read_text(encoding="utf-8")
    assert "def test_authorization_boundary" in source
    assert re.search(r"AVE_FINDING_FINGERPRINT = ['\"].+['\"]", source)


def test_generated_source_stays_off_the_answer_key(tmp_path: Path) -> None:
    binder = _binder(tmp_path)
    binder.ensure_bound(_finding())
    source = (tmp_path / "bound" / "_ave_bound.py").read_text(encoding="utf-8")
    assert "vulns/" not in source
    assert "ave_seed_" not in source
    assert "catalog.json" not in source
    assert "_ave_capture_" not in source


def test_same_bytes_second_ensure_bound_is_a_noop(tmp_path: Path) -> None:
    binder = _binder(tmp_path)
    finding = _finding()
    first = binder.ensure_bound(finding)
    path = tmp_path / "bound" / "_ave_bound.py"
    before = path.read_bytes()
    mtime = path.stat().st_mtime_ns
    second = binder.ensure_bound(finding)
    assert second == first
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == mtime


def test_different_existing_bytes_raise_and_leave_file(tmp_path: Path) -> None:
    binder = _binder(tmp_path)
    path = tmp_path / "bound" / "_ave_bound.py"
    path.parent.mkdir(parents=True)
    path.write_text("# not a bound exploit\n", encoding="utf-8")
    with pytest.raises(BindingConflict):
        binder.ensure_bound(_finding())
    assert path.read_text(encoding="utf-8") == "# not a bound exploit\n"


def test_interrupted_valid_file_returns_stamp_without_rewrite(tmp_path: Path) -> None:
    binder = _binder(tmp_path)
    first = binder.ensure_bound(_finding())
    path = tmp_path / "bound" / "_ave_bound.py"
    written = path.read_text(encoding="utf-8")
    mtime = path.stat().st_mtime_ns
    finding = _finding()
    assert "oracle" not in finding["evidence"]
    stamp = binder.ensure_bound(finding)
    assert stamp == first
    assert path.read_text(encoding="utf-8") == written
    assert path.stat().st_mtime_ns == mtime


def test_read_stamp_rejects_missing_wrong_and_escaped(tmp_path: Path) -> None:
    binder = _binder(tmp_path)
    finding = _finding()
    stamp = binder.ensure_bound(finding)
    finding["evidence"]["oracle"] = stamp
    assert binder.read_stamp(finding) == stamp

    missing = _finding()
    with pytest.raises(BindingError):
        binder.read_stamp(missing)

    wrong_test = _finding(evidence={"handler": dict(_HANDLER), "oracle": {**stamp, "test": "nope"}})
    with pytest.raises(BindingError):
        binder.read_stamp(wrong_test)

    outside = _finding(
        evidence={
            "handler": dict(_HANDLER),
            "oracle": {"path": "/tmp/not-under-run-root.py", "test": "test_authorization_boundary"},
        }
    )
    with pytest.raises(BindingError):
        binder.read_stamp(outside)

    vanished = _finding(evidence={"handler": dict(_HANDLER), "oracle": dict(stamp)})
    (tmp_path / "bound" / "_ave_bound.py").unlink()
    with pytest.raises(BindingError):
        binder.read_stamp(vanished)


def test_can_drive_is_finishability_without_oracle() -> None:
    pack = get_default_pack()
    assert pack.can_drive(_finding()) is True
    assert pack.can_drive(_finding(location=_UPDATE_PROFILE)) is False
    assert pack.can_drive(_finding(kind=ROLE_GAP)) is False
    assert pack.can_drive(_finding(evidence={})) is False
    smuggled = _finding(
        location=_UPDATE_PROFILE,
        evidence={
            "handler": {"method": "PUT", "path": "/profile"},
            "oracle": {"path": "app/tests/x.py", "test": "t"},
            "is_loop_anchor": True,
        },
    )
    assert pack.can_drive(smuggled) is False


def test_blast_radius_oracle_command_copies_into_target_tests() -> None:
    pack = get_default_pack()
    finding = _finding(
        evidence={
            "handler": dict(_HANDLER),
            "oracle": {
                "path": "results/runs/abc/bound/_ave_bound.py",
                "test": "test_authorization_boundary",
            },
        }
    )
    command = pack.blast_radius(finding)["before_you_merge"][0]["command"]
    assert command == (
        "cp results/runs/abc/bound/_ave_bound.py "
        "target/dvrestaurant/app/tests/_ave_bound.py && "
        "cd target/dvrestaurant && poetry run pytest "
        "app/tests/_ave_bound.py::test_authorization_boundary"
    )


def test_prepare_fix_stamps_oracle_and_emits_get_order_patch(tmp_path: Path) -> None:
    pack = get_default_pack()
    pack.bind_run(tmp_path)
    finding = _finding()
    change = pack.prepare_fix(finding)
    assert finding["evidence"]["oracle"] == {
        "path": finding["evidence"]["oracle"]["path"],
        "test": "test_authorization_boundary",
    }
    assert finding["evidence"]["oracle"]["test"] == "test_authorization_boundary"
    assert finding["evidence"]["oracle"]["path"].endswith("bound/_ave_bound.py")
    assert "current_user.id" in change["patch"]
    assert _PATCH_REL in change["patch"]


def test_find_does_not_stamp_oracle_or_loop_anchor() -> None:
    batch = get_default_pack().find("target/dvrestaurant@d32d0997")
    for finding in batch.kept:
        evidence = finding.get("evidence") or {}
        assert "oracle" not in evidence
        assert "is_loop_anchor" not in evidence


def test_unpinned_verify_t1_is_false_without_run_exploit(tmp_path: Path) -> None:
    pack = get_default_pack()
    pack.bind_run(tmp_path)
    finding = _finding()
    change = pack.prepare_fix(finding)
    out = verify({"selected_finding": finding, "prepared_change": change})
    assert out["verification"]["t1_exploit_oracle_flipped"] is False
    assert pack.run_exploit(finding, fixed=False) is True
