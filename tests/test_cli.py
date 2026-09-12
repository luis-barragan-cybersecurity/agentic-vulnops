from __future__ import annotations

import pytest

from ave.cli import main


def test_find_prints_finder_and_cull_stage_lines(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["find"]) == 0
    out = capsys.readouterr().out
    assert "finder: 8 accepted, 7 finder-cleared, 0 rejected, 0 exhausted." in out
    assert "adversarial-cull: 8 reviewed, 8 kept, 0 suppressed, 0 fail-open." in out
    assert "  8 findings, 7 cleared," not in out


def test_find_help_names_both_stages(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["-h"])
    assert exc.value.code == 0
    assert "LLM finder and adversarial cull" in capsys.readouterr().out
