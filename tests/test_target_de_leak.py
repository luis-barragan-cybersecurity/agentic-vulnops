"""The target's application source must not carry the benchmark answer key.

AVE's finder reads ``target/dvrestaurant/app/`` minus ``app/tests/``. The GPL-3.0 §5
change-marks in that tree may say a file was modified, by whom and when — never which
catalog instance, vulnerability class, oracle or intent (build ticket 22). The substance
stays in ``target/CATALOG.md`` and the ``app/tests/vulns/`` oracles, outside that tree.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_APP = _REPO / "target" / "dvrestaurant" / "app"
_TESTS = _APP / "tests"

# Tokens that would let a reader "rediscover" a seeded instance from its label.
_LEAK = re.compile(r"BOLA|BFLA|AVE-seeded|I-0\d|benchmark|deliberately|CATALOG")


def _finder_readable() -> list[Path]:
    return sorted(
        p
        for p in _APP.rglob("*")
        if p.is_file() and _TESTS not in p.parents and p.suffix in {".py", ".md", ".txt"}
    )


def test_finder_readable_tree_is_non_empty() -> None:
    assert len(_finder_readable()) > 20


def test_no_answer_key_tokens_in_finder_readable_source() -> None:
    hits: list[str] = []
    for path in _finder_readable():
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if _LEAK.search(line):
                hits.append(f"{path.relative_to(_REPO)}:{n}: {line.strip()}")
    assert hits == [], "\n".join(hits)


def test_modified_files_still_carry_a_dated_section5_mark() -> None:
    """De-leaking must not silently drop the GPL-3.0 §5 obligation."""
    marked = [
        _APP / "apis" / "referrals" / "service.py",
        _APP / "apis" / "menu" / "services" / "update_menu_item_service.py",
    ]
    for path in marked:
        head = "\n".join(path.read_text().splitlines()[:3])
        assert "§5" in head and "2026-08-29" in head and "target/README.md" in head, path
