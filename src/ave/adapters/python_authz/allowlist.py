"""The scan allowlist — enforced in code, never by prompt (ticket 23, decision 1).

The find stage may read the target's application source, and nothing else. The allowed
tree is ``target/dvrestaurant/app/`` **minus** ``app/tests/``, so the answer key —
``target/catalog.json``, ``target/CATALOG.md`` and every bound oracle under
``app/tests/vulns/`` — is *structurally* unreachable, not merely un-mentioned in a prompt.
This is the code half of the find-stage de-leak: ticket 22 rewrote the in-tree change-marks
so a file's own comments no longer name its instance; this module makes the files outside
the finder's tree impossible to open at all.

The boundary is the exact one ``tests/test_target_de_leak.py`` already pins token-free, so
the guarantee the guard test proves and the guarantee this allowlist enforces are the same
line drawn once.

Nothing here imports or executes target code — files are only ever opened as text for the
AST pass (`inventory`) and the source-serving tool (`code_facts.get_source`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# src/ave/adapters/python_authz/allowlist.py -> repo root is five parents up.
_REPO_ROOT = Path(__file__).resolve().parents[4]
_TARGET_APP = _REPO_ROOT / "target" / "dvrestaurant" / "app"

#: Files the finder is allowed to parse. Application source is Python; the tree also holds
#: Markdown/text the finder has no use for, so the finder allowlist is Python-only. A wider
#: suffix set would only enlarge the surface for no recall.
_FINDER_SUFFIXES = frozenset({".py"})


class AllowlistViolation(PermissionError):
    """A path outside the stage's allowlist was requested. Raised, never logged-and-skipped:
    a stage that reaches outside its tree is a bug in the stage, and the answer key sits
    exactly one directory outside the finder's."""


@dataclass(frozen=True)
class ScanAllowlist:
    """One stage's read boundary over the target tree.

    A stage reads only files that live under ``root``, are not under any ``excluded``
    subtree, and carry an allowed suffix. Membership is decided on resolved, absolute
    paths so ``..`` cannot walk out. The type is frozen and carries no open file handles —
    it is a *policy*, applied by `read_text` / `resolve`, not a sandbox.
    """

    name: str
    root: Path
    excluded: tuple[Path, ...]
    suffixes: frozenset[str]

    def _resolve(self, path: Path | str) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = _REPO_ROOT / candidate
        return candidate.resolve()

    def is_readable(self, path: Path | str) -> bool:
        """True iff `path` is inside this stage's tree, outside every excluded subtree, and
        carries an allowed suffix. Pure predicate — never raises, never reads the file."""
        resolved = self._resolve(path)
        if resolved.suffix not in self.suffixes:
            return False
        if not resolved.is_relative_to(self.root):
            return False
        return not any(resolved.is_relative_to(ex) for ex in self.excluded)

    def resolve(self, path: Path | str) -> Path:
        """The absolute path for `path`, or raise `AllowlistViolation` if it is off-limits.
        The one funnel every read goes through, so enforcement lives in exactly one place."""
        resolved = self._resolve(path)
        if not self.is_readable(resolved):
            raise AllowlistViolation(
                f"{self.name} allowlist forbids {path!r}: outside {self._rel(self.root)} "
                f"(minus {[self._rel(e) for e in self.excluded]}) or wrong suffix"
            )
        return resolved

    def read_text(self, path: Path | str) -> str:
        """Read an allowed file as UTF-8 text. The only way the find stage opens a target
        file; a forbidden path raises before any byte is read."""
        return self.resolve(path).read_text(encoding="utf-8")

    def files(self) -> list[Path]:
        """Every readable file under the allowlist, sorted — the inventory pass's input set
        and the coverage denominator's universe."""
        return sorted(
            p
            for p in self.root.rglob("*")
            if p.is_file() and self.is_readable(p)
        )

    def rel(self, path: Path | str) -> str:
        """A path rendered repo-relative — the stable form records and tools speak in."""
        return self._rel(self._resolve(path))

    @staticmethod
    def _rel(path: Path) -> str:
        try:
            return str(path.resolve().relative_to(_REPO_ROOT))
        except ValueError:
            return str(path)


def finder_allowlist() -> ScanAllowlist:
    """The find stage's allowlist: ``target/dvrestaurant/app/`` minus ``app/tests/``,
    Python only. The exact boundary `tests/test_target_de_leak.py` pins token-free."""
    return ScanAllowlist(
        name="finder",
        root=_TARGET_APP.resolve(),
        excluded=((_TARGET_APP / "tests").resolve(),),
        suffixes=_FINDER_SUFFIXES,
    )


def writer_allowlist() -> ScanAllowlist:
    """The exploit-writer allowlist: ``app/tests/`` minus ``app/tests/vulns/``, Python only."""
    tests = (_TARGET_APP / "tests").resolve()
    return ScanAllowlist(
        name="writer",
        root=tests,
        excluded=((tests / "vulns").resolve(),),
        suffixes=_FINDER_SUFFIXES,
    )
