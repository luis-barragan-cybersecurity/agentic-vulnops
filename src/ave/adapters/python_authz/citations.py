from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


class CitationRejected(Exception):
    """A submitted citation or identity claim failed at the validation boundary."""


@dataclass(frozen=True)
class Citation:
    file: str
    start_line: int
    end_line: int
    contains: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Citation:
        return Citation(
            file=str(data["file"]),
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            contains=str(data.get("contains", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "contains": self.contains,
        }


def require_identity(submitted: str, expected: str, *, label: str) -> None:
    if submitted != expected:
        raise CitationRejected(
            f"{label} {submitted!r} is not the judged {expected!r}"
        )


def validate_citations(store: Any, citations: Sequence[Citation]) -> None:
    if not citations:
        raise CitationRejected("at least one citation is required")
    for citation in citations:
        _validate_citation(store, citation)


def _validate_citation(store: Any, citation: Citation) -> None:
    if citation.end_line < citation.start_line:
        raise CitationRejected(
            f"citation span {citation.start_line}-{citation.end_line} is inverted"
        )
    try:
        source = store.get_source(citation.file, (citation.start_line, citation.end_line))
    except (PermissionError, FileNotFoundError, OSError) as exc:
        raise CitationRejected(
            f"cited file {citation.file!r} is not readable: {exc}"
        ) from exc
    needle = _normalize(citation.contains)
    if not needle:
        raise CitationRejected("a citation must claim text (contains) to check")
    if needle not in _normalize(source):
        raise CitationRejected(
            f"cited text {citation.contains!r} not found in "
            f"{citation.file}:{citation.start_line}-{citation.end_line}"
        )


def _normalize(text: str) -> str:
    return " ".join(text.split())
