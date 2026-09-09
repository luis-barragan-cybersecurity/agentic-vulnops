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
    def from_dict(data: Any) -> Citation:
        if not isinstance(data, dict):
            raise CitationRejected(
                f"citation must be an object, got {type(data).__name__}"
            )
        file = data.get("file")
        contains = data.get("contains")
        if not isinstance(file, str) or not file.strip():
            raise CitationRejected("citation file must be a non-empty string")
        if not isinstance(contains, str) or not contains.strip():
            raise CitationRejected("citation contains must be a non-empty string")
        start = _require_line(data.get("start_line"), "start_line")
        end = _require_line(data.get("end_line"), "end_line")
        return Citation(
            file=file, start_line=start, end_line=end, contains=contains
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


def _require_line(value: Any, label: str) -> int:
    if type(value) is not int:
        raise CitationRejected(f"citation {label} must be an integer")
    return value


def _source_line_count(store: Any, file: str) -> int:
    try:
        source = store.get_source(file)
    except (PermissionError, FileNotFoundError, OSError) as exc:
        raise CitationRejected(f"cited file {file!r} is not readable: {exc}") from exc
    return len(source.splitlines())


def _validate_citation(store: Any, citation: Citation) -> None:
    line_count = _source_line_count(store, citation.file)
    if not (1 <= citation.start_line <= citation.end_line <= line_count):
        raise CitationRejected(
            f"citation span {citation.start_line}-{citation.end_line} is outside "
            f"1-{line_count} in {citation.file}"
        )
    source = store.get_source(citation.file, (citation.start_line, citation.end_line))
    needle = _normalize(citation.contains)
    if needle not in _normalize(source):
        raise CitationRejected(
            f"cited text {citation.contains!r} not found in "
            f"{citation.file}:{citation.start_line}-{citation.end_line}"
        )


def _normalize(text: str) -> str:
    return " ".join(text.split())
