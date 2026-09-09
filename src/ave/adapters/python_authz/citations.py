"""Shared citation identity for the pack's model verdicts.

The finder and the adversarial cull both accept a structured claim only when its citations
resolve through the code-facts store and name the record or finding under review. A
resolvable *other* handler is still a rejection: accepted identity is the judged candidate,
not any id the store happens to know.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


class CitationRejected(Exception):
    """A submitted citation or identity claim failed at the validation boundary."""


@dataclass(frozen=True)
class Citation:
    """One evidence reference a verdict must stand behind: a source span and the text it
    claims is there. Validated against the store before the verdict is accepted."""

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
    """Reject a claim that names a different identity than the one under review.

    Resolution of the submitted id is not enough. The judged record is the trusted
    identity; a different but resolvable handler is still a miss.
    """
    if submitted != expected:
        raise CitationRejected(
            f"{label} {submitted!r} is not the judged {expected!r}"
        )


def validate_citations(store: Any, citations: Sequence[Citation]) -> None:
    """Reject an empty citation list or any span that does not contain its claimed text."""
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
    """Collapse whitespace so a citation's `contains` need not reproduce indentation.

    The claim is about what the line says, not its column.
    """
    return " ".join(text.split())
