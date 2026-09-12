from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

#: The tool a session calls to end its turn-loop with a decision. Named here so the finder
#: loop and every client agree on the one call that terminates a session.
SUBMIT_VERDICT = "submit_verdict"

#: Environment switch: set truthy to reach the live model instead of the recorded fixtures.
#: Absent or falsey (the default, and CI) means fixtures only — no network.
LIVE_ENV = "AVE_LLM_LIVE"
#: Optional parent directory the live client records fresh transcripts into. Live turns
#: land at ``<AVE_LLM_RECORD>/<stage>/<candidate-slug>.json`` (``llm_finder`` or
#: ``llm_cull``).
RECORD_ENV = "AVE_LLM_RECORD"


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation the model asked for: the tool's name and its arguments.

    `tool_use_id` is Anthropic's live tool-use id. Fixture JSON omits it; the live loop
    must echo the real id on the tool result or the API rejects the turn.
    """

    name: str
    arguments: dict[str, Any]
    tool_use_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": self.name, "arguments": dict(self.arguments)}
        if self.tool_use_id:
            payload["tool_use_id"] = self.tool_use_id
        return payload

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ToolCall:
        return ToolCall(
            name=str(data["name"]),
            arguments=dict(data.get("arguments", {})),
            tool_use_id=str(data.get("tool_use_id", "")),
        )


@dataclass(frozen=True)
class ToolResult:
    """The result of one executed tool call, fed back to the model as the next turn's
    context. `content` is JSON text — what the model reads to plan its next call."""

    call: ToolCall
    content: str


@runtime_checkable
class ModelSession(Protocol):
    """One candidate's live conversation. Stateless *across* candidates by construction:
    a session is opened per candidate and never sees another candidate's turns."""

    def respond(self, results: Sequence[ToolResult]) -> list[ToolCall]:
        """Return the next batch of tool calls, given the previous turn's results (empty on
        the first turn). A batch containing the session's terminal tool ends the session;
        an empty batch means the model declined to continue and no verdict was reached."""
        ...


@runtime_checkable
class ModelClient(Protocol):
    """Opens a fresh session per candidate. The finder depends only on this."""

    @property
    def name(self) -> str:
        """A short label for the client behind the seam (``fixture`` / ``anthropic``),
        recorded so a run says whether it replayed fixtures or reached the live model."""
        ...

    def begin(
        self,
        *,
        candidate_id: str,
        system: str,
        user: str,
        tools: Sequence[dict[str, Any]],
        terminal_tool: str = SUBMIT_VERDICT,
    ) -> ModelSession:
        """Open a stateless session for `candidate_id`.

        `terminal_tool` is the call that ends the session and, on the live client,
        flushes the recorded transcript.
        """
        ...


# -- Fixture client (the default: recorded, offline) --------------------------------


def fixture_slug(candidate_id: str) -> str:
    """A filesystem-safe name for one candidate's recorded transcript. Reversible enough to
    stay traceable to the handler id it came from."""
    return candidate_id.replace("/", "__").replace(":", "--") + ".json"


class _FixtureSession:
    """Replays a recorded transcript: `turns[i]` is returned on the i-th `respond`, the
    executed tool results ignored (they are already baked into what the recording chose to
    do next). Running out of turns returns an empty batch — a recording that never submitted
    a verdict, which the finder treats as no verdict."""

    def __init__(self, turns: list[list[ToolCall]]):
        self._turns = turns
        self._index = 0

    def respond(self, results: Sequence[ToolResult]) -> list[ToolCall]:
        if self._index >= len(self._turns):
            return []
        batch = self._turns[self._index]
        self._index += 1
        return batch


@dataclass(frozen=True)
class FixtureModelClient:
    """Replays transcripts recorded under `fixtures_dir`, one JSON file per candidate.

    The file shape is ``{"turns": [[{"name", "arguments"}, ...], ...]}`` — an ordered list
    of tool-call batches. A missing fixture is an error, not a silent no-op: the finder
    asked to judge a candidate the offline path has no recording for, and guessing would
    hide the gap."""

    fixtures_dir: Path
    name: str = "fixture"

    def begin(
        self,
        *,
        candidate_id: str,
        system: str,
        user: str,
        tools: Sequence[dict[str, Any]],
        terminal_tool: str = SUBMIT_VERDICT,
    ) -> ModelSession:
        del system, user, tools, terminal_tool
        path = self.fixtures_dir / fixture_slug(candidate_id)
        if not path.exists():
            raise FileNotFoundError(
                f"no recorded model transcript for {candidate_id!r} at {path}. "
                f"Record one with {LIVE_ENV}=1, or regenerate the fixtures."
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        turns = [
            [ToolCall.from_dict(call) for call in batch]
            for batch in data.get("turns", [])
        ]
        return _FixtureSession(turns)


# -- Live client (reached only on explicit opt-in) ----------------------------------


class _AnthropicSession:
    """A real Claude session over the Messages API tool loop. Imported lazily so the
    package needs no `anthropic` dependency to run offline; every turn is appended to the
    transcript so a live run can be recorded back to a fixture."""

    def __init__(
        self,
        *,
        client: Any,
        model: str,
        system: str,
        user: str,
        tools: Sequence[dict[str, Any]],
        record_to: Path | None,
        terminal_tool: str = SUBMIT_VERDICT,
    ):
        self._client = client
        self._model = model
        self._system = system
        self._tools = list(tools)
        self._messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
        self._transcript: list[list[ToolCall]] = []
        self._record_to = record_to
        self._terminal_tool = terminal_tool

    def respond(self, results: Sequence[ToolResult]) -> list[ToolCall]:
        if results:
            self._messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": _tool_use_id(r.call),
                            "content": r.content,
                        }
                        for r in results
                    ],
                }
            )
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=self._system,
            tools=self._tools,
            messages=self._messages,
        )
        self._messages.append({"role": "assistant", "content": response.content})
        calls = [
            ToolCall(
                name=block.name,
                arguments=dict(block.input),
                tool_use_id=str(getattr(block, "id", "") or ""),
            )
            for block in response.content
            if getattr(block, "type", None) == "tool_use"
        ]
        self._transcript.append(calls)
        if self._record_to is not None and any(
            c.name == self._terminal_tool for c in calls
        ):
            self._flush()
        return calls

    def _flush(self) -> None:
        if self._record_to is None:
            return
        self._record_to.parent.mkdir(parents=True, exist_ok=True)
        self._record_to.write_text(
            json.dumps(
                {"turns": [[c.to_dict() for c in batch] for batch in self._transcript]},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )


def _tool_use_id(call: ToolCall) -> str:
    if call.tool_use_id:
        return call.tool_use_id
    raise ValueError(
        f"live tool result for {call.name!r} is missing Anthropic's tool-use id"
    )


@dataclass(frozen=True)
class AnthropicModelClient:
    """The live client — reached only when `AVE_LLM_LIVE` is set. Lazily constructs an
    Anthropic client so the import cost and the dependency are paid only on opt-in."""

    model: str = "claude-sonnet-5"
    record_dir: Path | None = None
    name: str = "anthropic"

    def begin(
        self,
        *,
        candidate_id: str,
        system: str,
        user: str,
        tools: Sequence[dict[str, Any]],
        terminal_tool: str = SUBMIT_VERDICT,
    ) -> ModelSession:
        import anthropic  # lazy: offline runs never import this

        record_to = (
            self.record_dir / fixture_slug(candidate_id)
            if self.record_dir is not None
            else None
        )
        return _AnthropicSession(
            client=anthropic.Anthropic(),
            model=self.model,
            system=system,
            user=user,
            tools=tools,
            record_to=record_to,
            terminal_tool=terminal_tool,
        )


def record_root_for(record: str, fixtures_dir: Path) -> Path:
    return Path(record) / fixtures_dir.name


def default_model_client(fixtures_dir: Path) -> ModelClient:
    if os.environ.get(LIVE_ENV, "").strip().lower() in ("1", "true", "yes"):
        record = os.environ.get(RECORD_ENV, "").strip()
        record_dir = record_root_for(record, fixtures_dir) if record else None
        return AnthropicModelClient(record_dir=record_dir)
    return FixtureModelClient(fixtures_dir=fixtures_dir)
