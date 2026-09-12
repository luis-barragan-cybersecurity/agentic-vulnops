from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from ave.adapters.python_authz.cull import SUBMIT_REVIEW
from ave.adapters.python_authz.model import (
    LIVE_ENV,
    RECORD_ENV,
    SUBMIT_VERDICT,
    AnthropicModelClient,
    FixtureModelClient,
    ToolCall,
    ToolResult,
    default_model_client,
    fixture_slug,
)
from ave.adapters.python_authz.pack import CULL_FIXTURES_DIR, FIXTURES_DIR


def test_tool_call_fixture_json_omits_empty_tool_use_id() -> None:
    call = ToolCall.from_dict({"name": "get_source", "arguments": {"file": "app/x.py"}})
    assert call.tool_use_id == ""
    assert call.to_dict() == {"name": "get_source", "arguments": {"file": "app/x.py"}}


def test_tool_call_round_trips_a_recorded_tool_use_id() -> None:
    payload = {
        "name": "get_source",
        "arguments": {"file": "app/x.py"},
        "tool_use_id": "toolu_recorded_1",
    }
    assert ToolCall.from_dict(payload).to_dict() == payload


def test_anthropic_client_echoes_the_live_tool_use_id(monkeypatch: Any) -> None:
    live_id = "toolu_live_abc123"
    captured: list[dict[str, Any]] = []

    class _Messages:
        def create(self, **kwargs: Any) -> SimpleNamespace:
            captured.append({**kwargs, "messages": list(kwargs["messages"])})
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        type="tool_use",
                        name="get_source",
                        input={"file": "app/x.py"},
                        id=live_id,
                    )
                ]
            )

    monkeypatch.setitem(
        sys.modules,
        "anthropic",
        SimpleNamespace(Anthropic=lambda: SimpleNamespace(messages=_Messages())),
    )
    session = AnthropicModelClient().begin(
        candidate_id="app/x.py:handler",
        system="system",
        user="user",
        tools=[],
    )
    calls = session.respond([])
    assert calls == [
        ToolCall(name="get_source", arguments={"file": "app/x.py"}, tool_use_id=live_id)
    ]

    session.respond([ToolResult(call=calls[0], content='{"source": ""}')])
    messages = cast("list[dict[str, Any]]", captured[1]["messages"])
    assert messages[-1]["content"] == [
        {"type": "tool_result", "tool_use_id": live_id, "content": '{"source": ""}'}
    ]


def test_live_tool_result_without_anthropic_id_raises(monkeypatch: Any) -> None:
    class _Messages:
        def create(self, **kwargs: Any) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        type="tool_use",
                        name="get_source",
                        input={"file": "app/x.py", "_tool_use_id": "smuggled"},
                        id="",
                    )
                ]
            )

    monkeypatch.setitem(
        sys.modules,
        "anthropic",
        SimpleNamespace(Anthropic=lambda: SimpleNamespace(messages=_Messages())),
    )
    session = AnthropicModelClient().begin(
        candidate_id="app/x.py:handler",
        system="system",
        user="user",
        tools=[],
    )
    calls = session.respond([])
    assert calls[0].tool_use_id == ""
    with pytest.raises(ValueError, match="missing Anthropic's tool-use id"):
        session.respond([ToolResult(call=calls[0], content='{"source": ""}')])


def test_cull_terminal_live_session_writes_under_namespaced_root(
    tmp_path: Path, monkeypatch: Any
) -> None:
    candidate_id = "app/x.py:handler"
    slug = fixture_slug(candidate_id)

    class _Messages:
        def create(self, **kwargs: Any) -> SimpleNamespace:
            del kwargs
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        type="tool_use",
                        name=SUBMIT_REVIEW,
                        input={"stance": "keep"},
                        id="toolu_cull_1",
                    )
                ]
            )

    monkeypatch.setitem(
        sys.modules,
        "anthropic",
        SimpleNamespace(Anthropic=lambda: SimpleNamespace(messages=_Messages())),
    )
    monkeypatch.setenv(LIVE_ENV, "1")
    monkeypatch.setenv(RECORD_ENV, str(tmp_path))
    cull_client = default_model_client(CULL_FIXTURES_DIR)
    finder_client = default_model_client(FIXTURES_DIR)
    assert isinstance(cull_client, AnthropicModelClient)
    assert isinstance(finder_client, AnthropicModelClient)
    assert cull_client.record_dir == tmp_path / "llm_cull"
    assert finder_client.record_dir == tmp_path / "llm_finder"
    assert cull_client.record_dir != finder_client.record_dir

    session = cull_client.begin(
        candidate_id=candidate_id,
        system="system",
        user="user",
        tools=[],
        terminal_tool=SUBMIT_REVIEW,
    )
    session.respond([])
    cull_path = tmp_path / "llm_cull" / slug
    finder_path = tmp_path / "llm_finder" / slug
    assert cull_path.is_file()
    assert not finder_path.exists()
    recorded = json.loads(cull_path.read_text(encoding="utf-8"))
    assert recorded["turns"][0][0]["name"] == SUBMIT_REVIEW
    assert cull_path != finder_path


def test_missing_fixture_names_a_model_transcript(tmp_path: Path) -> None:
    client = FixtureModelClient(fixtures_dir=tmp_path)
    with pytest.raises(FileNotFoundError, match="model transcript"):
        client.begin(
            candidate_id="app/x.py:handler",
            system="system",
            user="user",
            tools=[],
            terminal_tool=SUBMIT_VERDICT,
        )
