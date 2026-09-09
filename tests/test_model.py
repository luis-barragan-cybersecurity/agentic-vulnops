"""The model seam: fixture JSON stays compatible, live tool results echo Anthropic's id."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any, cast

from ave.adapters.python_authz.model import (
    AnthropicModelClient,
    ToolCall,
    ToolResult,
)


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
    """The live client must return Anthropic's tool-use id on the next tool_result.

    Fabricating a placeholder id is what made live finder sessions fail while fixture
    replay stayed green.
    """
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
