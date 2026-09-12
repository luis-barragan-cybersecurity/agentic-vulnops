"""Shared retrieval schemas and dispatch used by the finder and the cull."""

from __future__ import annotations

import json

import pytest

from ave.adapters.python_authz.code_facts import CodeFactsStore
from ave.adapters.python_authz.cull import CULL_TOOL_SCHEMAS
from ave.adapters.python_authz.llm_finder import TOOL_SCHEMAS
from ave.adapters.python_authz.model import ToolCall
from ave.adapters.python_authz.tools import (
    CULL_RETRIEVAL,
    FINDER_RETRIEVAL,
    dispatch_retrieval,
    execute_retrieval,
    line_range,
    retrieval_schemas,
)

_FILE = "target/dvrestaurant/app/apis/orders/services/get_order_service.py"


def test_finder_schemas_include_list_candidates_and_cull_schemas_do_not() -> None:
    finder_names = [schema["name"] for schema in retrieval_schemas(FINDER_RETRIEVAL)]
    cull_names = [schema["name"] for schema in retrieval_schemas(CULL_RETRIEVAL)]
    assert finder_names == [
        "get_handler",
        "get_source",
        "model_definition",
        "callers_of",
        "list_candidates",
    ]
    assert cull_names == [
        "get_handler",
        "get_source",
        "model_definition",
        "callers_of",
    ]
    assert "list_candidates" in [schema["name"] for schema in TOOL_SCHEMAS]
    assert "list_candidates" not in [schema["name"] for schema in CULL_TOOL_SCHEMAS]


def test_cull_dispatch_rejects_list_candidates() -> None:
    content = dispatch_retrieval(
        CodeFactsStore.build(),
        ToolCall("list_candidates", {}),
        allowed=CULL_RETRIEVAL,
    )
    assert json.loads(content) == {"error": "unknown tool 'list_candidates'"}


def test_finder_dispatch_lists_examine_candidates() -> None:
    content = dispatch_retrieval(
        CodeFactsStore.build(),
        ToolCall("list_candidates", {}),
        allowed=FINDER_RETRIEVAL,
    )
    payload = json.loads(content)
    assert isinstance(payload, list)
    assert payload
    assert {"handler_id", "method", "path"} <= set(payload[0])


def test_null_line_range_is_a_json_tool_error() -> None:
    result = execute_retrieval(
        CodeFactsStore.build(),
        ToolCall("get_source", {"file": _FILE, "start_line": None, "end_line": 3}),
        allowed=CULL_RETRIEVAL,
    )
    payload = json.loads(result.content)
    assert "error" in payload
    assert "integer" in payload["error"]


def test_line_range_rejects_bool_float_and_string() -> None:
    with pytest.raises(ValueError, match="integer"):
        line_range({"start_line": True, "end_line": 1})
    with pytest.raises(ValueError, match="integer"):
        line_range({"start_line": 1.0, "end_line": 1})
    with pytest.raises(ValueError, match="integer"):
        line_range({"start_line": "1", "end_line": 1})
    assert line_range({"start_line": 2, "end_line": 4}) == (2, 4)
    assert line_range({"file": _FILE}) is None
