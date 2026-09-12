from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from ave.adapters.python_authz.code_facts import HandlerNotFound
from ave.adapters.python_authz.model import ToolCall, ToolResult

_RETRIEVAL_SCHEMAS: dict[str, dict[str, Any]] = {
    "get_handler": {
        "name": "get_handler",
        "description": "The full inventory record for a handler id (file:symbol).",
        "input_schema": {
            "type": "object",
            "properties": {"handler_id": {"type": "string"}},
            "required": ["handler_id"],
        },
    },
    "get_source": {
        "name": "get_source",
        "description": (
            "Source of an allowlisted file, comments stripped. Optional inclusive 1-based "
            "line range."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["file"],
        },
    },
    "model_definition": {
        "name": "model_definition",
        "description": "A data model's owner-column facts and source.",
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    "callers_of": {
        "name": "callers_of",
        "description": "Every call site of a symbol across the allowlisted tree.",
        "input_schema": {
            "type": "object",
            "properties": {"symbol": {"type": "string"}},
            "required": ["symbol"],
        },
    },
    "list_candidates": {
        "name": "list_candidates",
        "description": "The handler ids the pre-filter kept for judgement (screen=examine).",
        "input_schema": {"type": "object", "properties": {}},
    },
}

FINDER_RETRIEVAL = (
    "get_handler",
    "get_source",
    "model_definition",
    "callers_of",
    "list_candidates",
)
CULL_RETRIEVAL = (
    "get_handler",
    "get_source",
    "model_definition",
    "callers_of",
)


def retrieval_schemas(names: Sequence[str]) -> list[dict[str, Any]]:
    return [_RETRIEVAL_SCHEMAS[name] for name in names]


def execute_retrieval(
    store: Any, call: ToolCall, *, allowed: Sequence[str]
) -> ToolResult:
    try:
        content = dispatch_retrieval(store, call, allowed=allowed)
    except (HandlerNotFound, KeyError, PermissionError, TypeError, ValueError) as exc:
        content = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    return ToolResult(call=call, content=content)


def dispatch_retrieval(store: Any, call: ToolCall, *, allowed: Sequence[str]) -> str:
    if call.name not in allowed:
        return json.dumps({"error": f"unknown tool {call.name!r}"})
    args = call.arguments
    if call.name == "get_handler":
        return json.dumps(store.get_handler(str(args["handler_id"])).to_dict())
    if call.name == "get_source":
        lines = line_range(args)
        return json.dumps({"source": store.get_source(str(args["file"]), lines)})
    if call.name == "model_definition":
        definition = store.model_definition(str(args["name"]))
        return json.dumps(
            {"facts": definition.facts.to_dict(), "source": definition.source}
        )
    if call.name == "callers_of":
        sites = store.callers_of(str(args["symbol"]))
        return json.dumps(
            [
                {"file": site.file, "caller": site.caller_symbol, "line": site.line}
                for site in sites
            ]
        )
    return json.dumps(
        [
            {"handler_id": record.handler_id, "method": record.method, "path": record.path}
            for record in store.candidates("examine")
        ]
    )


def line_range(args: dict[str, Any]) -> tuple[int, int] | None:
    if "start_line" not in args and "end_line" not in args:
        return None
    start = args.get("start_line")
    end = args.get("end_line")
    if type(start) is not int or type(end) is not int:
        raise ValueError("start_line and end_line must both be integers")
    return (start, end)
