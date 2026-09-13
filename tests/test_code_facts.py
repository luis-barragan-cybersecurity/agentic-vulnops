"""The deterministic find-stage layer (ticket 23): the scan allowlist, the AST route
inventory, the sound pre-filter, and the typed code-facts store.

The load-bearing guarantees this pins:

* **Recall is preserved by construction.** Every catalogued instance survives the
  pre-filter to ``examine`` — the pre-filter drops only what provably cannot be an
  ownership or function-level gap, so it can never silently absorb a real finding the way a
  similarity search would.
* **The answer key is unreachable.** The finder allowlist forbids ``catalog.json``,
  ``CATALOG.md`` and every bound oracle, in code; and source served through the store has
  its comments stripped, closing the last channel a GPL-§5 mark's presence left open.
* **The facts are the ones a verdict needs.** ``get_order``'s inventory record shows the
  ``Order.id`` fetch with ``Order.user_id`` unconstrained (I-04); ``get_order_status``
  shows the ``user_id != current_user.id`` guard that makes it the D-03 decoy.

No model and no network are involved anywhere here — this is the evidence layer, tested as
one.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from ave.adapters.python_authz.allowlist import (
    AllowlistViolation,
    finder_allowlist,
    writer_allowlist,
)
from ave.adapters.python_authz.callgraph import ResolvedEdge
from ave.adapters.python_authz.code_facts import (
    CodeFactsStore,
    HandlerNotFound,
    RouteRef,
    strip_comments,
)
from ave.adapters.python_authz.inventory import build_inventory
from ave.adapters.python_authz.prefilter import screen_inventory

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CATALOG = json.loads((_REPO_ROOT / "target" / "catalog.json").read_text())


def _handler_id(file: str, symbol: str) -> str:
    """The inventory id for a catalog entry: catalog files are ``app/...``; the inventory
    speaks in the repo-relative ``target/dvrestaurant/app/...``."""
    return f"target/dvrestaurant/{file}:{symbol}"


# --------------------------------------------------------------------------- allowlist


def test_finder_allowlist_permits_app_source_only() -> None:
    allow = finder_allowlist()
    assert allow.is_readable(
        "target/dvrestaurant/app/apis/orders/services/get_order_service.py"
    )
    # The answer key and every bound oracle are outside the tree — structurally unreadable.
    assert not allow.is_readable("target/catalog.json")
    assert not allow.is_readable("target/CATALOG.md")
    assert not allow.is_readable(
        "target/dvrestaurant/app/tests/vulns/ave_seed_bola_order_read.py"
    )
    assert not allow.is_readable("target/dvrestaurant/app/tests/conftest.py")


def test_writer_allowlist_permits_app_tests_minus_vulns() -> None:
    allow = writer_allowlist()
    assert allow.is_readable("target/dvrestaurant/app/tests/conftest.py")
    assert not allow.is_readable(
        "target/dvrestaurant/app/tests/vulns/ave_seed_bola_order_read.py"
    )
    assert not allow.is_readable("target/catalog.json")
    assert not allow.is_readable(
        "target/dvrestaurant/app/apis/orders/services/get_order_service.py"
    )


def test_finder_allowlist_boundary_matches_the_de_leak_guard() -> None:
    """The allowlist tree and the token-free tree `tests/test_target_de_leak.py` pins are
    the same boundary: application ``.py`` under ``app/`` minus ``app/tests/``."""
    allow = finder_allowlist()
    files = {allow.rel(p) for p in allow.files()}
    assert files, "the allowlist found no files"
    assert all(f.startswith("target/dvrestaurant/app/") for f in files)
    assert all("/tests/" not in f for f in files)
    assert all(f.endswith(".py") for f in files)


def test_allowlist_read_text_raises_outside_the_tree() -> None:
    allow = finder_allowlist()
    with pytest.raises(AllowlistViolation):
        allow.read_text("target/catalog.json")
    with pytest.raises(AllowlistViolation):
        allow.read_text("target/dvrestaurant/app/../../catalog.json")


# --------------------------------------------------------------------------- inventory


def test_every_route_handler_is_inventoried() -> None:
    inventory = build_inventory()
    ids = {r.handler_id for r in inventory.handlers}
    # Every catalogued instance and decoy resolves to a record.
    for entry in _CATALOG["instances"]:
        assert _handler_id(entry["file"], entry["symbol"]) in ids


def test_records_carry_facts_not_judgment_for_the_anchor() -> None:
    inventory = build_inventory()
    by_id = {r.handler_id for r in inventory.handlers}
    hid = _handler_id("app/apis/orders/services/get_order_service.py", "get_order")
    assert hid in by_id
    record = next(r for r in inventory.handlers if r.handler_id == hid)
    assert record.method == "GET"
    assert record.path == "/orders/{order_id}"
    assert [(i.name, i.source) for i in record.inputs] == [("order_id", "path")]
    # The fetch is by object id; the owner column is never constrained — an ownership gap
    # visible in the facts alone.
    assert any(q.model == "Order" and q.column == "id" for q in record.query_filters)
    assert not record.caller_identity_reaches_query
    assert not record.identity_guards


def test_decoy_ownership_guard_is_captured() -> None:
    """D-03 `get_order_status` fetches by id like the anchor, but a post-fetch
    ``user_id != current_user.id`` guard makes it safe — and that guard is a recorded
    fact."""
    inventory = build_inventory()
    hid = _handler_id("app/apis/orders/services/get_order_status.py", "get_order_status")
    record = next(r for r in inventory.handlers if r.handler_id == hid)
    assert record.caller_identity_reaches_query
    assert any(
        g.owner_column == "user_id" and not g.under_caller_branch
        for g in record.identity_guards
    )


def test_conditional_binding_is_marked_conditional() -> None:
    """I-07 honours an attacker-supplied ``username`` on one branch and the caller's id on
    the other — the binding must read as *conditional*, the case a structural predicate
    mis-clears."""
    inventory = build_inventory()
    hid = _handler_id("app/apis/referrals/service.py", "get_referral_code_endpoint")
    record = next(r for r in inventory.handlers if r.handler_id == hid)
    identity_filters = [q for q in record.query_filters if q.rhs == "caller-identity"]
    assert identity_filters, "expected an identity-bound filter on one branch"
    assert all(q.under_caller_branch for q in identity_filters)


def test_owner_columns_read_from_models() -> None:
    inventory = build_inventory()
    assert inventory.models["Order"].owner_columns == ("user_id",)
    assert "user_id" in inventory.models["DiscountCoupon"].owner_columns
    # The users table is the identity itself.
    assert set(inventory.models["User"].owner_columns) == {"id", "username"}


# --------------------------------------------------------------------------- pre-filter


def test_every_catalog_instance_survives_the_prefilter() -> None:
    """The recall-preservation invariant: the arithmetic pre-filter drops nothing that
    could be a finding, so every seeded instance reaches the model as ``examine``."""
    inventory = build_inventory()
    screens = screen_inventory(inventory)
    for entry in _CATALOG["instances"]:
        hid = _handler_id(entry["file"], entry["symbol"])
        result = screens[hid]
        assert result.screen == "examine", f"{entry['id']} was screened {result.screen}"


def test_known_public_routes_are_dropped() -> None:
    """Sound drops: routes that touch no owned object and mutate nothing are neither an
    ownership nor a function gap."""
    inventory = build_inventory()
    screens = screen_inventory(inventory)
    for file, symbol in (
        ("app/apis/healthcheck/service.py", "healthcheck"),
        ("app/apis/auth/services/get_profile_service.py", "get_profile"),
        ("app/apis/menu/services/get_menu_service.py", "get_menu"),
    ):
        assert screens[_handler_id(file, symbol)].screen == "drop"


def test_unconditional_identity_binding_is_cheap_not_dropped() -> None:
    """D-04 `get_orders` filters on ``Order.user_id == current_user.id`` on every path — the
    ownership check is present, so it is screened ``cheap``, never dropped (still counted in
    the coverage denominator) and never ``examine``."""
    inventory = build_inventory()
    screens = screen_inventory(inventory)
    hid = _handler_id("app/apis/orders/services/get_orders_service.py", "get_orders")
    assert screens[hid].screen == "cheap"


def test_no_catalog_instance_is_ever_dropped() -> None:
    inventory = build_inventory()
    screens = screen_inventory(inventory)
    for entry in _CATALOG["instances"]:
        assert screens[_handler_id(entry["file"], entry["symbol"])].screen != "drop"


# --------------------------------------------------------------------------- store + tools


def test_get_handler_and_unknown_id_rejected() -> None:
    store = CodeFactsStore.build()
    hid = _handler_id("app/apis/orders/services/get_order_service.py", "get_order")
    assert store.get_handler(hid).symbol == "get_order"
    with pytest.raises(HandlerNotFound):
        store.get_handler("target/dvrestaurant/app/nope.py:ghost")


def test_candidates_and_list_candidates() -> None:
    store = CodeFactsStore.build()
    examine = store.candidates("examine")
    assert examine, "expected candidates to examine"
    assert all(store.screen_of(r.handler_id).screen == "examine" for r in examine)
    mutating = store.list_candidates(lambda r: r.mutates_state)
    assert {r.symbol for r in mutating} >= {"delete_menu_item", "update_menu_item"}


def test_get_source_is_allowlisted_and_comment_stripped() -> None:
    store = CodeFactsStore.build()
    # A file that carries a GPL-§5 change-mark comment; the mark must not survive the read.
    served = store.get_source("target/dvrestaurant/app/apis/referrals/service.py")
    assert "GPL-3.0" not in served
    assert "§5" not in served
    # Still real source.
    assert "def get_discount_coupons" in served
    # The answer key cannot be served.
    with pytest.raises(AllowlistViolation):
        store.get_source("target/catalog.json")


def test_get_source_line_range() -> None:
    store = CodeFactsStore.build()
    hid = _handler_id("app/apis/orders/services/get_order_service.py", "get_order")
    record = store.get_handler(hid)
    excerpt = store.get_source(record.file, (record.line_start, record.line_end))
    assert "def get_order(" in excerpt
    assert "Order.id == order_id" in excerpt


def test_model_definition_serves_owner_columns_and_source() -> None:
    store = CodeFactsStore.build()
    order = store.model_definition("Order")
    assert order.facts.owner_columns == ("user_id",)
    assert "class Order" in order.source
    with pytest.raises(HandlerNotFound):
        store.model_definition("NoSuchModel")


def test_callers_of_follows_a_delegated_query() -> None:
    """`update_menu_item` (I-08) delegates its write to a helper; `callers_of` finds the
    handler that calls it, so the find stage can follow the mutation one call away."""
    store = CodeFactsStore.build()
    sites = store.callers_of("update_menu_item")
    assert any(s.caller_symbol == "update_menu_item" for s in sites)


def test_coverage_denominator() -> None:
    store = CodeFactsStore.build()
    coverage = store.coverage()
    assert coverage.found == len(store.inventory.handlers)
    assert coverage.judged == coverage.found - coverage.dropped
    assert coverage.judged < coverage.found  # some routes drop by arithmetic
    assert coverage.summary() == f"examined {coverage.judged} of {coverage.found} handlers"
    attrs = store.run_record_attributes()
    assert attrs["coverage"]["found"] == coverage.found
    assert set(attrs["screens"]) == {r.handler_id for r in store.inventory.handlers}


def test_store_roundtrips_through_json(tmp_path: Path) -> None:
    store = CodeFactsStore.build()
    path = store.write(tmp_path)
    assert path.name == "code-facts.json"
    reloaded = CodeFactsStore.load(path)
    assert [r.handler_id for r in reloaded.inventory.handlers] == [
        r.handler_id for r in store.inventory.handlers
    ]
    assert reloaded.coverage().to_dict() == store.coverage().to_dict()
    # The reloaded store still serves source through the allowlist.
    hid = _handler_id("app/apis/orders/services/get_order_service.py", "get_order")
    record = reloaded.get_handler(hid)
    assert "def get_order(" in reloaded.get_source(
        record.file, (record.line_start, record.line_end)
    )


def test_strip_comments_keeps_strings_and_docstrings() -> None:
    source = 'x = "# not a comment"  # a real comment\n"""a docstring # inside"""\n'
    stripped = strip_comments(source)
    assert "# not a comment" in stripped  # inside a string literal — kept
    assert "docstring # inside" in stripped  # docstring — kept
    assert "a real comment" not in stripped  # the trailing comment — gone


# --------------------------------------------------------------------------- blast radius


def test_reach_of_anchor_is_complete_with_no_dependents() -> None:
    store = CodeFactsStore.build()
    hid = _handler_id("app/apis/orders/services/get_order_service.py", "get_order")
    reach = store.reach_of(hid)
    assert reach.symbol_resolved is True
    assert reach.dependent_sites == ()
    assert reach.unresolved_edges == ()
    assert reach.complete is True
    assert reach.dependents == 0
    assert reach.routes == 1
    assert reach.affected_routes == (
        RouteRef(handler_id=hid, method="GET", path="/orders/{order_id}"),
    )


def test_reach_binds_same_named_helper_to_its_own_file() -> None:
    """I-08's handler and its write helper share the name `update_menu_item`. The
    name-only `callers_of` reports one site for the name; the identity-aware graph binds
    that call to the helper in `apis/menu/utils.py`, so the *handler* has zero
    dependents."""
    store = CodeFactsStore.build()
    helper = "target/dvrestaurant/app/apis/menu/utils.py:update_menu_item"
    assert (
        ResolvedEdge(
            caller_file=(
                "target/dvrestaurant/app/apis/menu/services/update_menu_item_service.py"
            ),
            caller_symbol="update_menu_item",
            line=23,
            callee=helper,
        )
        in store.call_graph.by_callee[helper]
    )
    hid = _handler_id("app/apis/menu/services/update_menu_item_service.py", "update_menu_item")
    assert store.reach_of(hid).dependents == 0


def test_reach_keeps_duplicate_symbols_distinct() -> None:
    """Two unrelated handlers are both named `get_orders`; each reach must stay on its own
    identity rather than bleed into the other's routes."""
    store = CodeFactsStore.build()
    customer = _handler_id("app/apis/orders/services/get_orders_service.py", "get_orders")
    delivery = _handler_id(
        "app/apis/orders/services/get_orders_for_delivery_service.py", "get_orders"
    )
    customer_reach = store.reach_of(customer)
    delivery_reach = store.reach_of(delivery)
    assert customer_reach.routes == 1
    assert delivery_reach.routes == 1
    assert customer_reach.affected_routes[0].handler_id == customer
    assert delivery_reach.affected_routes[0].handler_id == delivery
    assert customer != delivery


def test_reach_of_nested_handler_is_incomplete() -> None:
    """main.py's doc routes are nested defs the call graph cannot see; the reach says so —
    counts are None, never a confident zero — while the start route itself is still
    recorded."""
    store = CodeFactsStore.build()
    reach = store.reach_of(_handler_id("app/main.py", "root_docs"))
    assert reach.symbol_resolved is False
    assert reach.complete is False
    assert reach.dependents is None
    assert reach.routes is None
    assert len(reach.affected_routes) == 1


def test_store_load_rederives_the_call_graph(tmp_path: Path) -> None:
    """The JSON format carries no call graph; `load` re-binds it from the allowlist, and a
    reloaded store answers `reach_of` byte-for-byte like the store that was written."""
    store = CodeFactsStore.build()
    path = store.write(tmp_path)
    reloaded = CodeFactsStore.load(path)
    hid = _handler_id("app/apis/orders/services/get_order_service.py", "get_order")
    assert reloaded.reach_of(hid).routes == 1
    assert reloaded.reach_of(hid) == store.reach_of(hid)


def test_call_graph_edge_counts_match_the_prototype() -> None:
    """The verified ticket-28 prototype bound 140 calls and left 248 unresolved on this
    fixture (246 unknown receivers, 2 unbound names; no attribute or expression gaps). A
    port that produces different numbers is a wrong port."""
    call_graph = CodeFactsStore.build().call_graph
    assert sum(len(v) for v in call_graph.by_callee.values()) == 140
    assert sum(len(v) for v in call_graph.unresolved_by_name.values()) == 248
    reasons = Counter(
        edge.reason
        for edges in call_graph.unresolved_by_name.values()
        for edge in edges
    )
    assert reasons == {"receiver_type_unknown": 246, "unbound_name": 2}
