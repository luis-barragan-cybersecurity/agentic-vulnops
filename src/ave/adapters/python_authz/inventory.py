"""The deterministic route-inventory pass — the layer the whole find stage stands on.

An AST walk over the finder-readable target tree (`allowlist.finder_allowlist`) that emits
**one structured record per route handler**, plus the owner-column facts read out of the
data models. No model is involved anywhere here (ticket 23): this pass produces *evidence*,
and the LLM finder (ticket 25) later produces the *verdict* by reasoning over it through the
typed tools in `code_facts`.

Every record carries **facts, not judgment** (find-stage design, decision 3): the route's
method and path, the handler's ``file:symbol`` and line span, the caller-controlled inputs
and where each comes from (path / query / body), the auth dependencies in the signature,
the database queries performed and the columns they filter on, the owner columns of the
models touched, and whether the caller's identity reaches the query. That is exactly enough
to *see*, without deciding, that `get_order` fetches ``Order.id == order_id`` while
``Order.user_id`` is never constrained (I-04), and that `get_order_status` guards the same
fetch with ``db_order.user_id != current_user.id`` (the D-03 decoy). What those facts
*mean* is the model's job, downstream.

The pass never imports or executes target code — files reach it only as text, through the
allowlist, and are parsed with :mod:`ast`.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from ave.adapters.python_authz.allowlist import ScanAllowlist, finder_allowlist

InputSource = Literal["path", "query", "body"]
RhsKind = Literal["caller-identity", "caller-input", "literal", "other"]

#: HTTP methods a ``@router.<method>("...")`` decorator can name.
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
#: Methods that mutate server state by definition, independent of what the body does.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: The auth callables this pack recognises inside ``Depends(...)``. Pack-side domain
#: knowledge (Python/FastAPI/authz), never leaked into the neutral core (D3). A role gate is
#: `RolesBasedAuthChecker`; `get_current_user` proves only authentication, not authorization.
_AUTH_CALLABLES = frozenset({"RolesBasedAuthChecker", "get_current_user"})
ROLE_GATE = "RolesBasedAuthChecker"
#: Framework-injected parameters that are not caller-controlled inputs.
_FRAMEWORK_TYPES = frozenset({"Request", "Response", "BackgroundTasks", "Session"})
#: Scalar annotations that make a non-Depends argument a query/path parameter rather than a
#: request body (a body is a Pydantic model — a non-scalar class).
_SCALAR_TYPES = frozenset({"int", "str", "float", "bool", "bytes"})
#: Names that denote the authenticated caller's own identity.
_IDENTITY_NAMES = frozenset({"current_user"})

_PATH_PARAM = re.compile(r"\{(\w+)\}")


@dataclass(frozen=True)
class InputFact:
    """One caller-controlled input and where it enters — the attacker's reach into a
    handler. `source` is ``path`` / ``query`` / ``body``; Depends-injected and framework
    parameters are not inputs and never appear here."""

    name: str
    source: InputSource


@dataclass(frozen=True)
class QueryFilter:
    """One column constraint on a database query: ``Model.column <op> <rhs>``. `rhs` records
    *what kind of value* the column is compared against — the caller's own identity, a
    caller-controlled input, a literal, or something else — without deciding what that
    means. `under_caller_branch` is True when the constraint sits inside an ``if`` whose
    test reads a caller input (the I-06 / I-07 shape, where a binding holds on one branch
    only)."""

    model: str
    column: str
    rhs: RhsKind
    under_caller_branch: bool


@dataclass(frozen=True)
class IdentityGuard:
    """A post-fetch ownership comparison in the handler body — ``<obj>.<owner_col> <op>
    current_user.<attr>`` — the hand-rolled check that makes `get_order_status` a decoy.
    Captured as a fact so the model can tell a real guard from a missing one; whether it
    holds on *every* path is what `under_caller_branch` records."""

    owner_column: str
    identity_ref: str
    under_caller_branch: bool


@dataclass(frozen=True)
class InventoryRecord:
    """One route handler, as facts. `handler_id` is ``file:symbol`` — stable across runs
    (lines drift), the identity the typed tools and de-dup key speak in."""

    handler_id: str
    method: str
    path: str
    file: str
    symbol: str
    line_start: int
    line_end: int
    inputs: tuple[InputFact, ...]
    dependencies: tuple[str, ...]
    auth_dependencies: tuple[str, ...]
    mutates_state: bool
    models_queried: tuple[str, ...]
    query_filters: tuple[QueryFilter, ...]
    identity_guards: tuple[IdentityGuard, ...]
    caller_identity_reaches_query: bool

    @property
    def role_gate(self) -> bool:
        """A role/function-level authorization gate is present in the signature."""
        return ROLE_GATE in self.auth_dependencies

    @property
    def authenticated(self) -> bool:
        """The route requires an authenticated caller (a role gate or `get_current_user`)."""
        return bool(self.auth_dependencies)

    def to_dict(self) -> dict[str, Any]:
        return {
            "handler_id": self.handler_id,
            "method": self.method,
            "path": self.path,
            "file": self.file,
            "symbol": self.symbol,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "inputs": [{"name": i.name, "source": i.source} for i in self.inputs],
            "dependencies": list(self.dependencies),
            "auth_dependencies": list(self.auth_dependencies),
            "mutates_state": self.mutates_state,
            "models_queried": list(self.models_queried),
            "query_filters": [
                {
                    "model": q.model,
                    "column": q.column,
                    "rhs": q.rhs,
                    "under_caller_branch": q.under_caller_branch,
                }
                for q in self.query_filters
            ],
            "identity_guards": [
                {
                    "owner_column": g.owner_column,
                    "identity_ref": g.identity_ref,
                    "under_caller_branch": g.under_caller_branch,
                }
                for g in self.identity_guards
            ],
            "caller_identity_reaches_query": self.caller_identity_reaches_query,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> InventoryRecord:
        return InventoryRecord(
            handler_id=data["handler_id"],
            method=data["method"],
            path=data["path"],
            file=data["file"],
            symbol=data["symbol"],
            line_start=data["line_start"],
            line_end=data["line_end"],
            inputs=tuple(
                InputFact(name=i["name"], source=i["source"]) for i in data["inputs"]
            ),
            dependencies=tuple(data["dependencies"]),
            auth_dependencies=tuple(data["auth_dependencies"]),
            mutates_state=data["mutates_state"],
            models_queried=tuple(data["models_queried"]),
            query_filters=tuple(
                QueryFilter(
                    model=q["model"],
                    column=q["column"],
                    rhs=q["rhs"],
                    under_caller_branch=q["under_caller_branch"],
                )
                for q in data["query_filters"]
            ),
            identity_guards=tuple(
                IdentityGuard(
                    owner_column=g["owner_column"],
                    identity_ref=g["identity_ref"],
                    under_caller_branch=g["under_caller_branch"],
                )
                for g in data["identity_guards"]
            ),
            caller_identity_reaches_query=data["caller_identity_reaches_query"],
        )


@dataclass(frozen=True)
class ModelFacts:
    """A data model and its **owner columns** — the columns that bind a row to a user, so a
    query that fails to constrain one is a candidate ownership gap. Foreign keys to the
    users table are owner columns; the users table itself is the identity, so its ``id`` and
    ``username`` count as owner columns too (an object identified *by* a user)."""

    name: str
    file: str
    line_start: int
    line_end: int
    owner_columns: tuple[str, ...]
    columns: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "owner_columns": list(self.owner_columns),
            "columns": list(self.columns),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ModelFacts:
        return ModelFacts(
            name=data["name"],
            file=data["file"],
            line_start=data["line_start"],
            line_end=data["line_end"],
            owner_columns=tuple(data["owner_columns"]),
            columns=tuple(data["columns"]),
        )


@dataclass(frozen=True)
class Inventory:
    """The whole deterministic pass: every handler record and the model owner-column facts.
    The backing store (`code_facts.CodeFactsStore`) serialises this and serves it through
    the typed tools; the pre-filter (`prefilter`) reads records against `models`."""

    handlers: tuple[InventoryRecord, ...]
    models: dict[str, ModelFacts]

    def has_owner_column(self, model_name: str) -> bool:
        facts = self.models.get(model_name)
        return bool(facts and facts.owner_columns)

    def owner_columns(self) -> frozenset[str]:
        """Every owner-column name across all models — the vocabulary an identity guard is
        recognised against."""
        return frozenset(
            col for facts in self.models.values() for col in facts.owner_columns
        )


# --------------------------------------------------------------------------- models


def _string_arg(call: ast.Call) -> str | None:
    if call.args and isinstance(call.args[0], ast.Constant):
        value = call.args[0].value
        return value if isinstance(value, str) else None
    return None


def _is_foreign_key_to_users(node: ast.expr) -> bool:
    """True for a ``ForeignKey("users.id")`` (or ``users.<col>``) call anywhere in a Column
    definition."""
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id == "ForeignKey"
        ):
            ref = _string_arg(child)
            if ref and ref.split(".")[0] == "users":
                return True
    return False


def _is_column_def(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Column"
    )


def _parse_models(tree: ast.Module, file_rel: str) -> dict[str, ModelFacts]:
    """Read the SQLAlchemy models out of one parsed file: each class, its columns, and
    which of them are owner columns (foreign keys to the users table; for the users table
    itself, its identity columns)."""
    models: dict[str, ModelFacts] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        columns: list[str] = []
        owner: list[str] = []
        tablename: str | None = None
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
                continue
            target = stmt.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if target.id == "__tablename__" and isinstance(stmt.value, ast.Constant):
                tablename = (
                    stmt.value.value if isinstance(stmt.value.value, str) else None
                )
                continue
            if _is_column_def(stmt.value):
                columns.append(target.id)
                if _is_foreign_key_to_users(stmt.value):
                    owner.append(target.id)
        if not columns:
            continue
        # The users table is the identity: its own id/username own the objects that *are*
        # a user (the I-02 / I-07 shape — the object is the identity itself).
        if tablename == "users":
            owner = [c for c in ("id", "username") if c in columns] or owner
        models[node.name] = ModelFacts(
            name=node.name,
            file=file_rel,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            owner_columns=tuple(owner),
            columns=tuple(columns),
        )
    return models


# --------------------------------------------------------------------------- handlers


def _model_alias_map(tree: ast.Module) -> dict[str, str]:
    """Map local names to model class names for one file, honouring ``import ... as``.
    ``from db.models import User as UserModel`` makes ``UserModel`` mean ``User``."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("db"):
            for name in node.names:
                aliases[name.asname or name.name] = name.name
    return aliases


def _route_of(func: ast.AST) -> tuple[str, str] | None:
    """The ``(METHOD, path)`` of a ``@router.<method>("path")`` decorator, or None if the
    function is not a route handler."""
    if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    for dec in func.decorator_list:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        method = dec.func.attr
        if method not in _HTTP_METHODS:
            continue
        path = _string_arg(dec)
        if path is not None:
            return method.upper(), path
    return None


def _depends_callable(node: ast.AST) -> str | None:
    """The callable named inside ``Depends(<callable>)`` — ``Depends(get_current_user)`` ->
    ``get_current_user``, ``Depends(RolesBasedAuthChecker([...]))`` ->
    ``RolesBasedAuthChecker`` — or None if `node` is not a ``Depends(...)`` call."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    is_depends = (isinstance(func, ast.Name) and func.id == "Depends") or (
        isinstance(func, ast.Attribute) and func.attr == "Depends"
    )
    if not is_depends or not node.args:
        return None
    return _callable_name(node.args[0])


def _callable_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Call):
        return _callable_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _annotation_names(node: ast.expr | None) -> tuple[list[str], list[ast.AST]]:
    """Return the type names mentioned in an annotation and the ``Depends(...)`` calls
    embedded in it (for ``Annotated[T, Depends(...)]``)."""
    names: list[str] = []
    depends: list[ast.AST] = []
    if node is None:
        return names, depends
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.append(child.id)
        elif isinstance(child, ast.Attribute):
            names.append(child.attr)
        if _depends_callable(child) is not None:
            depends.append(child)
    return names, depends


def _iter_args(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.arg, ast.expr | None]]:
    """Every parameter of a handler paired with its default (None if it has none), across
    positional-only, positional, and keyword-only parameters."""
    args = func.args
    positional = list(args.posonlyargs) + list(args.args)
    pos_defaults: list[ast.expr | None] = [None] * (
        len(positional) - len(args.defaults)
    ) + list(args.defaults)
    paired: list[tuple[ast.arg, ast.expr | None]] = list(
        zip(positional, pos_defaults, strict=True)
    )
    paired += list(zip(args.kwonlyargs, args.kw_defaults, strict=True))
    return paired


class _HandlerAnalyzer(ast.NodeVisitor):
    """Walk a handler body once, tracking which ``if`` branches are keyed on a caller input,
    and collect the query facts: model filters, ownership guards, mutation calls."""

    def __init__(self, input_names: set[str], model_names: set[str], owner_cols: set[str]):
        self._input_names = input_names
        self._model_names = model_names
        self._owner_cols = owner_cols
        self._caller_branch_depth = 0
        self.models_queried: set[str] = set()
        self.query_filters: list[QueryFilter] = []
        self.identity_guards: list[IdentityGuard] = []
        self.mutates_via_db = False

    # -- caller-input branch tracking ------------------------------------------------
    def visit_If(self, node: ast.If) -> None:
        # The condition is evaluated on the way in — a guard written as ``if
        # db_order.user_id != current_user.id`` lives *in the test*, at the branch's own
        # depth, not under it. Visit it before opening the branch.
        self.visit(node.test)
        keyed = self._reads_caller_input(node.test)
        if keyed:
            self._caller_branch_depth += 1
        for child in node.body:
            self.visit(child)
        for child in node.orelse:
            self.visit(child)
        if keyed:
            self._caller_branch_depth -= 1

    def _reads_caller_input(self, node: ast.expr) -> bool:
        return any(
            isinstance(n, ast.Name) and n.id in self._input_names
            for n in ast.walk(node)
        )

    @property
    def _under_caller_branch(self) -> bool:
        return self._caller_branch_depth > 0

    # -- facts -----------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr == "query" and node.args:
                model = self._model_of(node.args[0])
                if model is not None:
                    self.models_queried.add(model)
            if attr in ("add", "commit", "delete", "execute", "merge"):
                self.mutates_via_db = True
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left, *node.comparators]
        for i, operand in enumerate(operands):
            model, column = self._model_column(operand)
            if model is not None and column is not None:
                other = operands[1 - i] if len(operands) == 2 else None
                rhs = self._classify(other) if other is not None else "other"
                self.query_filters.append(
                    QueryFilter(model, column, rhs, self._under_caller_branch)
                )
            owner_col = self._owner_attr(operand)
            if owner_col is not None:
                other = operands[1 - i] if len(operands) == 2 else None
                if other is not None and self._classify(other) == "caller-identity":
                    self.identity_guards.append(
                        IdentityGuard(
                            owner_col, _dump(other), self._under_caller_branch
                        )
                    )
        self.generic_visit(node)

    # -- expression classifiers ------------------------------------------------------
    def _model_of(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name) and node.id in self._model_names:
            return node.id
        if isinstance(node, ast.Attribute) and node.attr in self._model_names:
            return node.attr
        return None

    def _model_column(self, node: ast.expr) -> tuple[str | None, str | None]:
        """``Order.user_id`` -> (``Order``, ``user_id``); anything else -> (None, None)."""
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in self._model_names
        ):
            return node.value.id, node.attr
        return None, None

    def _owner_attr(self, node: ast.expr) -> str | None:
        """``db_order.user_id`` where ``user_id`` is an owner column -> ``user_id``. The
        left side of a hand-rolled ownership guard on a fetched instance (not a model
        class)."""
        if (
            isinstance(node, ast.Attribute)
            and node.attr in self._owner_cols
            and isinstance(node.value, ast.Name)
            and node.value.id not in self._model_names
        ):
            return node.attr
        return None

    def _classify(self, node: ast.expr) -> RhsKind:
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            if root.id in _IDENTITY_NAMES:
                return "caller-identity"
            if root.id in self._input_names:
                return "caller-input"
            return "other"
        if isinstance(node, ast.Constant):
            return "literal"
        return "other"


def _dump(node: ast.expr) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - unparse is total on valid trees
        return "<expr>"


def _analyze_handler(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    method: str,
    path: str,
    file_rel: str,
    aliases: dict[str, str],
    inventory_models: dict[str, ModelFacts],
) -> InventoryRecord:
    path_params = set(_PATH_PARAM.findall(path))
    inputs: list[InputFact] = []
    dependencies: list[str] = []
    auth_dependencies: list[str] = []

    for arg, default in _iter_args(func):
        name = arg.arg
        anno_names, anno_depends = _annotation_names(arg.annotation)
        dep = _depends_callable(default) if default is not None else None
        for extra in anno_depends:
            dep = dep or _depends_callable(extra)
        if dep is not None:
            dependencies.append(dep)
            if dep in _AUTH_CALLABLES:
                auth_dependencies.append(dep)
            continue
        if name in ("self", "db") or any(t in _FRAMEWORK_TYPES for t in anno_names):
            continue
        inputs.append(InputFact(name=name, source=_input_source(name, path_params, anno_names)))

    model_names = set(inventory_models) | set(aliases)
    owner_cols = {
        col for facts in inventory_models.values() for col in facts.owner_columns
    }
    input_names = {i.name for i in inputs}
    analyzer = _HandlerAnalyzer(input_names, model_names, owner_cols)
    for stmt in func.body:
        analyzer.visit(stmt)

    models_queried = tuple(
        sorted({aliases.get(m, m) for m in analyzer.models_queried})
    )
    query_filters = tuple(
        QueryFilter(aliases.get(q.model, q.model), q.column, q.rhs, q.under_caller_branch)
        for q in analyzer.query_filters
    )
    mutates_state = method in _MUTATING_METHODS or analyzer.mutates_via_db
    caller_identity_reaches_query = any(
        q.rhs == "caller-identity" for q in query_filters
    ) or bool(analyzer.identity_guards)

    return InventoryRecord(
        handler_id=f"{file_rel}:{func.name}",
        method=method,
        path=path,
        file=file_rel,
        symbol=func.name,
        line_start=min(
            [func.lineno, *[d.lineno for d in func.decorator_list]]
        ),
        line_end=func.end_lineno or func.lineno,
        inputs=tuple(inputs),
        dependencies=tuple(sorted(set(dependencies))),
        auth_dependencies=tuple(sorted(set(auth_dependencies))),
        mutates_state=mutates_state,
        models_queried=models_queried,
        query_filters=query_filters,
        identity_guards=tuple(analyzer.identity_guards),
        caller_identity_reaches_query=caller_identity_reaches_query,
    )


def _input_source(
    name: str, path_params: set[str], anno_names: list[str]
) -> InputSource:
    if name in path_params:
        return "path"
    # A non-scalar class annotation (a Pydantic schema) is a request body; a scalar is a
    # query parameter. Optional[str] etc. still read as scalar (str is present).
    is_scalar = not anno_names or any(t in _SCALAR_TYPES for t in anno_names)
    return "query" if is_scalar else "body"


@dataclass(frozen=True)
class ParsedTree:
    """One allowlisted file, read and parsed exactly once — the shared input of the
    inventory pass and the call-graph pass (`callgraph.build_call_graph`), so neither
    re-reads the tree."""

    rel: str
    tree: ast.Module


def parse_allowlisted(allowlist: ScanAllowlist) -> list[ParsedTree]:
    """Read and parse each allowlisted file once, in `allowlist.files()` order."""
    return [
        ParsedTree(rel=allowlist.rel(path), tree=ast.parse(allowlist.read_text(path)))
        for path in allowlist.files()
    ]


def inventory_from(trees: Sequence[ParsedTree]) -> Inventory:
    """The deterministic inventory pass over already-parsed trees: every route handler as
    a facts-only record, and the model owner-column facts the pre-filter and the model
    both read."""
    models: dict[str, ModelFacts] = {}
    for parsed in trees:
        models.update(_parse_models(parsed.tree, parsed.rel))

    handlers: list[InventoryRecord] = []
    for parsed in trees:
        aliases = _model_alias_map(parsed.tree)
        for node in ast.walk(parsed.tree):
            route = _route_of(node)
            if route is None:
                continue
            assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            method, route_path = route
            handlers.append(
                _analyze_handler(node, method, route_path, parsed.rel, aliases, models)
            )

    handlers.sort(key=lambda r: r.handler_id)
    return Inventory(handlers=tuple(handlers), models=models)


def build_inventory(allowlist: ScanAllowlist | None = None) -> Inventory:
    """Walk the allowlisted target tree and produce the whole deterministic inventory.
    Reads only through `allowlist`; no target code is imported or run."""
    return inventory_from(parse_allowlisted(allowlist or finder_allowlist()))
