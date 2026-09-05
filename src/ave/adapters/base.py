"""The language-pack seam — the stable interface a per-language adapter plugs into.

D3: the core (`ave.graph`, `ave.state`, `ave.records`, `ave.policy`) stays language- and
vuln-family-neutral; everything target-specific lives behind this seam. A `LanguagePack`
supplies the four capabilities named in `adapters/README.md`:

  1. **finding sources** — `find()`
  2. **blast-radius extraction** — `blast_radius()`
  3. **fix templates** — `prepare_fix()`
  4. **exploit-oracle harness** — `run_exploit()` (inverted polarity: True == still vulnerable)

The walking skeleton (ticket 03) lands the first concrete pack (`python_authz`) against a
single synthetic instance, which is what reveals the genuinely Python-specific edges. The
real vendored-target catalog is ticket 04; a second-language pack is roadmap (D3 fog).
"""

from __future__ import annotations

from typing import Any, Protocol, TypedDict, runtime_checkable

from ave.state import Finding


class PinnedExploitResult(TypedDict):
    """The result of running an instance's exploit oracle in the target's *pinned*
    environment — the second runner shape (see `PinnedEnvCapable`). Neutral by construction
    (no `authz`/`fastapi`/HTTP specifics in the core's view): the captured transcript rides
    opaquely in `attack_exchange` and is interpreted only by the renderer's own fail-closed
    validator.

    - `ran`: did the pinned env actually run? False is the honest skip (env absent) — never
      a fabricated pass.
    - `before_vulnerable` / `after_blocked`: the two halves of the inverted-polarity flip,
      measured against the real target; None when not run.
    - `flipped`: `before_vulnerable and after_blocked` — the pinned T1 signal; None when not
      run.
    - `attack_exchange`: the captured, already-redacted transcript
      (`request` / `before_response` / `after_response`), or None when not captured.
    - `detail`: one line on what happened, for the run record and logs."""

    ran: bool
    before_vulnerable: bool | None
    after_blocked: bool | None
    flipped: bool | None
    attack_exchange: dict[str, Any] | None
    detail: str


class PreparedFix(dict[str, Any]):
    """A class-level change plus the artifacts a PR needs. A plain dict subclass so it
    threads through graph state unchanged; keys: `class_level`, `summary`, `patch`
    (unified diff), `patch_caveat`, `finding_id`, `blast_radius`.

    `patch_caveat` is the pack's one-sentence warning to the reviewer, rendered above the
    diff, for when the patch does not apply cleanly to the target as shipped. The pack
    words it because only the pack knows what its patch stands for; the core stays
    language-neutral (D3) and just renders whatever it is handed."""


@runtime_checkable
class LanguagePack(Protocol):
    """One language/framework's plug into the core. Ticket 05 firms the return schemas;
    the skeleton pack implements the thinnest honest version of each."""

    name: str

    def find(self, target_ref: str) -> list[Finding]:
        """Surface candidate findings from the target. Neutral `Finding` records only."""
        ...

    def blast_radius(self, finding: Finding) -> dict[str, Any]:
        """The caller/PR-level reach of a change to this finding's symbol. Carries the
        policy-facing dimensions `files` / `dependents` / `routes` the governance
        predicate is measured against, alongside the reviewer-facing caller view.

        Per ticket 06's PR-body contract, this same pass emits the body's four
        blast-radius blocks via optional keys — `fact` ({statement, how_sure: 1-5 |
        "unproven", proof}), `cleared` ([{ruled_out, how}]), `before_you_merge`
        ([{command, expect}]) — filled only with what the pack can honestly stand
        behind; the renderer draws honest empties for anything absent and never
        fabricates a block."""
        ...

    def fix_plan(self, finding: Finding) -> dict[str, Any]:
        """The *proposed* class-level remediation surface, before the concrete patch
        (`prepare_fix`). Keys: `changed_paths` (repo-relative files the fix would touch),
        `is_class_level`, `preserves_legitimate_access`. The Decide node evaluates the
        policy's fix predicates over this proposal; `prepare_fix` later realizes it."""
        ...

    def prepare_fix(self, finding: Finding) -> PreparedFix:
        """Produce the class-level fix and its unified-diff patch for the finding."""
        ...

    def run_exploit(self, finding: Finding, *, fixed: bool) -> bool:
        """Run the finding's exploit oracle. **Inverted polarity**: returns True when the
        exploit SUCCEEDS (target still vulnerable), False once the fix blocks it."""
        ...

    def legitimate_use_holds(self, *, fixed: bool) -> bool:
        """The verification ladder's positive check: the fix must not break legitimate
        (correctly-authorized) use of the affected endpoint."""
        ...


@runtime_checkable
class PinnedEnvCapable(Protocol):
    """An *optional* pack capability: running an instance's by-path exploit oracle inside
    the target's pinned environment, against the real target rather than the pack's hermetic
    in-process model — and capturing the real attack exchange while there.

    This is deliberately **not** part of `LanguagePack`. It surfaces a seam smell the core
    is not yet ready to name: the exploit-oracle harness now has **two runner shapes** — the
    hermetic in-process `run_exploit()` that drives `make check` without any target env, and
    this pinned-subprocess shape that needs the target stood up. The core selects between
    them by a capability probe (`isinstance(pack, PinnedEnvCapable)` + `pinned_env_available()`),
    not by a first-class Runner abstraction on the seam. Unifying the two shapes behind one
    named Runner strategy is **ticket 14** (language-pack seam hardening); until then this
    stays an add-on Protocol so a pack without a pinned env is not forced to implement it and
    the core stays D3-neutral.

    Honesty contract: `pinned_env_available()` is False when the env is absent, and every
    entry point returns a `ran=False` result rather than a fabricated pass or transcript."""

    def pinned_env_available(self) -> bool:
        """True only when this pack can actually run the pinned env right now (the target is
        present and its runner is on PATH). False is the signal to fall back to the hermetic
        oracle — the core never treats an unavailable env as a passing one."""
        ...

    def run_pinned_exploit(self, finding: Finding) -> PinnedExploitResult:
        """Run the finding's by-path oracle in the pinned env and capture the attack
        exchange. Returns a `ran=False` result (never raises) when the env is absent or the
        instance has no pinned harness, so a caller can always trust the `ran` flag."""
        ...
