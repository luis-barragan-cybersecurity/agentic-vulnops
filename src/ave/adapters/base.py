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

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ave.findings import Dependents
from ave.state import Finding
from ave.state import PinnedExploitResult as PinnedExploitResult
from ave.state import PinnedStatus as PinnedStatus


@dataclass(frozen=True)
class FindingBatch:
    """The atomic result of `LanguagePack.find()`.

    `kept` is what Match ranks. `suppressed` is what the pack culled. `report` is
    JSON-ready find-stage facts for the Match span. There is no side channel.
    """

    kept: tuple[Finding, ...]
    suppressed: tuple[Finding, ...]
    report: dict[str, Any]


class PreparedFix(dict[str, Any]):
    """A class-level change plus the artifacts a PR needs. A plain dict subclass so it
    threads through graph state unchanged; keys: `class_level`, `summary`, `patch`
    (unified diff), `patch_paths` (unique target-relative paths the patch touches;
    Prepare requires them to equal the fix plan's `changed_paths`), `patch_caveat`,
    `finding_id`, `blast_radius`.

    `patch_caveat` is the pack's one-sentence warning to the reviewer, rendered above the
    diff, for when the patch does not apply cleanly to the target as shipped. The pack
    words it because only the pack knows what its patch stands for; the core stays
    language-neutral (D3) and just renders whatever it is handed."""


@runtime_checkable
class LanguagePack(Protocol):
    """One language/framework's plug into the core. Ticket 05 firms the return schemas;
    the skeleton pack implements the thinnest honest version of each."""

    name: str

    def find(self, target_ref: str) -> FindingBatch:
        """Surface candidate findings from the target as one batch: `kept` for ranking,
        `suppressed` for the sidecar, and a JSON-ready `report` for the Match span.
        Every finding should carry `source`; the core stamps `unattributed` on any that
        does not, so the omission is visible rather than blank."""
        ...

    def dedup_key(self, finding: Finding) -> str:
        """The stable location identity two findings must share to be the same flaw —
        `file:symbol`, never `file:line` (lines drift between runs and sources).

        This is the pack's half of de-dup: only the pack knows how to read its own
        `location` into a file and an enclosing symbol. The other half — grouping on
        `(dedup_key, kind)`, keeping the higher confidence, folding the losers' sources
        into `corroborated_by` — is language-neutral and lives once in `ave.findings`,
        so a second pack inherits it. **Fail toward not merging:** a location the pack
        cannot resolve to a symbol must come back as-is, so a surviving duplicate is
        visible and honest rather than a source silently dropped by a wrong merge."""
        ...

    def measured_dependents(self, findings: Iterable[Finding]) -> Dependents:
        """finding id -> measured dependent call sites. A finding this pack did not
        measure is absent; `rank_findings` reads an absent key as unmeasured. This is the
        one seam Assess obtains the counts through — the core never parses a pack
        evidence key."""
        ...

    def blast_radius(self, finding: Finding) -> dict[str, Any]:
        """A projection of the measurement the pack recorded in `find()`: the
        policy-facing dimensions `files` / `dependents` / `routes` the governance
        predicate is measured against, alongside the reviewer-facing blocks. A finding
        with a measurement is readable even when `can_drive()` is false.

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

    def can_drive(self, finding: Finding) -> bool:
        """Finishability: the pack can bind a pytest and emit a patch for `finding` now."""
        ...


@runtime_checkable
class PinnedEnvCapable(Protocol):
    """Optional pinned-environment runner for an already prepared fix.

    Every requested run returns an explicit outcome. Unavailable or failed runs do not
    fall back to the hermetic oracle."""

    def run_pinned_exploit(
        self, finding: Finding, prepared: dict[str, Any]
    ) -> PinnedExploitResult:
        """Apply `prepared["patch"]` in an isolated copy and run the finding's by-path
        oracle against the original target and that copy. Never raises; every failure is an
        explicit `PinnedStatus`."""
        ...
