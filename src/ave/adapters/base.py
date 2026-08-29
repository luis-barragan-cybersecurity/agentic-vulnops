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

from typing import Any, Protocol, runtime_checkable

from ave.state import Finding


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
        """The caller/PR-level reach of a change to this finding's symbol."""
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
