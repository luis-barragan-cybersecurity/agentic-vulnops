# The pattern-scanner baseline AVE must beat

AVE's central claim is that it beats a pattern scanner **on the semantic ownership
cases** — not by scanning harder, but by reasoning about authorization a syntactic rule
cannot express. That claim is only worth anything against a *concrete, competent*
baseline. This directory is that baseline: a real Semgrep rule, run over the vendored
target, scored against the same catalog answer key the agent is scored against.

## What's here

| file | role |
|------|------|
| [`semgrep/rules/missing-role-checker.yaml`](semgrep/rules/missing-role-checker.yaml) | the rule — the strongest honest role-pattern check |
| [`semgrep/score.py`](semgrep/score.py) | runs the rule, maps findings to catalog handlers, scores precision/recall |
| `semgrep/semgrep-findings.json` | frozen raw Semgrep output, paths relative to `target/dvrestaurant` (so scoring reproduces without Semgrep installed) |
| `semgrep/results.json` | frozen scored result — the numbers below |

## The rule

One rule, one class: **flag a state-changing route handler that authenticates its caller
but declares no `RolesBasedAuthChecker` role dependency** — a possible missing
function-level authorization check (BFLA). This is what a pattern scanner is genuinely
good at: spotting a *missing gate*.

It is deliberately not a strawman. Two scoping choices keep it credible:

- **State-changing methods only** (`post`/`put`/`delete`/`patch`). Extending it to `GET`
  reads was tried and rejected — it floods precision with false positives on correct
  reads (e.g. the hand-rolled-ownership decoy D-03) while still detecting **zero**
  ownership gaps. A pattern can flag a missing *decorator*; it cannot flag a missing
  *ownership predicate*.
- **Authenticated handlers only** (`Depends(get_current_user)` present). This excludes
  genuinely public endpoints (login, register, password reset) so they are not counted
  against Semgrep as false positives.

## What it catches, and what it cannot

The rule flags **6 handlers**. Scored against `target/catalog.json`:

**Catches (correctly) — the pattern-visible BFLA end of the catalog:**
- **I-01** `delete_menu_item` (role checker commented out) ✓
- **I-08** `update_menu_item` (seeded: role checker commented out) ✓
- **I-03** `update_user_role` (no role checker at all — a real privilege-escalation BFLA) ✓
  The catalog marks I-03 `scanner_blind`; this rule still catches it, because the missing
  checker is a token.

**Structurally blind — every object-ownership (BOLA) case:**
- **I-04** `get_order` — already has `RolesBasedAuthChecker` and no `get_current_user`,
  so this pattern does not match. The missing thing is *ownership binding*.
- **I-06** `get_discount_coupons` and **I-07** `get_referral_code` — both have
  `get_current_user` and no role checker. They stay unmatched because `$METHOD` is
  `get`, not because those tokens are inexpressible. Ownership is still the missing
  predicate; extending the rule to GET would location-overlap them for the wrong class
  and flood precision on correct reads (D-01, D-03, `get_profile`).
- **I-02** `update_profile` — the rule *does* land on this file, but for the **wrong
  reason**: it reports "missing role check," whereas the flaw is a body-supplied identity
  (IDOR). Adding a role checker would not remove the vulnerability. A location-scoring
  recall hit; under class-aware scoring it is discarded as a recall hit and counted as
  a wrong-class false positive for precision.

**Also missed — I-05** `get_orders` (the hidden `include_in_schema=False` delivery route):
it carries no `get_current_user`, so it reads as a public endpoint and is not flagged.

**False positives:**
- **D-05** `patch_profile` (decoy). Correct self-service ownership, no role gate needed.
- `apply_referral_code` (unlabelled). A correct self-service mutation.
- **I-02** (wrong-class, class-aware precision only). A BFLA verdict on a BOLA instance.

## The numbers (frozen; regenerate with `make baseline`)

Two scorings, because they answer different questions.

**Class-aware (honest, the scoreboard bar):** a flag is a recall hit only where its
class (BFLA) matches the instance's family. A BFLA verdict on a BOLA instance is a
wrong-class false positive for precision.

| subset | recall | detail |
|--------|:------:|--------|
| overall | **3/8 (38%)** | I-01, I-03, I-08 |
| BFLA | 3/4 (75%) | misses I-05 (hidden route, no authn) |
| **BOLA** | **0/4 (0%)** | structurally blind to every ownership gap |

precision: **0.75** vs decoys, **0.50** across all flags (3/6). I-02 is not a
class-aware recall hit; it is a wrong-class FP, so the all-flags denominator stays 6.

**Location (generous — standard SAST benchmark):** any flag overlapping an instance
handler, class ignored. Overall recall 4/8; BOLA 1/4 (the wrong-reason I-02 overlap);
precision 0.80 / 0.667.

## Why this is the bar

The headline is **BOLA recall 0/4**. A pattern scanner cannot detect object-ownership
authorization gaps. The missing predicate is not a token in the source. It is a
relationship between the fetched object and the caller. GET exclusion is a precision
choice. I-06 and I-07 would location-overlap if GET were in scope, still as the wrong
class. That ownership subset is what AVE exists to cover.
AVE beats this baseline by **rediscovering those ownership gaps** (scored against
`catalog.ground_truth()`, which no detector may read) at no worse precision. That
means not flagging the decoys (D-01…D-05) that this rule's aggressive cousins would
trip on, and not treating a wrong-class overlap as a free exclusion from the
denominator.

## Running it

```sh
make baseline           # installs semgrep if needed, runs the rule, scores it
```

Or directly, if Semgrep is on `PATH` (or `AVE_SEMGREP` points at it):

```sh
python evals/baseline/semgrep/score.py
```

With no Semgrep available, `score.py` scores the committed `semgrep-findings.json`, so the
baseline numbers are reproducible offline and in CI.
