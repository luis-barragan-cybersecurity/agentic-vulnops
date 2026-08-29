# Seeded-instance catalog + exploit oracles

The benchmark AVE is scored against: the authorization gaps in the vendored
[Damn Vulnerable RESTaurant](dvrestaurant/) fork (pinned at `d32d0997…`), each **bound to
an exploit-test oracle**, plus **decoys** — correct-but-non-standard authz that a good
agent must *not* flag. The machine-readable source of truth is
[`catalog.json`](catalog.json); this file is its readable face.

## How the oracles work (two gotchas from the survey)

1. **Not auto-collected.** The exploit files do not match pytest's `python_files` glob, so
   a bare `pytest` run skips them. Each is invoked **by path**.
2. **Inverted polarity.** A **passing** exploit test means the target is **still
   vulnerable**; the test **fails** once the intended fix lands. An oracle harness reads
   "fail" as "fixed", and separately requires the module regression suite to stay green.

Run an oracle in the target's **pinned env** (faithful):
`docker compose run web pytest app/tests/vulns/<file>.py` from `dvrestaurant/`.
Or **locally** from `dvrestaurant/app` with `DB_BACKEND=memory ENV=testing` and `bcrypt==4.0.1`:
`python -m pytest tests/vulns/<file>.py`.

## Instances (8) — what AVE must find and fix

| id | family | endpoint | origin | scanner-blind | oracle | flip verified |
|----|--------|----------|--------|:---:|--------|:---:|
| **I-04** *(loop anchor)* | BOLA | `GET /orders/{id}` | latent-native | ✅ | `ave_seed_bola_order_read.py` | ✅ 200→404 |
| I-02 | BOLA | `PUT /profile` | native | ✅ | `level_2_..._IDOR.py` | upstream-blessed |
| I-01 | BFLA | `DELETE /menu/{id}` | native | — | `level_1_....py` | ✅ vuln green |
| I-03 | BFLA | `PUT /users/update_role` | native | ✅ | `level_3_....py` | upstream-blessed |
| I-05 | BFLA | `GET /delivery/orders` | latent-native | ✅ | `ave_seed_bfla_delivery_orders.py` | ✅ 200→401 |
| I-06 | BOLA | `GET /discount-coupons?user_id=` | **seeded** | ✅ | `ave_seed_bola_discount_coupons.py` | ✅ →empty |
| I-07 | BOLA | `GET /referral-code?username=` | **seeded** | ✅ | `ave_seed_bola_referral_code.py` | ✅ →own code |
| I-08 | BFLA | `PUT /menu/{id}` | **seeded** | — | `ave_seed_bfla_menu_update.py` | ✅ 200→403 |

**origin** — `native`: a challenge level upstream ships and blesses; `latent-native`: a real
gap upstream left in the code but never wrote a test for (AVE binds the oracle);
`seeded`: a gap AVE introduced as a localized one-file diff (GPL §5-marked in the file).

**scanner-blind** — ✅ means a role/pattern rule structurally cannot see it: the role check
is present and passing, and the missing thing is an *ownership predicate* (BOLA) or an
un-schema'd route (I-05). These are the cases that justify AVE over a pattern scanner. The
two `—` rows (commented-out decorator) are the pattern-visible end, kept for BFLA balance.

**flip verified** — `✅` oracles were run this session against the vendored target
(vulnerable state green; the intended fix applied to a throwaway copy turns them red) using
the local in-memory harness. `upstream-blessed`: native PUT-body oracles (I-02, I-03) whose
polarity is guaranteed by upstream's own game harness; they were not re-run locally because
that plumbing needs the pinned httpx/pydantic-v1 env (see the caveat below). See
`.scratch/ave-build/issues/04-...` for the full verification record.

### The loop anchor (I-04)

AVE's end-to-end loop (`make run` / `make check`) drives **I-04** — the `get_order`
object-ownership gap. Its hermetic in-process oracle is
`ave.adapters.python_authz._skeleton_target`, an in-process model of exactly this gap, kept
so `make check` runs without standing up the target's environment. The **canonical**
by-path oracle for I-04 is `ave_seed_bola_order_read.py`, run in the target's pinned env.
Wiring the loop to execute the by-path oracles of the *other* seven instances in the
target's pinned env is deliberately **not** part of this catalog — it is the next
deepening (find-stage / execution), tracked on the build map.

## Decoys (5) — correct-but-non-standard authz; must NOT be flagged

| id | endpoint | why it is correct |
|----|----------|-------------------|
| D-01 | `GET /admin/stats/disk` | Inline `role != CHEF` compare instead of the checker — correct authz, non-standard shape. |
| D-02 | `GET /admin/reset-chef-password` | Network-origin gate (`127.0.0.1`), not a role — deliberately not user-role authz. |
| D-03 | `GET /orders/status/{id}` | Hand-rolled ownership (`user_id != current_user.id`) — the correct inverse of I-04. |
| D-04 | `GET /orders` | Correct ownership filter (`user_id == current_user.id`) — the right way to do I-04/I-06. |
| D-05 | `PATCH /profile` | Correct ownership; its `Extra.allow` mass-assignment is authz-adjacent but not a missing object/function check. |

## Licensing / provenance

The target is GPL-3.0. Every file AVE modified to seed an instance carries a GPL §5
change-marking header (dated 2026-08-29). Upstream provenance and the full obligation list
are in [`dvrestaurant/`'s README](dvrestaurant/README.md), this repo's
[`ATTRIBUTION.md`](../ATTRIBUTION.md), and [`README.md`](README.md).

## Local-run caveat (honesty note)

This session verified oracle **flips** with a local in-memory harness under a *modern*
interpreter (Python 3.14, fastapi 2.x/pydantic v2), because the target's pinned interpreter
(3.10 + pydantic v1) and Docker were not available here. Under that drift, native oracles
that send a request **body with `content=`** (I-02, I-03, and one upstream module test)
return 422 from request-validation plumbing — an artifact of the httpx/pydantic version
gap, **not** an authz behavior change (verified: the same failures occur on the pristine
clone before any AVE change). All AVE-**seeded** oracles use GET or `json=` bodies and flip
cleanly under both envs. The faithful, canonical runner remains the target's pinned
Docker/Poetry environment.
