# `evals/` — evals-as-property

Evals are treated as **properties of the system**, run against the real graph (not mocked
prompts), and their results are generated into the README results table.

- [`promptfooconfig.yaml`](./promptfooconfig.yaml) — the promptfoo suite config (k=3, with
  a cheap tool-result screen; wired up as the loop lands).
- [`provider.py`](./provider.py) — a promptfoo custom provider that drives the real AVE
  graph.

Run with `make eval` (uses `npx promptfoo`). Scaffold only in ticket 02; the suites
sharpen once the loop runs.
