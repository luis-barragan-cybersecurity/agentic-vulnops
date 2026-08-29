"""The language-pack seam — named here, deliberately **not designed** (D3).

A future "language pack" plugs a new language into AVE's stable core by supplying:

  - finding sources (rule + model findings for that language/stack),
  - an exploit-oracle harness (how an exploit test is written and its polarity read),
  - blast-radius extraction (caller graph / route map for that stack),
  - fix templates (what a class-level fix looks like there).

v1 ships exactly one adapter — the Python/FastAPI BOLA/BFLA vertical — and its only
obligation to the vision is **negative**: the core must not bake in `python`, `fastapi`,
or `authz`. The real interface cannot be seen until the FastAPI walking skeleton (ticket
03) shows what is genuinely Python-specific, so no `Protocol` is defined yet — only this
seam is reserved.
"""
