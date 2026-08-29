"""AVE — Autonomous Vulnerability Eradication.

A general-purpose vulnerability-eradication engine. It reviews a target codebase, finds
vulnerabilities a pattern scanner cannot see, and drives each one to a merged,
test-verified, class-level fix under a human governance gate.

Core naming here is deliberately language- and vuln-family-neutral (see docs on the
language-pack seam): nothing in this package is named `python`, `fastapi`, or `authz`.
The v1 vertical (Python/FastAPI, BOLA/BFLA) plugs in behind the adapter seam.
"""

__all__ = ["__version__"]

__version__ = "0.0.0"
