# `prompts/` — prompts-as-code

Reasoning prompts for the AVE graph live here as versioned files, indexed by
[`manifest.json`](./manifest.json). Keeping prompts as code makes them diffable and lets
the eval suites address them by id.

**Status (v1): internal-first.** The prompt-manifest tooling is *not* a committed
compounding export — it is promoted to one only if a later project actually needs it
(a locked Phase 0 decision, to avoid over-promising a tool nobody asked for).
