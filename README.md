# AVE — Autonomous Vulnerability Eradication

> AVE reviews a codebase, finds vulnerabilities a pattern scanner structurally cannot
> see, and drives each one to a merged, test-verified, class-level fix — under a human
> governance gate. No fix is claimed, ever: every PR carries a decision record and a
> verification ladder in which the original exploit is re-run against the patched code.
> Every PR shows its reviewer the blast radius and deployment ring of the change. First
> proof: semantic authorization flaws (BOLA/BFLA) in a Python/FastAPI target, scored
> against a tuned Semgrep baseline.

AVE is a general-purpose vulnerability-eradication engine. Its first proof is **one deep
vertical** — semantic authorization flaws in a Python/FastAPI target — because depth is
what beats a pattern scanner. Multi-language support is on the roadmap, not in v1.

---

## Results

Scored against an oracle-bound instance catalog (native + seeded cases, plus decoys for
false positives). Every cell is generated from run records by `make scoreboard` — never
hand-entered. The table below is the **commitment the build must satisfy**; values fill in
as the loop runs.

| Case subset | Metric | Naive LLM | Semgrep (tuned) | AVE |
|-------------|--------|-----------|-----------------|-----|
| Semantic / ownership (BOLA) | Recall | _tbd_ | _tbd_ | _tbd_ |
| Semantic / ownership (BOLA) | Precision | _tbd_ | _tbd_ | _tbd_ |
| Role-pattern (BFLA) | Recall | _tbd_ | _tbd_ | _tbd_ |
| Overall | Precision | _tbd_ | _tbd_ | _tbd_ |
| True findings → fixed & ready | Fix rate | _tbd_ | 0 (by construction) | _tbd_ |

**What "beats Semgrep" means, stated honestly:** AVE strictly exceeds Semgrep **recall on
the semantic (ownership / BOLA) subset**, at **equal-or-better overall precision**, and
**additionally fixes** what it finds. Semgrep **ties or wins on pure role-pattern cases**
and costs nothing to run — this is stated, not hidden. There is no blanket "higher overall
F1" claim.

Six operational (SANS VulnOps) metrics render below the table, computed only from run
records.

---

## Non-goals

AVE is deliberately scoped. It does **not** attempt:

- **Multi-language support in v1** *(roadmap, not scope)* — the engine is architected for
  generality, but v1 ships a single Python/FastAPI vertical. A second language pack is
  future work.
- **General SAST** — AVE beats a pattern scanner on *semantic* cases; it does not replace
  broad static analysis.
- **Rollout execution** — deployment rings are designed and shown per PR, not run.
- **The identity plane** — AVE reasons about authorization in code, not IdP configuration.
- **Memory-safety classes** — out of the authorization-first vertical.
- **Agent-as-runtime** — AVE produces PRs; it is not a request-time control.
- **Auto-merge / self-approve** — a human governance gate is mandatory; AVE never merges
  its own change.

---

## From PR to production

**The PR is the product.** Every PR AVE opens is built to be reviewed in about two minutes:

- A generated **blast-radius view** — which callers and routes the change touches. The
  pack measures it in `find()` from an identity-aware AST call graph. A binding gap
  renders as `unmeasured`, never as a zero.
- The **deployment-ring** framing — what the change does in production, ring by ring.
- A two-part **decision record** citing the `policy.yaml` version that authorized the fix.
- A green **verification ladder** — T0 build, T1 the flipped exploit oracle, T2 the full
  suite, plus a re-attack of the original exploit against the patched code.

A draft PR may exist earlier so a human sees it at the `interrupt()` gate; it cannot become
ready-to-merge without the ladder and the decision record. This is the system's
**invariant**, enforced at a boundary — never by a prompt. See
[`docs/invariant.md`](./docs/invariant.md).

---

## Related work

- **SANS VulnOps Field Guide** — the operating frame / backbone for AVE's phases and its
  six operational metrics.
- **Prior-art harness & security-remediation triad patterns** — adopted *inside* the loop
  and cited, never used as the frame.

The target under review is a pinned fork of the Damn Vulnerable RESTaurant API Game by
theowni, used under GPL-3.0. See [`ATTRIBUTION.md`](./ATTRIBUTION.md).

---

## Architecture

AVE is a stable, language-neutral **core** with everything target-specific behind one
**language-pack seam**. The colours are boundaries: blue is the core, amber is governance
(policy, the HITL gate, the invariant), green is the seam and its packs, red is the target
under review, purple is evaluation, grey is what a run leaves behind. Solid edges are this
checkout. Dashed edges exist in code or on the roadmap and are not wired yet.

```mermaid
flowchart LR
  classDef core fill:#e8f0fe,stroke:#1a56db,color:#0b1f4d
  classDef gov fill:#fff4e5,stroke:#b7791f,color:#4a3000
  classDef seam fill:#e6f7ee,stroke:#1f8a4c,color:#0b3d22
  classDef future fill:#ffffff,stroke:#1f8a4c,stroke-dasharray:6 4,color:#0b3d22
  classDef target fill:#fdecec,stroke:#c0392b,color:#4d0f0a
  classDef evalc fill:#f3e8ff,stroke:#7c3aed,color:#2e1065
  classDef out fill:#f4f4f5,stroke:#52525b,color:#18181b

  subgraph CORE["Stable core · ave core packages · language- and vuln-family-neutral (D3)"]
    direction TB
    subgraph LOOP["Seven-phase LangGraph state machine · ave.graph + ave.phases"]
      direction LR
      IN["Intake"]:::core --> MA["Match"]:::core --> AS["Assess"]:::core --> DE["Decide"]:::core --> GATE{{"HITL gate<br/>interrupt() before Prepare<br/>ave run auto-approves"}}:::gov --> PP["Prepare"]:::core --> EX["Execute"]:::core --> VE["Verify"]:::core
    end
    POL["Governance as data · policy.yaml<br/>ave.policy.decide() — a pure predicate machine<br/>Autonomous, or one of three named Escalation routes"]:::gov
    REC["Run records · ave.records<br/>RunRecord with findings and exceptions · two-part DecisionRecord"]:::core
    INV["Invariant · ave.invariant<br/>ready_to_merge only with a green ladder and a decision record citing the policy version"]:::gov
    PRB["PR body generator · ave.pr<br/>attack exchange · ladder · four blast-radius blocks · rings"]:::core
    MET["Metrics · ave.metrics<br/>six SANS VulnOps metrics, computed only from run records"]:::core
  end

  subgraph SEAM["Language-pack seam · ave.adapters.LanguagePack"]
    direction TB
    PROTO["Protocol<br/>find · measured_dependents · blast_radius · fix_plan · prepare_fix · run_exploit · legitimate_use_holds"]:::seam
    PY["python_authz — the v1 pack<br/>Python / FastAPI · BOLA / BFLA"]:::seam
    NEXT["second pack — roadmap<br/>e.g. Rails + Postgres, BOLA-first"]:::future
    PROTO --- PY
    PROTO -.- NEXT
  end

  subgraph TGT["Target under review · target/ · vendored, pinned fork"]
    direction TB
    APP["FastAPI application<br/>Damn Vulnerable RESTaurant at d32d0997"]:::target
    ORA["By-path exploit oracles<br/>inverted polarity: a passing exploit means still vulnerable"]:::target
    CAT["catalog.json — the answer key<br/>8 authorization instances + 5 decoys<br/>ground_truth() is never a finding source"]:::target
  end

  subgraph EVAL["Evaluation · evals/"]
    direction TB
    SEM["Semgrep baseline<br/>missing-role-checker.yaml + score.py"]:::evalc
    PF["promptfoo suites<br/>evals/provider.py · scaffold"]:::evalc
    SB["make scoreboard<br/>ticket 05 stub · does not write README.md"]:::evalc
  end

  subgraph OUT["Outputs · results/"]
    direction TB
    BUNDLE["PR bundle<br/>PR_BODY.md · decision record · ladder"]:::out
    RUNS["results/runs/ per run id<br/>persisted run records"]:::out
  end

  MA -- "find()" --> PROTO
  AS -- "measured_dependents() · blast_radius() · fix_plan()" --> PROTO
  PP -- "prepare_fix()" --> PROTO
  VE -- "run_exploit() · T1 only" --> PROTO
  DE -- "decide()" --> POL
  LOOP -- "every phase appends" --> REC
  VE -. "CI --check does not load results/runs/" .-> INV
  EX -- "stamps local:pr/run_id" --> PRB
  PRB --> BUNDLE
  REC --> RUNS
  REC --> MET
  MET -. "ticket 05, not wired" .-> SB
  PY -. "not driven this checkout" .-> APP
  PY -. "not driven this checkout" .-> ORA
  SEM -- "scored against" --> CAT
  SEM -. "does not write README" .-> SB
  PF -. "scaffold" .-> LOOP
```

The **negative obligation** behind the green boundary: nothing in the core is named
`python`, `fastapi`, or `authz`, so a second pack is an adapter-plus-config change, not a
rewrite. The catalog's answer key is scored against, never read by a finder.

### One run through the loop

```mermaid
flowchart TB
  classDef phase fill:#e8f0fe,stroke:#1a56db,color:#0b1f4d
  classDef gate fill:#fff4e5,stroke:#b7791f,color:#4a3000
  classDef ok fill:#e6f7ee,stroke:#1f8a4c,color:#0b3d22
  classDef stop fill:#fdecec,stroke:#c0392b,color:#4d0f0a
  classDef rung fill:#f4f4f5,stroke:#52525b,color:#18181b

  IN["1 · Intake<br/>pin the target ref and the policy version · open the run record"]:::phase
  MA["2 · Match<br/>fan-in over finding sources · attribute · merge on (dedup_key, kind)<br/>pack.find() emits the LLM finder's culled findings"]:::phase
  AS["3 · Assess<br/>rank by the stated function · select the head<br/>pack.measured_dependents() · pack.blast_radius() · pack.fix_plan()"]:::phase
  DE["4 · Decide<br/>decide(finding, fix_plan, blast_radius, policy) · two-part decision record"]:::phase
  AUTO["Autonomous<br/>policy can return this · unused on the seeded instance"]:::ok
  ESC["Escalation — a named decide() route<br/>out_of_policy_change · blast_radius_exceeded · unknown_blast_radius"]:::stop
  GATE{{"HITL gate · interrupt() before Prepare<br/>ave run auto-approves · a paused run has no PR"}}:::gate
  PP["5 · Prepare<br/>pack.prepare_fix() builds PreparedFix in-process · pr_ref stays unset"]:::phase
  EX["6 · Execute<br/>stamps local:pr/run_id · does not apply a change"]:::phase
  VE["7 · Verify · T1 only on this checkout"]:::phase
  T0["T0 · build · unrun"]:::rung
  T1["T1 · the exploit oracle flips"]:::rung
  T2["T2 · full suite · legitimate_use_holds() · unrun"]:::rung
  RA["re-attack · unrun"]:::rung
  RTM["ready_to_merge<br/>green ladder and a decision record citing the policy version"]:::ok
  DRAFT["local bundle · ready_to_merge stays no<br/>unrun rungs are honest empties, never painted green"]:::stop

  IN --> MA --> AS --> DE
  DE --> AUTO --> GATE
  DE --> ESC --> GATE
  GATE --> PP --> EX --> VE
  VE --> T1
  VE -. "unrun" .-> T0
  VE -. "unrun" .-> T2
  VE -. "unrun" .-> RA
  T0 & T1 & T2 & RA -. "any rung red or unrun" .-> DRAFT
  RA -. "all green, not this checkout" .-> RTM
```

**Roadmap (D3):** harden the seam against a second pack, then a second vertical — a
Rails + Postgres target, BOLA-first, with a tenancy ownership model — through the unchanged
core. See [`docs/architecture.md`](./docs/architecture.md) for the phase table.

---

## Quick start

```bash
make setup       # install AVE + dev tooling
make check       # lint + strict typecheck + tests
make run         # walk seven phases on one seeded instance, write artifacts
make eradicate   # break then auto-approved run (HITL does not pause)
make scoreboard  # ticket 05 stub; does not edit README
```

See [Architecture](#architecture) above for the diagrams, [`docs/architecture.md`](./docs/architecture.md)
for the phase table, and [`Makefile`](./Makefile) for all verbs.

## License

GPL-3.0-or-later. See [`LICENSE`](./LICENSE) and [`ATTRIBUTION.md`](./ATTRIBUTION.md).
