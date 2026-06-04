# Architecture

How the Elder Mind Governance Harness is put together, in diagrams.

## Where it sits — the wedge

Governance runs **as the agent's own pre-tool-use hook**, locally, not at a cluster control plane.

```mermaid
flowchart TB
    subgraph cluster["Cluster overlays (govern deployed workloads)"]
        A1[Deployed agent] -->|phones home| CP[Policy control plane: K8s, network, infra]
    end
    subgraph local["Elder Mind — local, in the dev loop"]
        DEV[You + Claude Code / OpenCode / Kiro] --> AGENT[Agent decides to run a tool]
        AGENT --> GATE{{pre-tool hook}}
        GATE -->|allow| EXEC[Tool executes]
        GATE -->|block| STOP[blocked + OWASP-mapped reason]
    end
    style GATE fill:#ff6b35,color:#fff
    style STOP fill:#c1121f,color:#fff
```

## Runtime loop — every tool call

```mermaid
sequenceDiagram
    participant A as Coding Agent
    participant H as Pre-Tool Hook (per harness)
    participant G as evaluate() (gate.py)
    participant D as decide() — deterministic
    participant S as supply-chain (OSV, opt-in)
    participant L as audit.jsonl
    A->>H: wants to run a tool (e.g. force-push, install)
    H->>G: {action, target, context}
    G->>D: policy match + impact×likelihood + detectors (offline)
    D-->>G: verdict + ASI tag + decision id
    G->>S: if enabled & install cmd → OSV check (curated override + API)
    S-->>G: clean / vulnerable / malicious
    G->>L: append decision (id, score, ASI, supply-chain, detectors)
    G-->>H: final verdict + reason + exit code
    H-->>A: allow / warn / ask / block (native)
    Note over A,L: decide() is offline & reproducible; only the opt-in OSV step may use the network.
```

## Component anatomy

```mermaid
flowchart LR
    subgraph core["eldermind/ (stdlib + pyyaml)"]
        POL[policy.py] --> DEC[decide.py]
        RE[risk_engine.py] --> DEC
        DET[detectors.py] --> DEC
        DEC --> GATE[gate.py: evaluate]
        SC[supplychain.py — OSV] --> GATE
        GATE --> AUD[audit.py JSONL]
        GATE --> CLI[cli.py — hook target]
        CFG[config.py] --> GATE
    end
    subgraph mcp["MCP server (optional)"]
        GC[govern_check]
        CO[council_review — BYO-LLM]
        SCAN[scan]
    end
    subgraph adapters["pre-tool hooks (hard gate)"]
        CC[Claude Code PreToolUse]
        OC[OpenCode tool.execute.before]
        KI[Kiro preToolUse]
    end
    CC --> CLI
    OC --> CLI
    KI --> CLI
    GC --> GATE
    CO --> COUNCIL[council.py]
    style GATE fill:#ff6b35,color:#fff
    style DEC fill:#06d6a0,color:#000
```

`decide()` is the pure, offline brain (policy + risk + detectors). `gate.evaluate()` wraps it and adds the optional, network-touching supply-chain check. Hooks hard-block; the MCP server is advisory.

## Decision engine

```mermaid
flowchart TB
    IN[tool call] --> M{policy match?}
    M -->|no| ALLOW1[allow — fail-open low-risk]
    M -->|yes| RULE[rule → impact, likelihood, ASI, action-floor]
    RULE --> SCORE["score = impact × likelihood (1–25)"]
    SCORE --> TIER{escalation tier}
    TIER -->|1-4| T1[auto_approve → allow]
    TIER -->|5-9| T2[notify_after → warn]
    TIER -->|10-14| T3[review → ask]
    TIER -->|15-19| T4[elevated_review → ask]
    TIER -->|20-25| T5[block_critical → block]
    T1 & T2 & T3 & T4 & T5 --> FLOOR[max of rule floor, tier, detector — never relax below floor]
    FLOOR --> SCAN{supply-chain enabled & install?}
    SCAN -->|malicious| BLK[escalate → block]
    SCAN -->|else| OUT[Decision + exit code + audit]
    BLK --> OUT
    style SCORE fill:#118ab2,color:#fff
    style OUT fill:#ff6b35,color:#fff
```

## Standards as a loop (NIST AI RMF backbone)

```mermaid
flowchart LR
    G[GOVERN: versioned policy.yaml + config + threat model] --> MA[MAP: ASI→rule mapping]
    MA --> ME[MEASURE: audit log + decision ids + summary aggregates]
    ME --> MN[MANAGE: gate verdict + supply-chain + council]
    MN --> G
    style MN fill:#ff6b35,color:#fff
```

See [`STANDARDS-MAP.md`](STANDARDS-MAP.md) for the honest per-ASI coverage and [`../THREAT_MODEL.md`](../THREAT_MODEL.md) for the trust boundary.
