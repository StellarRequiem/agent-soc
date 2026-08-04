# Agent-plane ops log

**Purpose:** Multi-day metrics for claim ladder R3/R4 — false freezes, MTTR, arm-hours — without inventing detection rates.

**Not a SIEM.** Append-only operator notes. No PII in public forks.

## How to use

1. Copy `TEMPLATE.md` → `YYYY-Www.md` (ISO week) or `YYYY-MM-DD.md`.  
2. Log FREEZE engage/clear, FP notes, chain rotates, arm/disarm, notable denials.  
3. Weekly rollup: count freezes, FP freezes, median clear time, hours armed.

## Re-run related proofs

```bash
python3 ~/agent-soc/purple.py
python3 ~/agent-soc/hit_table.py
python3 ~/agent-soc/hit_table.py --split all
```

## Claim hygiene

- Ops log supports **calibration**, not marketing % until holdout study (see `corpora/HOLDOUT_DESIGN.md`).  
- Never paste secrets, cookies, or private URLs into committed logs.
