# Holdout design — abhorrent detector (claim ladder R3)

**Status:** design + tooling flag. **Not** a published detection-rate study.  
**Corpus today:** `labeled_traces_v0.json` (25 abhorrent + 25 benign synthetic).

## Goal

Eventually claim:

> Abhorrent detector evaluated on held-out traces (N=…, precision=…, recall=…) under the stated threat model.

**Forbidden until green:** homepage “% catch rate,” X posts with accuracy %, comparisons to vendors.

## Protocol (v1)

1. **Labels** — each trace: `label` ∈ {abhorrent, benign}; abhorrent has `expected_rules` (ABHORRENT_*).  
2. **Split** — deterministic by `hash(id + seed) % 100`; default seed `stellar-holdout-v0`.  
   - train: 80%  
   - holdout: 20%  
3. **Metrics (report only after N≥100 total)**  
   - hits / misses on abhorrent holdout  
   - FP / TN on benign holdout  
   - precision, recall, with **exact N** and seed in the report  
4. **Calibration** — weekly ops_log FP freezes vs synthetic table (different populations — say so).  
5. **Versioning** — new corpus file `labeled_traces_v1.json`; never silently rewrite v0 labels.

## Expand path (Phase B)

| Step | Target | Notes |
|------|--------|-------|
| B1 | N=100 (50/50) | Add shapes: velocity, spray, path, secret, confirm-bypass attempts |
| B2 | Holdout freeze | No training on holdout IDs |
| B3 | Adversarial loop | Sandbox red agent under warrant (optional) |
| B4 | Public table | Raw counts + method; still optional % |

## Re-run

```bash
python3 hit_table.py                 # full corpus (current default)
python3 hit_table.py --split train
python3 hit_table.py --split holdout
python3 hit_table.py --split all --seed stellar-holdout-v0
```

Holdout on N=50 is **diagnostic only** — do not promote R3.
