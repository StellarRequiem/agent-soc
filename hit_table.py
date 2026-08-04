#!/usr/bin/env python3
"""Hit table for labeled_traces_v0 — counts hits/misses/false positives.

Does NOT publish accuracy % as a product claim. Reports raw counts for a fixed
synthetic corpus so third parties can re-run the same table.

Optional deterministic split (see corpora/HOLDOUT_DESIGN.md):
  python3 hit_table.py --split holdout
Holdout on N=50 is diagnostic only — not claim ladder R3.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from detect import detect  # noqa: E402

CORPUS = ROOT / "corpora" / "labeled_traces_v0.json"
DEFAULT_SEED = "stellar-holdout-v0"


def _bucket(tid: str, seed: str) -> int:
    h = hashlib.sha256(f"{seed}:{tid}".encode("utf-8")).hexdigest()
    return int(h[:8], 16) % 100


def _select(traces: list, split: str, seed: str) -> list:
    if split == "all":
        return list(traces)
    out = []
    for t in traces:
        b = _bucket(str(t.get("id") or ""), seed)
        # 80/20 train/holdout
        in_holdout = b >= 80
        if split == "holdout" and in_holdout:
            out.append(t)
        elif split == "train" and not in_holdout:
            out.append(t)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Abhorrent detector hit table (synthetic)")
    ap.add_argument(
        "--split",
        choices=("all", "train", "holdout"),
        default="all",
        help="deterministic corpus split (default all)",
    )
    ap.add_argument("--seed", default=DEFAULT_SEED, help="split seed")
    ap.add_argument(
        "--corpus",
        default=str(CORPUS),
        help="path to labeled traces JSON",
    )
    args = ap.parse_args(argv)

    corpus_path = Path(args.corpus)
    data = json.loads(corpus_path.read_text(encoding="utf-8"))
    traces = _select(data.get("traces") or [], args.split, args.seed)
    rows = []
    hits = misses = fps = tns = 0

    for t in traces:
        tid = t.get("id")
        label = t.get("label")
        expect = set(t.get("expected_rules") or [])
        out = detect(t.get("events") or [])
        rules = {
            a.get("rule")
            for a in (out.get("alerts") or [])
            if str(a.get("rule") or "").startswith("ABHORRENT_")
        }
        if label == "abhorrent":
            ok = expect.issubset(rules) and bool(expect)
            if ok:
                hits += 1
                status = "HIT"
            else:
                misses += 1
                status = "MISS"
        else:
            if rules:
                fps += 1
                status = "FP"
            else:
                tns += 1
                status = "TN"
        rows.append(
            {
                "id": tid,
                "label": label,
                "status": status,
                "expected": sorted(expect),
                "got_abhorrent": sorted(rules),
                "severity": out.get("severity"),
            }
        )

    n_abh = sum(1 for t in traces if t.get("label") == "abhorrent")
    n_ben = sum(1 for t in traces if t.get("label") == "benign")
    report = {
        "ok": misses == 0 and fps == 0,
        "corpus": corpus_path.name,
        "split": args.split,
        "seed": args.seed,
        "n_traces": len(traces),
        "n_abhorrent": n_abh,
        "n_benign": n_ben,
        "hits": hits,
        "misses": misses,
        "false_positives": fps,
        "true_negatives": tns,
        "note": (
            "Synthetic corpus — not a published detection rate. "
            "Holdout split is diagnostic until N≥100 + study freeze. "
            "See corpora/HOLDOUT_DESIGN.md. Re-run: python3 hit_table.py"
        ),
        "rows": rows,
    }
    print(json.dumps(report, indent=2)[:50000])
    outp = ROOT / "corpora" / "hit_table_latest.json"
    outp.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"\nhit_table split={args.split} hits={hits}/{n_abh} misses={misses} "
        f"fp={fps}/{n_ben} tn={tns} ok={report['ok']}",
        file=sys.stderr,
    )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
