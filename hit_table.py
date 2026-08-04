#!/usr/bin/env python3
"""Hit table for labeled_traces_v0 — counts hits/misses/false positives.

Does NOT publish accuracy % as a product claim. Reports raw counts for a fixed
synthetic corpus so third parties can re-run the same table.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from detect import detect  # noqa: E402

CORPUS = ROOT / "corpora" / "labeled_traces_v0.json"


def main() -> int:
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    traces = data.get("traces") or []
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
            # benign: any abhorrent rule is FP
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
        "corpus": str(CORPUS.name),
        "n_abhorrent": n_abh,
        "n_benign": n_ben,
        "hits": hits,
        "misses": misses,
        "false_positives": fps,
        "true_negatives": tns,
        "note": (
            "Synthetic fixed corpus — not a holdout study, not a published detection rate. "
            "Re-run: python3 hit_table.py"
        ),
        "rows": rows,
    }
    print(json.dumps(report, indent=2)[:50000])
    outp = ROOT / "corpora" / "hit_table_latest.json"
    outp.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # human summary line
    print(
        f"\nhit_table hits={hits}/{n_abh} misses={misses} "
        f"fp={fps}/{n_ben} tn={tns} ok={report['ok']}",
        file=sys.stderr,
    )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
