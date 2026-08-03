#!/usr/bin/env python3
"""Offline purple runner for abhorrent detector fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from detect import detect  # noqa: E402

FIXTURE = ROOT / "purple_fixtures" / "abhorrent_shapes.json"
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main() -> int:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    failed = 0
    for case in data.get("cases") or []:
        cid = case.get("id")
        out = detect(case.get("events") or [])
        rules = {a.get("rule") for a in out.get("alerts") or [] if a.get("rule") != "QUIET"}
        expect = set(case.get("expect_rules") or [])
        min_sev = case.get("expect_min_severity") or "info"
        ok_rules = expect.issubset(rules) if expect else (len(rules) == 0 or rules == set())
        # quiet case: no non-info alerts
        if not expect:
            ok_rules = out.get("alert_count", 0) == 0
        ok_sev = SEV.get(out.get("severity"), 0) >= SEV.get(min_sev, 0) if expect else out.get("severity") == "info"
        # if expect rules, severity must meet min
        if expect and not ok_sev:
            failed += 1
            print(f"FAIL {cid}: severity {out.get('severity')} < {min_sev} rules={rules}")
            continue
        if not ok_rules:
            failed += 1
            print(f"FAIL {cid}: rules {rules} expected {expect}")
            continue
        print(f"PASS {cid}: severity={out.get('severity')} rules={sorted(rules)}")
    print(f"purple_abhorrent={'PASS' if failed == 0 else 'FAIL'} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
