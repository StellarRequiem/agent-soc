#!/usr/bin/env python3
"""agent-soc CLI — agent-plane collect / detect / respond."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from collect import collect  # noqa: E402
from detect import detect  # noqa: E402
from lockdown import lockdown_clear, lockdown_engage, lockdown_status  # noqa: E402
from respond import clear_freeze, list_incidents, respond  # noqa: E402
from watch import watch_loop, watch_once  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agent-soc")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="collect+detect summary")
    sub.add_parser("collect")
    sub.add_parser("detect")
    r = sub.add_parser("respond")
    r.add_argument("--reason", default="operator respond")
    r.add_argument("--disarm-all", action="store_true")
    r.add_argument("--freeze", action="store_true", default=True)
    r.add_argument("--no-freeze", action="store_true")
    r.add_argument("--no-disarm", action="store_true")
    w = sub.add_parser("watch", help="continuous collect/detect (JSONL ticks)")
    w.add_argument("--interval", type=float, default=30.0, help="seconds between ticks")
    w.add_argument("--once", action="store_true", help="single tick then exit")
    w.add_argument(
        "--auto-respond-high",
        action="store_true",
        help="on high/critical: FREEZE (disarm only if AGENT_SOC_AUTO_DISARM=1)",
    )
    w.add_argument("--max-ticks", type=int, default=None, help="stop after N ticks")
    w.add_argument("--reason", default="agent-soc watch")
    sub.add_parser("incidents")
    sub.add_parser("clear-freeze", help="remove FREEZE files (operator recovery)")
    sub.add_parser("claim", help="print claim ceiling")
    # Phase C — abhorrent lockdown
    ld = sub.add_parser("lockdown", help="abhorrent mediated-plane lockdown status/engage/clear")
    ld.add_argument(
        "action",
        nargs="?",
        default="status",
        choices=["status", "engage", "clear"],
        help="status (default) | engage | clear",
    )
    ld.add_argument("--reason", default="abhorrent lockdown")
    ld.add_argument(
        "--disarm",
        action="store_true",
        help="also disarm leashes (default freeze-only)",
    )
    ld.add_argument(
        "--force",
        action="store_true",
        help="engage even if detectors do not recommend",
    )

    args = p.parse_args(argv)

    if args.cmd == "claim":
        print(
            json.dumps(
                {
                    "is": "agent-plane SOC (collect/detect/respond on local control receipts)",
                    "is_not": [
                        "enterprise SIEM",
                        "EDR",
                        "network SOC",
                        "stop-all-attacks guarantee",
                    ],
                    "phase_c": "abhorrent lockdown on mediated MCP/agent tool shapes (FREEZE ± disarm)",
                    "pairs_with": ["mcp-assure", "browser-leash", "desktop-leash", "agent-control CUA"],
                },
                indent=2,
            )
        )
        return 0

    if args.cmd == "collect":
        print(json.dumps(collect(), indent=2)[:20000])
        return 0

    if args.cmd == "detect":
        c = collect()
        print(json.dumps(detect(c.get("events") or []), indent=2)[:20000])
        return 0

    if args.cmd == "status":
        c = collect()
        d = detect(c.get("events") or [])
        print(
            json.dumps(
                {
                    "ok": True,
                    "service": "agent-soc",
                    "events": c.get("count"),
                    "files": c.get("files"),
                    "severity": d.get("severity"),
                    "alerts": d.get("alerts"),
                    "stats": d.get("stats"),
                    "claim_ceiling": {
                        "agent_plane_soc": True,
                        "enterprise_soc": False,
                    },
                },
                indent=2,
            )[:20000]
        )
        return 0

    if args.cmd == "respond":
        c = collect()
        d = detect(c.get("events") or [])
        out = respond(
            reason=args.reason,
            freeze=not args.no_freeze,
            disarm=bool(args.disarm_all) and not args.no_disarm,
            alerts=d.get("alerts"),
        )
        print(json.dumps(out, indent=2)[:20000])
        return 0

    if args.cmd == "watch":
        if args.once:
            out = watch_once(
                auto_respond_high=args.auto_respond_high,
                reason=args.reason,
            )
            # already printed by watch_once log; also pretty
            print(json.dumps(out, indent=2)[:12000])
            return 0
        return watch_loop(
            interval_sec=args.interval,
            auto_respond_high=args.auto_respond_high,
            max_ticks=args.max_ticks,
            reason=args.reason,
        )

    if args.cmd == "incidents":
        print(json.dumps(list_incidents(), indent=2)[:20000])
        return 0

    if args.cmd == "clear-freeze":
        print(json.dumps({"ok": True, "cleared": clear_freeze()}, indent=2))
        return 0

    if args.cmd == "lockdown":
        if args.action == "status":
            print(json.dumps(lockdown_status(), indent=2, default=str)[:20000])
            return 0
        if args.action == "engage":
            out = lockdown_engage(
                reason=args.reason,
                disarm=bool(args.disarm),
                force=bool(args.force),
            )
            print(json.dumps(out, indent=2, default=str)[:20000])
            return 0 if out.get("ok") else 1
        if args.action == "clear":
            print(json.dumps(lockdown_clear(reason=args.reason), indent=2)[:8000])
            return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
