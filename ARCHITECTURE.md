# agent-soc architecture

```
receipts sources
  ~/browser-leash/receipts/*.jsonl
  ~/desktop-leash/receipts/*.jsonl
  ~/agent-control/receipts/*.jsonl
  ~/mcp-assure/**/receipts (optional)
        │
        ▼
   collect → normalize events (including host-stamped actor)
        │
        ▼
   detect → Alert[]
     (UNKNOWN_TOOL catalog-spray counts skip passports.json actors)
        │
        ▼
   respond → FREEZE + disarm leashes + incidents/*.json
        │
        ▼
   CLI / JSON status
```

Responders are **local** and **reversible** (re-arm by operator). No network block, no MDM, no EDR kill.
