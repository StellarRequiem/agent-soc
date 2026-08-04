# Claim gate — agent-soc

## Allowed

| Claim | Evidence |
|-------|----------|
| Collects local control-plane receipts | `collect.py` |
| Detects simple abuse shapes (deny spikes, high-blast churn) | `detect.py` |
| Detects abhorrent MCP shapes (secret/path/template/shell spray) | `abhorrent.py` + tests + `purple.py` |
| Synthetic labeled corpus hit table (25/25) | `corpora/labeled_traces_v0.json` · `hit_table.py` — **not** a published accuracy % |
| Responds with FREEZE + optional disarm + incidents | `respond.py` |
| Lockdown status/engage/clear surface | `lockdown.py` · `cli.py lockdown` |
| Continuous watch; auto-FREEZE only on abhorrent class | `watch.py` |

## Not allowed

| Overclaim |
|-----------|
| Full enterprise SOC / SIEM / EDR |
| Stops all agent attacks |
| Network/cloud monitoring product |
| Content moderation of all model text |

## Wording

> **agent-soc** is a local **agent-plane** SOC for control-plane receipts: collect, detect, abhorrent-shape lockdown (FREEZE ± disarm). Not an enterprise SIEM.
