# Claim gate — agent-soc

## Allowed

| Claim | Evidence |
|-------|----------|
| Collects local control-plane receipts | `collect.py` |
| Detects simple abuse shapes (deny spikes, high-blast churn) | `detect.py` |
| Responds with FREEZE + optional disarm + incidents | `respond.py` |
| Continuous watch ticks | `watch.py` |

## Not allowed

| Overclaim |
|-----------|
| Full enterprise SOC / SIEM / EDR |
| Stops all agent attacks |
| Network/cloud monitoring product |

## Wording

> **agent-soc** is a local **agent-plane** SOC for control-plane receipts: collect, detect, respond (freeze/disarm). Not an enterprise SIEM.
