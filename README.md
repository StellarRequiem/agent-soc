# agent-soc — Agent-plane Security Operations

**Not** an enterprise SIEM/EDR/IR platform.  
**Is** a local SOC for **this machine’s control planes**:

- browser-leash receipts  
- desktop-leash receipts  
- agent-control plane-host receipts  
- mcp-assure FREEZE / receipts  

## What “full SOC capability” means here

| SOC function | Implementation |
|--------------|----------------|
| Collect | Tail JSONL receipts across planes |
| Detect | Rules: deny spikes, high-blast, NOT_ARMED floods, unknown tools, velocity |
| Respond | Write FREEZE, disarm browser+desktop, open incident record |
| Report | CLI status / incidents / last events |

## Claim ceiling

> Agent-plane SOC for local control surfaces — collect, detect, respond (freeze/disarm).  
> Not a full enterprise SOC. Not stop-all-attacks.

## Quick start

```bash
python3 ~/agent-soc/cli.py status
python3 ~/agent-soc/cli.py collect
python3 ~/agent-soc/cli.py detect
python3 ~/agent-soc/cli.py respond --disarm-all --reason "hold-test"
python3 ~/agent-soc/cli.py incidents
```

## Architecture

See `ARCHITECTURE.md` · Plan `~/ops/CUA_AND_AGENT_SOC_PLAN.md`
