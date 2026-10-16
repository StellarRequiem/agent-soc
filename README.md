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
python3 ~/agent-soc/cli.py respond --dry-run --reason "plan only"
python3 ~/agent-soc/cli.py respond --disarm-all --reason "hold-test"
python3 ~/agent-soc/cli.py agentic cycle --dry-run
python3 ~/agent-soc/cli.py agentic cycle          # FREEZE if high/critical (disarm if AGENT_SOC_AUTO_DISARM=1)
python3 ~/agent-soc/cli.py lockdown engage --dry-run
python3 ~/agent-soc/cli.py incidents
```

### Configurable receipt sources

```bash
# env: name:path pairs
export AGENT_SOC_RECEIPT_SOURCES="browser-leash:$HOME/browser-leash/receipts,agent-control:$HOME/agent-control/receipts"
# or JSON file: {"sources":{"browser-leash":"/path"}}
export AGENT_SOC_SOURCES_FILE=~/agent-soc/sources.example.json
```

### Glossary — hit table

**Hit table** in this repo = a **re-runnable synthetic fixture** (`hit_table.py` + labeled corpora) proving detectors fire on known shapes.  
It is **not** a published production detection rate or enterprise SOC KPI.

### Env

| Var | Meaning |
|-----|---------|
| `AGENT_SOC_AUTO_DISARM` | `1`/`true` — allow disarm in watch/agentic after high streak |
| `AGENT_SOC_RECEIPT_SOURCES` | Override collect paths |
| `AGENT_SOC_SOURCES_FILE` | JSON map of sources |

## Architecture

See `ARCHITECTURE.md` · Plan `~/ops/CUA_AND_AGENT_SOC_PLAN.md`  
Batch-1 backlog: `~/ops/GROK_CONVERSATION_NOTES_2026-08-04.md`


## License

Apache-2.0
