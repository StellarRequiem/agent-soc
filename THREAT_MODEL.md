# Threat model — agent-soc

Local process that reads JSONL receipts and can disarm local leashes / write FREEZE files.

## Risks

- False-positive auto-freeze if `--auto-respond-high` enabled  
- Disarm only if `AGENT_SOC_AUTO_DISARM=1` (default freeze-only)  

## Non-goals

- Enterprise IR, SOAR, network IDS  
