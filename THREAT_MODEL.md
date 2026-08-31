# Threat model — agent-soc

Local process that reads JSONL receipts and can disarm local leashes / write FREEZE files.

## Risks

- False-positive auto-freeze if `--auto-respond-high` enabled  
- Disarm only if `AGENT_SOC_AUTO_DISARM=1` (default freeze-only)  
- Passport roster (`passports.json`) is host-stamped `actor` only — not a request header. Missing actor stays unlabeled. Passport does not skip secret/path/exec/highblast rules.  

## Non-goals

- Enterprise IR, SOAR, network IDS  
- Detection-rate claims or “full SOC”
