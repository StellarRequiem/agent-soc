# Abhorrent lockdown (mediated plane)

Local watch over control-plane receipts. **Not** a full SOC, SIEM, or EDR.
**Not** a published detection-rate claim.

## Catalog-spray thresholds (honest)

| Rule | Window | Threshold | Notes |
|------|--------|-----------|--------|
| `UNKNOWN_TOOL_ATTEMPTS` | last 200 | **≥3** unlabeled / non-passport | high; watch does **not** auto-freeze on this alone |
| `ABHORRENT_TOOL_SPRAY` | last 200 | **≥5** unlabeled / non-passport | critical; watch auto-FREEZE when abhorrent class fires |

Code is the source of truth: spray is **≥5**, not ≥8. Phase C originally used ≥8; `tests/test_abhorrent.py::test_tool_spray_at_8` still has that name but the fixture is 5 unlabeled events. Docs that said ≥8 were stale relative to `abhorrent.py`.

## Internal-agent passport

File: `passports.json` (next to `passports.py`). Operator-editable on disk.
Default roster: `grok`, `claude`, `codex`.

`collect.py` copies the host-stamped receipt `actor` field. The Grok MCP host stamps `actor="grok"` (not a request header a client can set). Purple fixtures that use `actor="agent"` are **not** on the roster.

### What a passport grants

UNKNOWN_TOOL events from roster actors are **excluded** from:

- `ABHORRENT_TOOL_SPRAY`
- `UNKNOWN_TOOL_ATTEMPTS`

So an internal MCP client listing/alias-missing pack tools (browser.press, browser.hover, browser.workspace, …) does not catalog-spray freeze the operator Mac.

### What a passport does not grant

- Deny-by-default: missing/empty `actor`, `actor="agent"`, or anything **not** on the roster still counts toward the unlabeled thresholds above.
- No exemption from `ABHORRENT_SECRET_SHAPE`, `ABHORRENT_SHELL_BYPASS`, `ABHORRENT_PATH_SMELL`, `ABHORRENT_TEMPLATE_SMELL`, or `ABHORRENT_HIGHBLAST_SPRAY` — including when `actor=grok`.
- Not a full SOC. Not a claim that worms cannot stamp a roster name if they can write receipts.

Edit the roster on disk (`actors: []` means no passports). Do not treat HTTP/MCP headers as identity.
