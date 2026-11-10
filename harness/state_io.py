"""Load harness account/address fixtures from env or a local gitignored state dir.

Test-run account ids and Solana addresses used to live as tracked dot-files in the repo
root. They are public identifiers, not secrets, but they are local fixtures: noise for a
reader and a hard tie to one lab's wallets. Harness scripts therefore read them from
`harness/.state/` (gitignored) or from environment overrides listed below.

Set `LEASH_STATE_DIR` to point at another directory if needed.
"""
from __future__ import annotations

import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATE_DIR = os.environ.get("LEASH_STATE_DIR", os.path.join(HERE, ".state"))

# Filename in harness/.state/ -> preferred environment override.
# Existing LEASH_CONTRACT / LEASH_ADDRESS / LEASH_RECIPIENT names are kept.
_ENV_FOR = {
    ".contract-account": "LEASH_CONTRACT",
    ".solana-address": "LEASH_ADDRESS",
    ".allowed-recipient": "LEASH_RECIPIENT",
    ".agent-account": "LEASH_AGENT",
    ".owner-account": "LEASH_OWNER",
    ".denied-recipient": "LEASH_DENIED_RECIPIENT",
    ".attack-account": "LEASH_ATTACK",
    ".locked-account": "LEASH_LOCKED",
    ".spent-account-locked-with-rogue": "LEASH_ROGUE_ACCOUNT",
    ".policybound-account": "LEASH_POLICYBOUND_ACCOUNT",
    ".policybound-address": "LEASH_POLICYBOUND_ADDRESS",
}


def rd(name: str) -> str:
    """Read a fixture: env override first, then `harness/.state/<name>`."""
    env_key = _ENV_FOR.get(name)
    if env_key:
        val = os.environ.get(env_key)
        if val:
            return val.strip()
    path = os.path.join(STATE_DIR, name)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError as e:
        raise SystemExit(
            "missing harness fixture %r (looked in %s). "
            "Copy local account/address files into harness/.state/ or set %s. "
            "See docs/RUNBOOK.md."
            % (name, STATE_DIR, env_key or "LEASH_STATE_DIR")
        ) from e
