"""HARBNGR — adaptive inventory collector for an authorized host.

The public sample reads a fixture or runs the starter check set against it.
It does not open SSH connections.
"""

from tenaille.harbngr.recon import (
    ReconError,
    collect,
    fingerprint_summary,
    load_inventory,
    refuse_live_ssh,
    run_starter_checks,
)

__all__ = [
    "ReconError",
    "collect",
    "fingerprint_summary",
    "load_inventory",
    "refuse_live_ssh",
    "run_starter_checks",
]
