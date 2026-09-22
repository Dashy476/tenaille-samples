"""In-process description of future MCP tools. Does not bind a socket.

Nothing here listens on 0.0.0.0 or any other address. `serve()` refuses.
"""

from __future__ import annotations

TOOLS = (
    {
        "name": "lookup_cve",
        "description": "Return a checked-in CVE fixture. No live NVD, OSV, KEV, or EPSS call.",
        "input": {"cve_id": "string"},
    },
    {
        "name": "assess_inventory",
        "description": "Run starter checks and both briefs against a synthetic inventory file.",
        "input": {"inventory_path": "string"},
    },
    {
        "name": "get_red_brief",
        "description": "CVINFERNO sample brief for a synthetic inventory. Hypotheses only.",
        "input": {"inventory_path": "string"},
    },
    {
        "name": "get_blue_brief",
        "description": "CVBASTION sample brief for the same inventory. Detection and remediation.",
        "input": {"inventory_path": "string"},
    },
)


def describe_tools() -> list[dict]:
    """Return the tool list a future MCP server would advertise."""
    return [dict(item) for item in TOOLS]


def serve(*_args, **_kwargs) -> None:
    """Refuse to start a network service."""
    raise RuntimeError(
        "Tenaille MCP stub: not starting a listener. "
        "No bind to 0.0.0.0, 127.0.0.1, or any other address. See docs/mcp.md."
    )
