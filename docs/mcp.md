# MCP stub

`tenaille/mcp/server_stub.py` describes four tools a future MCP server could expose. It does not start one.

| Tool | Role |
| --- | --- |
| `lookup_cve` | Return a checked-in CVE fixture. |
| `assess_inventory` | Starter checks plus both briefs for a synthetic inventory file. |
| `get_red_brief` | CVINFERNO sample brief. |
| `get_blue_brief` | CVBASTION sample brief. |

`describe_tools()` returns that list in-process. `serve()` raises `RuntimeError`.

The stub does not bind `0.0.0.0`, `127.0.0.1`, or any other address. There is no port, no API token, and no background thread.
