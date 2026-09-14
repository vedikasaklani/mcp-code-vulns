"""stdio entrypoint for the code-vulns MCP server.

Named `stdio_server.py` so every service in this fixture family shares the
same stdio entrypoint filename. Run it directly, or point an MCP client at it:
    python stdio_server.py
"""
import os

from server import mcp


def run_stdio() -> None:
    """Serve the MCP server over stdio (no ports, no network)."""
    os.environ.setdefault("MCP_TRANSPORT", "stdio")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run_stdio()