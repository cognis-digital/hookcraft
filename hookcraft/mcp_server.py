"""HOOKCRAFT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from hookcraft.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-hookcraft[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-hookcraft[mcp]'")
        return 1
    app = FastMCP("hookcraft")

    @app.tool()
    def hookcraft_scan(target: str) -> str:
        """Generates ready-to-run Frida instrumentation scripts from a YAML intent (e.g. 'bypass SSL pinning', 'dump crypto keys') and verifies they attach to a target process.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
