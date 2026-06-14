"""HOOKCRAFT MCP server — exposes build() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from hookcraft.core import build, HookcraftError


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
    def hookcraft_generate(yaml_intent: str) -> str:
        """Generate a Frida instrumentation script from a YAML intent string.

        Returns a JSON object with keys: ok, script, findings.
        """
        try:
            script, intent, findings = build(yaml_intent, strict=False)
            return json.dumps({
                "ok": not any(f.severity == "error" for f in findings),
                "target": intent.target,
                "platform": intent.platform,
                "script": script,
                "findings": [f.to_dict() for f in findings],
            })
        except HookcraftError as exc:
            return json.dumps({"ok": False, "error": str(exc)})

    app.run()
    return 0
