"""
mcp_server.py
--------------
Exposes dummy_tools.py over the Model Context Protocol (MCP) using FastMCP.

Run standalone for debugging:
    python tools_server/mcp_server.py

The Worker agent (agents/worker_agent.py) connects to this exact script as
a subprocess via stdio, the same way it would connect to any real MCP
server (e.g. a Gmail or filesystem MCP server). This is what satisfies the
"MCP Server" requirement of the capstone rubric -- tools are not hard-wired
function calls inside the agent, they're served over the protocol.
"""

from mcp.server.fastmcp import FastMCP
from dummy_tools import search_web, read_file, send_email, transfer_funds, execute_shell

mcp = FastMCP("sentinel-demo-tools")

# Register each dummy tool as an MCP tool. FastMCP derives the tool's
# name/description/schema from the function signature and docstring,
# same as ADK does for native function tools.
mcp.tool()(search_web)
mcp.tool()(read_file)
mcp.tool()(send_email)
mcp.tool()(transfer_funds)
mcp.tool()(execute_shell)

if __name__ == "__main__":
    # stdio transport: the parent process (the ADK agent) talks to us
    # over stdin/stdout, exactly like a real local MCP server.
    mcp.run(transport="stdio")
