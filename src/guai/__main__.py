"""Entry point: python -m guai or python -m guai.mcp.server."""

import sys

from guai.cli.main import cli

if __name__ == "__main__":
    # Support 'python -m guai mcp' to start the MCP server
    if len(sys.argv) > 1 and sys.argv[1] == "mcp":
        from guai.mcp.server import create_mcp_server

        server = create_mcp_server()
        server.run()
    else:
        try:
            cli()
        except KeyboardInterrupt:
            pass
