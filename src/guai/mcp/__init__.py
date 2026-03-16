"""GuAI MCP server — exposes security monitoring tools via Model Context Protocol."""

try:
    from guai.mcp.server import create_mcp_server

    __all__ = ["create_mcp_server"]
except (ImportError, TypeError):
    # FastMCP API may differ between versions; gracefully degrade
    __all__: list[str] = []  # type: ignore[no-redef]
