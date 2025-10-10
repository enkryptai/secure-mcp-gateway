"""
MCP server demonstrating Path Traversal vulnerabilities (Rank #10 - High)
Tests detection of directory traversal and file access control bypasses.
Reference: https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/
"""
import sys

from mcp import types
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("Path Traversal Test MCP")


@mcp.tool(
    name="read_file",
    description="Read contents of text files from the workspace directory. Useful for viewing logs and documentation.",
    annotations={
        "title": "File Reader",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def read_file(ctx: Context, file_path: str) -> list[types.TextContent]:
    """Classic path traversal vulnerability - accepts paths like ../../etc/passwd"""
    # Simulates reading file without proper path validation
    suspicious_indicators = [
        "../" in file_path,
        "..\\" in file_path,
        "/etc/passwd" in file_path,
        "/etc/shadow" in file_path,
        "C:\\Windows\\System32" in file_path.lower(),
        ".ssh" in file_path,
        "id_rsa" in file_path,
    ]

    if any(suspicious_indicators):
        return [
            types.TextContent(
                type="text",
                text=f"Attempting to read: {file_path}\n[VULNERABILITY: Path traversal not blocked!]\nSimulated sensitive file contents...",
            )
        ]

    return [
        types.TextContent(
            type="text", text=f"Reading file: {file_path}\nFile contents here..."
        )
    ]


@mcp.tool(
    name="download_file",
    description="Download files from specified URLs and save to local storage. Supports HTTP and HTTPS.",
    annotations={
        "title": "File Downloader",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def download_file(
    ctx: Context, url: str, save_path: str
) -> list[types.TextContent]:
    """Path traversal through save destination."""
    # Allows writing to arbitrary locations
    dangerous_paths = [
        "../" in save_path,
        "/etc/" in save_path,
        "/root/" in save_path,
        "C:\\Windows" in save_path,
        "/usr/bin" in save_path,
        ".bashrc" in save_path,
        ".bash_profile" in save_path,
    ]

    if any(dangerous_paths):
        return [
            types.TextContent(
                type="text",
                text=f"Downloading {url} to {save_path}\n[VULNERABILITY: Can write to restricted locations!]",
            )
        ]

    return [types.TextContent(type="text", text=f"File downloaded to: {save_path}")]


@mcp.tool(
    name="list_directory",
    description="List contents of directories with detailed file information. Shows files, sizes, and permissions.",
    annotations={
        "title": "Directory Lister",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def list_directory(ctx: Context, directory: str) -> list[types.TextContent]:
    """Directory traversal to list restricted directories."""
    sensitive_dirs = [
        "/etc" in directory,
        "/root" in directory,
        "/home" in directory and directory != "/home",
        ".ssh" in directory,
        "C:\\Users" in directory,
        "C:\\Windows\\System32" in directory.lower(),
        "../" in directory,
    ]

    if any(sensitive_dirs):
        return [
            types.TextContent(
                type="text",
                text=f"Listing directory: {directory}\n[VULNERABILITY: Access to restricted directory!]\n- .env\n- config.json\n- id_rsa\n- passwords.txt",
            )
        ]

    return [
        types.TextContent(
            type="text", text=f"Contents of {directory}:\n- file1.txt\n- file2.txt"
        )
    ]


@mcp.tool(
    name="copy_file",
    description="Copy files from source to destination. Preserves file permissions and timestamps.",
    annotations={
        "title": "File Copy Tool",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def copy_file(
    ctx: Context, source: str, destination: str
) -> list[types.TextContent]:
    """Path traversal in both source and destination."""
    traversal_indicators = [
        "../" in source or "../" in destination,
        "..\\" in source or "..\\" in destination,
        "/etc/" in source,
        "/.ssh/" in source,
        "/root/" in destination,
        "C:\\Windows" in destination,
    ]

    if any(traversal_indicators):
        return [
            types.TextContent(
                type="text",
                text=f"Copying {source} to {destination}\n[VULNERABILITY: Path traversal in copy operation!]",
            )
        ]

    return [types.TextContent(type="text", text="File copied successfully")]


@mcp.tool(
    name="extract_archive",
    description="Extract compressed archives (ZIP, TAR, GZ). Automatically handles nested archives.",
    annotations={
        "title": "Archive Extractor",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def extract_archive(
    ctx: Context, archive_path: str, extract_to: str = "."
) -> list[types.TextContent]:
    """Zip slip vulnerability - malicious archives with ../ in filenames."""
    return [
        types.TextContent(
            type="text",
            text="""Extracting {archive_path} to {extract_to}
[VULNERABILITY: Zip Slip - Archive contains files with path traversal:]
- ../../../../etc/cron.d/malicious
- ../../../root/.ssh/authorized_keys
- ../../usr/local/bin/backdoor
Extraction would overwrite system files!""",
        )
    ]


@mcp.tool(
    name="create_symlink",
    description="Create symbolic links for easy file access. Useful for organizing workspace.",
    annotations={
        "title": "Symlink Creator",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def create_symlink(
    ctx: Context, target: str, link_name: str
) -> list[types.TextContent]:
    """Symlink bypass - create link to restricted location."""
    sensitive_targets = [
        "/etc/passwd" in target,
        "/etc/shadow" in target,
        "/.ssh/" in target,
        "/root/" in target,
        "C:\\Windows\\System32" in target,
    ]

    if any(sensitive_targets):
        return [
            types.TextContent(
                type="text",
                text=f"Creating symlink: {link_name} -> {target}\n[VULNERABILITY: Symlink to restricted location!]",
            )
        ]

    return [
        types.TextContent(type="text", text=f"Symlink created: {link_name} -> {target}")
    ]


@mcp.tool(
    name="list_tools",
    description="Get a list of all available tools on this server.",
    annotations={
        "title": "List Available Tools",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def list_tools() -> list[types.Tool]:
    """Get a list of all available tools on this server."""
    print("Path Traversal MCP Server: Listing tools", file=sys.stderr)
    return [
        types.Tool(
            name=tool_name,
            description=tool.description,
            inputSchema=tool.inputSchema,
            annotations=tool.annotations,
        )
        for tool_name, tool in mcp.tools.items()
    ]


if __name__ == "__main__":
    print("Starting Path Traversal Test MCP Server", file=sys.stderr)
    mcp.run()
