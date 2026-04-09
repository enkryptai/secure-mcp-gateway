"""Package dependencies — runtime mirror of pyproject.toml [project.dependencies].

The canonical dependency list lives in ``pyproject.toml``.  This file exists
so that ``gateway.py`` can read and auto-install dependencies at startup.
Keep both in sync when adding or updating packages.
"""

__dependencies__ = [
    # Core dependencies
    "flask~=3.1.3",
    "flask-cors~=6.0.2",
    "redis~=7.4.0",
    "requests~=2.33.1",
    "aiohttp~=3.13.5",
    # FastAPI and REST API dependencies
    "fastapi~=0.135.3",
    "uvicorn[standard]~=0.44.0",
    "pydantic~=2.12.5",
    "pydantic[email]~=2.12.5",
    "email-validator~=2.3.0",
    # Logging and utilities
    "python-dateutil~=2.9.0.post0",
    "psutil~=7.2.2",
    # Security and encryption
    "cryptography~=46.0.7",
    "pyjwt~=2.12.1",
    # Retry logic
    "tenacity~=9.1.4",
    # MCP
    "mcp[cli]~=1.27.0",
    # OpenTelemetry
    "opentelemetry-sdk~=1.40.0",
    "opentelemetry-exporter-otlp~=1.40.0",
    "opentelemetry-exporter-prometheus~=0.61b0",
    "opentelemetry-instrumentation~=0.61b0",
    "opentelemetry-instrumentation-requests~=0.61b0",
    "structlog~=25.5.0",
]
