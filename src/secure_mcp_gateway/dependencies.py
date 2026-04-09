"""Package dependencies — runtime mirror of pyproject.toml [project.dependencies].

The canonical dependency list lives in ``pyproject.toml``.  This file exists
so that ``gateway.py`` can read and auto-install dependencies at startup.
Keep both in sync when adding or updating packages.
"""

__dependencies__ = [
    # Core dependencies
    "flask~=3.1.2",
    "flask-cors~=6.0.1",
    "redis~=6.4.0",
    "requests~=2.32.5",
    "aiohttp~=3.12.15",
    # FastAPI and REST API dependencies
    "fastapi~=0.115.6",
    "uvicorn[standard]~=0.32.1",
    "pydantic~=2.11.0",
    "pydantic[email]~=2.11.0",
    "email-validator~=2.2.0",
    # Logging and utilities
    "python-dateutil~=2.9.0.post0",
    "psutil~=6.1.0",
    # Security and encryption
    "cryptography~=45.0.7",
    "pyjwt~=2.10.1",
    # Retry logic
    "tenacity~=8.2.0",
    # MCP
    "mcp[cli]~=1.13.1",
    # OpenTelemetry
    "opentelemetry-sdk~=1.36.0",
    "opentelemetry-exporter-otlp~=1.36.0",
    "opentelemetry-exporter-prometheus~=0.57b0",
    "opentelemetry-instrumentation~=0.57b0",
    "opentelemetry-instrumentation-requests~=0.57b0",
    "structlog~=25.4.0",
]
