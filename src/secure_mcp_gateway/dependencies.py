"""
Dependencies for the Enkrypt Secure MCP Gateway package
"""

__dependencies__ = [
    "flask>=2.0.0",
    "flask-cors>=3.0.0",
    "redis>=4.0.0",
    "requests>=2.26.0",
    "aiohttp>=3.8.0",
    "python-json-logger>=2.0.0",
    "python-dateutil>=2.8.2",
    "cryptography>=3.4.0",
    "pyjwt>=2.0.0",
    "asyncio>=3.4.3",
    "mcp[cli]>=1.10.1",
    "opentelemetry-sdk>=1.34.1",
    "opentelemetry-exporter-otlp>=1.34.1",
    "opentelemetry-exporter-prometheus>=0.55b1",
    "opentelemetry-instrumentation>=0.55b1",
    "opentelemetry-instrumentation-requests>=0.55b1",
    "structlog>=25.4.0"
]
