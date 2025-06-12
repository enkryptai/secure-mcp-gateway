from .gateway import *
from .client import *
from .utils import *
from .guardrail import *

# -----------------------------------------------------------------------
# NOTE: Also change these in __init__.py, pyproject.toml, and setup.py
# Tried changing these to be only in one place using hatchling, importlib.metadata, but it was not working
# So, keeping it in all three places for now
# -----------------------------------------------------------------------
__version__ = "1.0.0"
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
    "mcp[cli]"
]
