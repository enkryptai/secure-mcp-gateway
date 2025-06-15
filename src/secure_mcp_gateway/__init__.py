import sys
print("Initializing Enkrypt Secure MCP Gateway", file=sys.stderr)

from .gateway import *
from .client import *
from .utils import *
from .guardrail import *
from .dependencies import __dependencies__

# -----------------------------------------------------------------------
# NOTE: Also change this in __init__.py, pyproject.toml, and setup.py
# Tried using hatchling, importlib.metadata to be only in one place but it was not working
# So, keeping it in all three places for now
# -----------------------------------------------------------------------
__version__ = "1.0.1"
