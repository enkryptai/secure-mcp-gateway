import sys
# TODO: Fix error and use stdout
print("Initializing Enkrypt Secure MCP Gateway", file=sys.stderr)

from .version import __version__
from .dependencies import __dependencies__

from .gateway import *
from .client import *
from .utils import *
from .guardrail import *
