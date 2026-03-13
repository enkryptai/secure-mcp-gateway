import logging
import sys

# Gateway deps (redis, flask, etc.) are only available when installed with
# the [gateway] extra. Guard these imports so that hooks-only installs can
# still import this package and use the CLI without crashing.
try:
    from enkryptai_agent_security.gateway.client import *
    from enkryptai_agent_security.gateway.gateway import *
    from enkryptai_agent_security.gateway.utils import *
except ImportError as _exc:
    logging.getLogger(__name__).debug(
        "Gateway modules not available (missing optional dependencies): %s", _exc
    )
