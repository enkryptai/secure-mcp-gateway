"""Enkrypt Secure MCP Gateway package.

The package init is intentionally empty.

Earlier revisions did::

    from secure_mcp_gateway.client import *
    from secure_mcp_gateway.gateway import *
    from secure_mcp_gateway.utils import *

That was a Python footgun: ``python -m secure_mcp_gateway.gateway`` first
imports the parent package (running this ``__init__``), which in turn
imports ``secure_mcp_gateway.gateway`` and registers it under
``sys.modules``. ``runpy`` then sees the module is already imported and
emits::

    RuntimeWarning: 'secure_mcp_gateway.gateway' found in sys.modules
    after import of package 'secure_mcp_gateway', but prior to execution
    of 'secure_mcp_gateway.gateway'; this may result in unpredictable
    behaviour

…before re-executing the module body as ``__main__``. The net effect is
that every top-level statement in ``gateway.py`` runs twice: FastMCP
server creation, telemetry init, plugin singletons. That ranges from
noisy (duplicate log lines) to actively buggy (signal handlers
registered twice, OTel providers double-installed).

A grep across the repo (and the public test suite) shows nothing actually
relied on those wildcard re-exports — every import site uses the fully
qualified ``secure_mcp_gateway.<submodule>`` form. So we remove them and
let consumers import the submodule they actually need.
"""
