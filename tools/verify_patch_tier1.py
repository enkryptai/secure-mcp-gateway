"""Build-time verification for Dockerfile.patch-tier1metrics.

Asserts that every Tier-1 patch is correctly overlaid on top of the
official v2.2.0 image after running tools/build_tier1_overlay.py.  Run as
the final RUN step in the Dockerfile so the build fails loudly when any
patch is missing or the merge step skipped a file.

In-scope checks (everything in the merged overlay):
  * session_pool.py asyncio.wait_for guards (PR #40)
  * 7 new MetricNames constants
  * 6 new metrics_helpers functions
  * 7 new TelemetryConfigManager @property accessors
  * MCPGatewayError.__init__ auto-emission of enkrypt.errors.by_code

Out-of-scope (left for a future PR that lands on main first so v2.2.0+main
stay in lock-step):
  * compliance_hits / permission_denied / degradation call sites in
    services/execution/secure_tool_execution_service.py
  * discovery_server_failure call site in services/discovery/discovery_service.py
"""

from __future__ import annotations

import inspect
import sys


def check(label: str, ok: bool, detail: str = "") -> None:
    status = "OK " if ok else "FAIL"
    print(f"{status}  {label}{(' -- ' + detail) if detail else ''}")
    if not ok:
        sys.exit(1)


# ---- PR #40: session_pool acquire/connect timeouts -----------------------
from secure_mcp_gateway.services.session.session_pool import SessionPool

src = inspect.getsource(SessionPool.__init__)
check(
    "PR #40 session_pool fix",
    "acquire_timeout" in src and "connect_timeout" in src,
    "missing asyncio.wait_for guards" if "acquire_timeout" not in src else "",
)

# ---- PR #41: 7 new metric name constants ---------------------------------
from secure_mcp_gateway.plugins.telemetry.conventions import MetricNames

NEW_METRIC_CONSTS = (
    "GUARDRAIL_COMPLIANCE_HIT",
    "TOOL_PERMISSION_DENIED",
    "ERRORS_BY_CODE",
    "DEGRADATION_FAIL_OPEN",
    "DEGRADATION_FAIL_CLOSED",
    "TRANSPORT_ERRORS",
    "DISCOVERY_SERVER_FAILURES",
    # Guardrail-detail
    "GUARDRAIL_PII_ENTITY",
    "GUARDRAIL_TOXICITY_SUBTYPE",
)
missing = [n for n in NEW_METRIC_CONSTS if not hasattr(MetricNames, n)]
check("Tier-1 + guardrail-detail MetricNames constants", not missing, f"missing: {missing}")

# ---- PR #41: 6 new helpers exported --------------------------------------
from secure_mcp_gateway.plugins.telemetry import metrics_helpers as mh

NEW_HELPERS = (
    "record_compliance_hits",
    "record_error_by_code",
    "record_tool_permission_denied",
    "record_degradation",
    "record_transport_error",
    "record_discovery_failure",
    # Guardrail-detail
    "record_pii_entities",
    "record_toxicity_subtypes",
)
missing = [h for h in NEW_HELPERS if not hasattr(mh, h)]
check("Tier-1 + guardrail-detail metrics_helpers", not missing, f"missing: {missing}")

# ---- PR #41 commit 5f68755: 7 new @property accessors --------------------
# Without these, metrics_helpers._add() silently no-ops because the manager
# wraps every metric in a @property and getattr(mgr, "<new>", None) returns
# None for any property that wasn't declared here.  This bug was caught
# during local OpenSearch verification -- shipping without this fix would
# silently break every Tier-1 metric in production.
from secure_mcp_gateway.plugins.telemetry.config_manager import TelemetryConfigManager

NEW_PROPS = (
    "guardrail_compliance_hit_counter",
    "tool_permission_denied_counter",
    "errors_by_code_counter",
    "degradation_fail_open_counter",
    "degradation_fail_closed_counter",
    "transport_error_counter",
    "discovery_server_failure_counter",
    # Guardrail-detail
    "guardrail_pii_entity_counter",
    "guardrail_toxicity_subtype_counter",
)
missing = [p for p in NEW_PROPS if not hasattr(TelemetryConfigManager, p)]
check(
    "Tier-1 + guardrail-detail @property accessors (commit 5f68755)",
    not missing,
    f"missing: {missing} -- without these the helpers silently no-op",
)

# ---- PR #41: MCPGatewayError.__init__ auto-emits errors.by_code ----------
from secure_mcp_gateway.exceptions import MCPGatewayError

src = inspect.getsource(MCPGatewayError.__init__)
check(
    "MCPGatewayError auto-emission",
    "record_error_by_code" in src,
    "MCPGatewayError.__init__ does not call record_error_by_code",
)


# ---- Audit (Phase A + B) ------------------------------------------------
NEW_AUDIT_METRICS = (
    "ADMIN_ACTIONS", "PRIVILEGED_OPERATIONS", "ADMIN_CACHE_FLUSH",
    "APIKEY_ROTATIONS", "AUDIT_APIKEY_CREATED", "AUDIT_APIKEY_DELETED",
    "AUDIT_APIKEY_DISABLED", "AUDIT_APIKEY_ROTATED",
    "AUDIT_CONFIG_MODIFIED", "AUDIT_SETTINGS_ENKRYPT_API_KEY_SET",
    "AUDIT_SETTINGS_TELEMETRY_CHANGED", "AUDIT_USER_CREATED",
    "AUDIT_USER_DELETED", "PROJECTS_CREATED",
    "SYSTEM_BACKUP_COMPLETED", "SYSTEM_RESET", "SYSTEM_RESTORE",
    "AUTH_UNAUTHORIZED_HTTP",
)
from secure_mcp_gateway.plugins.telemetry.conventions import MetricNames as _M
missing_audit_metrics = [n for n in NEW_AUDIT_METRICS if not hasattr(_M, n)]
check(
    "18 audit MetricNames constants",
    not missing_audit_metrics,
    f"missing: {missing_audit_metrics}",
)

NEW_AUDIT_HELPERS = (
    "record_admin_action", "record_cache_flush",
    "record_apikey_lifecycle", "record_user_lifecycle",
    "record_project_created", "record_system_op",
    "record_settings_change", "record_config_modified",
    "record_unauthorized_http",
)
missing_audit_helpers = [h for h in NEW_AUDIT_HELPERS if not hasattr(mh, h)]
check(
    "9 audit helpers exported",
    not missing_audit_helpers,
    f"missing: {missing_audit_helpers}",
)

NEW_AUDIT_PROPS = (
    "admin_actions_counter", "privileged_operations_counter",
    "admin_cache_flush_counter", "apikey_rotations_counter",
    "audit_apikey_created_counter", "audit_apikey_deleted_counter",
    "audit_apikey_disabled_counter", "audit_apikey_rotated_counter",
    "audit_config_modified_counter",
    "audit_settings_enkrypt_api_key_set_counter",
    "audit_settings_telemetry_changed_counter",
    "audit_user_created_counter", "audit_user_deleted_counter",
    "projects_created_counter", "system_backup_completed_counter",
    "system_reset_counter", "system_restore_counter",
    "auth_unauthorized_http_counter",
)
missing_audit_props = [
    p for p in NEW_AUDIT_PROPS if not hasattr(TelemetryConfigManager, p)
]
check(
    "18 audit @property accessors",
    not missing_audit_props,
    f"missing: {missing_audit_props} -- without these the audit helpers "
    "silently no-op",
)

from secure_mcp_gateway import audit as audit_mod  # noqa: F401
check("audit module importable", True)
check(
    "audit.log_audit callable",
    callable(getattr(audit_mod, "log_audit", None)),
)

from secure_mcp_gateway import audit_middleware  # noqa: F401
check("audit_middleware module importable", True)
check(
    "audit_middleware.audit_http_middleware callable",
    callable(getattr(audit_middleware, "audit_http_middleware", None)),
)
# Route table is data; check at least the high-value routes resolve.
_resolve = audit_middleware._resolve_route
for method, path, expected_action in [
    ("POST", "/api/v1/projects", "project_created"),
    ("POST", "/api/v1/api-keys/rotate", "apikey_rotated"),
    ("POST", "/api/v1/system/reset", "system_reset"),
    ("POST", "/api/v1/cache/flush-gateway-config", "cache_flush"),
]:
    res = _resolve(method, path)
    check(
        f"audit route resolves: {method} {path}",
        res is not None and res[0] == expected_action,
        f"got {res}",
    )

# Check api_server.py has the audit middleware registration.
#
# We read the file off disk instead of ``import secure_mcp_gateway.api_server``
# because that import path runs the CLI bootstrap which insists on
# HOST_OS / HOST_ENKRYPT_HOME env vars being set -- we don't want the
# image-build verification to require Docker-runtime env, just the
# *source* to be correct.
#
# CRITICAL: read from /app/src, NOT site-packages.  v2.2.0's CMD runs
# python /app/src/secure_mcp_gateway/gateway.py so /app/src is the
# authoritative source tree; the site-packages copy is only used by
# ad-hoc ``python -m ...`` probes.
_api_server_path = "/app/src/secure_mcp_gateway/api_server.py"
with open(_api_server_path, encoding="utf-8") as _f:
    api_server_src = _f.read()
check(
    "api_server.py registers audit middleware",
    "audit_http_middleware" in api_server_src,
)
check(
    "api_server.py has http_exception_handler for unauthorized_http",
    "record_unauthorized_http" in api_server_src,
)

# gateway_cache_routes.py instrumentation (also at /app/src, see note above)
_gcr_path = "/app/src/secure_mcp_gateway/gateway_cache_routes.py"
with open(_gcr_path, encoding="utf-8") as _f:
    _gcr_src = _f.read()
check(
    "gateway_cache_routes.py imports log_audit (success path)",
    "from secure_mcp_gateway.audit import log_audit" in _gcr_src,
)
check(
    "gateway_cache_routes.py emits action=cache_flush",
    'action="cache_flush"' in _gcr_src,
)

# ---- Guardrail-detail: STES has the per-detector emission wired ---------
# Read from /app/src, same rationale as api_server.py above.
_stes_path = "/app/src/secure_mcp_gateway/services/execution/secure_tool_execution_service.py"
with open(_stes_path, encoding="utf-8") as _f:
    _stes_src = _f.read()
check(
    "STES imports record_pii_entities",
    "record_pii_entities," in _stes_src,
)
check(
    "STES imports record_toxicity_subtypes",
    "record_toxicity_subtypes," in _stes_src,
)
# We injected 3 call sites (input + sync output + async output).
# Allow >=2 because the async output anchor is best-effort (see patch_stes).
_pii_calls = _stes_src.count("record_pii_entities(")
_tox_calls = _stes_src.count("record_toxicity_subtypes(")
check(
    f"STES has >=2 record_pii_entities call sites (found {_pii_calls})",
    _pii_calls >= 2,
)
check(
    f"STES has >=2 record_toxicity_subtypes call sites (found {_tox_calls})",
    _tox_calls >= 2,
)


print("\nALL_PATCHES_VERIFIED")
