"""Build merged "overlay" files for Dockerfile.patch-tier1metrics.

Why
---
My `main`-branch source files differ from `v2.2.0`'s files (v2.2.0 has
classes/methods that don't exist on `main` yet -- e.g. `TransportError`).
Overlaying my whole files would BREAK v2.2.0's imports.

Instead, for each file we:
  1. dump v2.2.0's official source into  build/tier1_overlay/<file>
  2. surgically inject ONLY my additions on top of v2.2.0
The Dockerfile then COPYs from build/tier1_overlay/* over v2.2.0's
files inside the image -- preserving everything v2.2.0 ships AND adding
the new instrumentation.

What this tool now produces
---------------------------
Despite the historical name "tier1_overlay", this tool ships BOTH:

  Tier 1 (PR #41) -- 7 metrics, 6 helpers, MCPGatewayError auto-emit,
                     session_pool acquire/connect timeouts.
  Audit  (this PR) -- 18 audit metrics, 9 audit helpers, audit.py,
                      audit_middleware.py, HTTPException handler in
                      api_server.py.

Files we patch (merge with v2.2.0)
----------------------------------
* conventions.py            -- +7 Tier-1 + +18 Audit MetricNames/descs
* opentelemetry_provider.py -- +7 Tier-1 + +18 Audit counters (real+noop)
* metrics_helpers.py        -- append all 6 Tier-1 + 9 Audit helpers
                               (read from main branch's marker onwards;
                               audit helpers landed after Tier-1 marker)
* config_manager.py         -- +7 Tier-1 + +18 Audit @property accessors
* exceptions.py             -- MCPGatewayError.__init__ auto-emission
* api_server.py             -- HTTPException handler for unauthorized
                               http + middleware registration

Files we copy verbatim from main (don't exist in v2.2.0)
--------------------------------------------------------
* audit.py                  -- new module with log_audit() entry point
* audit_middleware.py       -- FastAPI middleware with path->action table

Files pulled from a different image (proven safe)
-------------------------------------------------
* session_pool.py           -- from v2.2.0-sessionpoolpatch (PR #40)

Files we deliberately SKIP
--------------------------
* error_handling.py                       -- doc-only change
* secure_tool_execution_service.py        -- 5 Tier-1 call sites won't
                                             merge onto v2.2.0 cleanly
                                             (line drift); covered by the
                                             middleware for the audit
                                             case, and the Tier-1 call
                                             sites stay on main until
                                             PR #41 merges
* discovery_service.py                    -- 1 Tier-1 call site, same
* api_routes.py                           -- per-endpoint instrumentation
                                             intentionally deleted from
                                             this branch -- the audit
                                             middleware in api_server.py
                                             handles it without per-
                                             endpoint changes

Net effect of the resulting image vs v2.2.0
-------------------------------------------
* enkrypt.errors.by_code     -> emitted automatically from every
                                MCPGatewayError (~9 dashboard widgets)
* enkrypt.admin.actions etc. -> emitted automatically from every admin
                                REST mutation via the audit middleware
                                (~14 Audit Trail widgets)
* enkrypt.auth.unauthorized_http -> emitted from every 401/403
* session_pool fix           -> hang protection (PR #40)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

REPO = Path(__file__).resolve().parents[1]
OVERLAY_DIR = REPO / "build" / "tier1_overlay"
V220_IMAGE = "enkryptai/secure-mcp-gateway:v2.2.0"
PKG_ROOT = "/usr/local/lib/python3.12/dist-packages/secure_mcp_gateway"


def _dump_from_image(rel_path: str) -> str:
    """Return the contents of <PKG_ROOT>/<rel_path> from the v2.2.0 image."""
    full = f"{PKG_ROOT}/{rel_path}"
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "cat", V220_IMAGE, full],
        check=True,
        capture_output=True,
    )
    # Docker stdout is bytes; decode tolerantly.  v2.2.0 source is utf-8 LF
    # but Windows docker.exe sometimes injects CRLF when piping through
    # cmd.exe; normalise to LF so anchor matching is reliable.
    raw = proc.stdout.decode("utf-8", errors="strict")
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def _write(rel_path: str, content: str) -> None:
    out = OVERLAY_DIR / rel_path
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8", newline="\n")
    print(f"  wrote {out.relative_to(REPO)}  ({len(content.splitlines())} lines)")


# ---------------------------------------------------------------------------
# Per-file mergers
# ---------------------------------------------------------------------------


def patch_conventions(src: str) -> str:
    """Add 7 Tier-1 + 18 Audit MetricNames constants and matching
    METRIC_DESCRIPTIONS entries."""

    new_consts = dedent('''
        # ----- Tier-1 (PR #41) additions -----------------------------------
        GUARDRAIL_COMPLIANCE_HIT = "enkrypt.guardrail.compliance_hit"
        TOOL_PERMISSION_DENIED = "enkrypt.tool.permission_denied"
        ERRORS_BY_CODE = "enkrypt.errors.by_code"
        DEGRADATION_FAIL_OPEN = "enkrypt.degradation.fail_open"
        DEGRADATION_FAIL_CLOSED = "enkrypt.degradation.fail_closed"
        TRANSPORT_ERRORS = "enkrypt.transport.errors"
        DISCOVERY_SERVER_FAILURES = "enkrypt.discovery.server_failures"
        # ----- Audit / compliance additions --------------------------------
        ADMIN_ACTIONS = "enkrypt.admin.actions"
        PRIVILEGED_OPERATIONS = "enkrypt.privileged.operations"
        ADMIN_CACHE_FLUSH = "enkrypt.admin.cache_flush"
        APIKEY_ROTATIONS = "enkrypt.apikey.rotations"
        AUDIT_APIKEY_CREATED = "enkrypt.audit.apikey.created"
        AUDIT_APIKEY_DELETED = "enkrypt.audit.apikey.deleted"
        AUDIT_APIKEY_DISABLED = "enkrypt.audit.apikey.disabled"
        AUDIT_APIKEY_ROTATED = "enkrypt.audit.apikey.rotated"
        AUDIT_CONFIG_MODIFIED = "enkrypt.audit.config.modified"
        AUDIT_SETTINGS_ENKRYPT_API_KEY_SET = "enkrypt.audit.settings.enkrypt_api_key_set"
        AUDIT_SETTINGS_TELEMETRY_CHANGED = "enkrypt.audit.settings.telemetry_changed"
        AUDIT_USER_CREATED = "enkrypt.audit.user.created"
        AUDIT_USER_DELETED = "enkrypt.audit.user.deleted"
        PROJECTS_CREATED = "enkrypt.projects.created"
        SYSTEM_BACKUP_COMPLETED = "enkrypt.system.backup.completed"
        SYSTEM_RESET = "enkrypt.system.reset"
        SYSTEM_RESTORE = "enkrypt.system.restore"
        AUTH_UNAUTHORIZED_HTTP = "enkrypt.auth.unauthorized_http"
        # ----- Guardrail-detail additions (PII entities + toxicity subtypes) -
        GUARDRAIL_PII_ENTITY = "enkrypt.guardrail.pii_entity"
        GUARDRAIL_TOXICITY_SUBTYPE = "enkrypt.guardrail.toxicity_subtype"
    ''').strip("\n")

    # Inject the constants block just before the "# Metric descriptions"
    # banner that opens the next top-level section.
    anchor = "# Metric descriptions"
    if anchor not in src:
        raise RuntimeError(
            "v2.2.0 conventions.py has no 'Metric descriptions' banner -- "
            "merge anchor changed; bailing rather than risk silent miss"
        )
    indented = "\n".join("    " + ln if ln.strip() else ln for ln in new_consts.splitlines())
    # Inject AFTER the closing of MetricNames class.  Easiest: find the
    # last non-comment, non-blank line BEFORE "# Metric descriptions" --
    # that's the final class attribute.  Then insert our additions on the
    # line right after it.  We do this by finding the index of the "# ==="
    # comment block that precedes "# Metric descriptions" and inserting
    # right before that block.
    sep_idx = src.index(anchor)
    # Walk back over the "# ===" banner that decorates the section header.
    # The pattern is:
    #     <blank>
    #     # ===================================================================
    #     # Metric descriptions
    # We want to insert the new constants right before the blank.
    # Reliable approach: insert exactly at sep_idx and prepend the constants
    # with two blank lines + a header comment.
    block_to_inject = (
        "\n" + indented + "\n\n\n"
        + "# ===================================================================\n"
    )
    # The "# ===" line directly above "# Metric descriptions"; remove it
    # to avoid double-decorators, since we're prepending one.
    above = src[:sep_idx]
    if above.rstrip().endswith("# ==================================================================="):
        # Trim that decorator line and the trailing newline, we'll add our own.
        above_lines = above.rstrip().splitlines()
        above_lines.pop()  # remove decorator line
        above = "\n".join(above_lines) + "\n"
    src = above + block_to_inject + src[sep_idx:]

    # Append 7 description entries to METRIC_DESCRIPTIONS dict.  The dict
    # always ends with "}" on its own line; we inject before that closing brace.
    new_descs = dedent('''
        # Tier-1 additions
        MetricNames.GUARDRAIL_COMPLIANCE_HIT: (
            "Compliance framework hits per blocked guardrail call "
            "(one per framework + framework_id pair)"
        ),
        MetricNames.TOOL_PERMISSION_DENIED: (
            "Tools refused by server-level allow/deny policy"
        ),
        MetricNames.ERRORS_BY_CODE: (
            "MCPGatewayErrors emitted, by ErrorCode/severity/recovery"
        ),
        MetricNames.DEGRADATION_FAIL_OPEN: (
            "Calls allowed after guardrail/downstream error"
        ),
        MetricNames.DEGRADATION_FAIL_CLOSED: (
            "Calls blocked after guardrail/downstream error"
        ),
        MetricNames.TRANSPORT_ERRORS: (
            "MCP client transport failures (HTTP / stdio)"
        ),
        MetricNames.DISCOVERY_SERVER_FAILURES: (
            "Failed tool discovery attempts per downstream MCP server"
        ),
        # Audit / compliance additions
        MetricNames.ADMIN_ACTIONS: "Every gateway state-mutation",
        MetricNames.PRIVILEGED_OPERATIONS: "Privileged admin actions",
        MetricNames.ADMIN_CACHE_FLUSH: "Cache flush requests",
        MetricNames.APIKEY_ROTATIONS: "API key rotations",
        MetricNames.AUDIT_APIKEY_CREATED: "API key creation events",
        MetricNames.AUDIT_APIKEY_DELETED: "API key deletion events",
        MetricNames.AUDIT_APIKEY_DISABLED: "API key disable events",
        MetricNames.AUDIT_APIKEY_ROTATED: "API key rotation events",
        MetricNames.AUDIT_CONFIG_MODIFIED: "MCP config modification events",
        MetricNames.AUDIT_SETTINGS_ENKRYPT_API_KEY_SET: "Enkrypt cloud apikey changed",
        MetricNames.AUDIT_SETTINGS_TELEMETRY_CHANGED: "Telemetry config changed",
        MetricNames.AUDIT_USER_CREATED: "User account creation events",
        MetricNames.AUDIT_USER_DELETED: "User account deletion events",
        MetricNames.PROJECTS_CREATED: "Project creation events",
        MetricNames.SYSTEM_BACKUP_COMPLETED: "System backup completions",
        MetricNames.SYSTEM_RESET: "System reset events",
        MetricNames.SYSTEM_RESTORE: "System restore events",
        MetricNames.AUTH_UNAUTHORIZED_HTTP: "401/403 admin REST responses",
        # Guardrail-detail additions
        MetricNames.GUARDRAIL_PII_ENTITY: (
            "PII entities detected by the guardrail, one increment per "
            "entity (attribute entity_type)"
        ),
        MetricNames.GUARDRAIL_TOXICITY_SUBTYPE: (
            "Toxicity subtypes above threshold (attributes subtype + "
            "score_bucket low|medium|high)"
        ),
    ''').strip("\n")

    # Find the METRIC_DESCRIPTIONS dict closing brace.  v2.2.0 declares it as
    # METRIC_DESCRIPTIONS: dict[str, str] = { ... }
    idx_open = src.index("METRIC_DESCRIPTIONS")
    # Find the matching closing brace by simple bracket counting.
    after = src[idx_open:]
    brace_open = after.index("{")
    depth = 0
    end = None
    for i, ch in enumerate(after[brace_open:], start=brace_open):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        raise RuntimeError("could not find METRIC_DESCRIPTIONS closing brace")
    absolute_end = idx_open + end
    indented_descs = "\n".join("    " + ln for ln in new_descs.splitlines())
    src = src[:absolute_end] + indented_descs + "\n" + src[absolute_end:]
    return src


_AUDIT_COUNTER_NAMES = [
    "admin_actions_counter",
    "privileged_operations_counter",
    "admin_cache_flush_counter",
    "apikey_rotations_counter",
    "audit_apikey_created_counter",
    "audit_apikey_deleted_counter",
    "audit_apikey_disabled_counter",
    "audit_apikey_rotated_counter",
    "audit_config_modified_counter",
    "audit_settings_enkrypt_api_key_set_counter",
    "audit_settings_telemetry_changed_counter",
    "audit_user_created_counter",
    "audit_user_deleted_counter",
    "projects_created_counter",
    "system_backup_completed_counter",
    "system_reset_counter",
    "system_restore_counter",
    "auth_unauthorized_http_counter",
]
# Map counter attribute name -> MetricNames constant name.  Both sides
# follow a predictable pattern so we can derive one from the other for
# the audit counters (counter name minus trailing "_counter", uppercased
# with consistent transforms).
_AUDIT_COUNTER_TO_METRIC = {
    "admin_actions_counter": "ADMIN_ACTIONS",
    "privileged_operations_counter": "PRIVILEGED_OPERATIONS",
    "admin_cache_flush_counter": "ADMIN_CACHE_FLUSH",
    "apikey_rotations_counter": "APIKEY_ROTATIONS",
    "audit_apikey_created_counter": "AUDIT_APIKEY_CREATED",
    "audit_apikey_deleted_counter": "AUDIT_APIKEY_DELETED",
    "audit_apikey_disabled_counter": "AUDIT_APIKEY_DISABLED",
    "audit_apikey_rotated_counter": "AUDIT_APIKEY_ROTATED",
    "audit_config_modified_counter": "AUDIT_CONFIG_MODIFIED",
    "audit_settings_enkrypt_api_key_set_counter": "AUDIT_SETTINGS_ENKRYPT_API_KEY_SET",
    "audit_settings_telemetry_changed_counter": "AUDIT_SETTINGS_TELEMETRY_CHANGED",
    "audit_user_created_counter": "AUDIT_USER_CREATED",
    "audit_user_deleted_counter": "AUDIT_USER_DELETED",
    "projects_created_counter": "PROJECTS_CREATED",
    "system_backup_completed_counter": "SYSTEM_BACKUP_COMPLETED",
    "system_reset_counter": "SYSTEM_RESET",
    "system_restore_counter": "SYSTEM_RESTORE",
    "auth_unauthorized_http_counter": "AUTH_UNAUTHORIZED_HTTP",
}


def _audit_counter_declarations() -> str:
    """Produce the 18 ``self.<x>_counter = self._meter.create_counter(...)``
    lines for the active-telemetry branch of ``_create_metrics``."""
    lines = ["        # ----- Audit / compliance counters -----------------------"]
    for attr, metric_const in _AUDIT_COUNTER_TO_METRIC.items():
        lines.append(f"        self.{attr} = self._meter.create_counter(")
        lines.append(f"            M.{metric_const},")
        lines.append(f"            description=D[M.{metric_const}],")
        lines.append("            unit=\"1\",")
        lines.append("        )")
    return "\n".join(lines)


def _audit_noop_declarations() -> str:
    """Produce the 18 ``self.<x>_counter = NoOpCounter()`` lines for the
    disabled-telemetry branch of ``_setup_disabled_telemetry``."""
    lines = ["        # Audit / compliance no-op shims"]
    for attr in _AUDIT_COUNTER_TO_METRIC:
        lines.append(f"        self.{attr} = NoOpCounter()")
    return "\n".join(lines)


def patch_opentelemetry_provider(src: str) -> str:
    """Add 7 Tier-1 + 18 Audit counter declarations inside
    ``_create_metrics`` and matching NoOp declarations inside
    ``_setup_disabled_telemetry``."""

    real_counters = dedent('''
        # ----- Tier-1 (PR #41) additions -----------------------------------
        self.guardrail_compliance_hit_counter = self._meter.create_counter(
            M.GUARDRAIL_COMPLIANCE_HIT,
            description=D[M.GUARDRAIL_COMPLIANCE_HIT],
            unit="1",
        )
        self.tool_permission_denied_counter = self._meter.create_counter(
            M.TOOL_PERMISSION_DENIED,
            description=D[M.TOOL_PERMISSION_DENIED],
            unit="1",
        )
        self.errors_by_code_counter = self._meter.create_counter(
            M.ERRORS_BY_CODE, description=D[M.ERRORS_BY_CODE], unit="1",
        )
        self.degradation_fail_open_counter = self._meter.create_counter(
            M.DEGRADATION_FAIL_OPEN,
            description=D[M.DEGRADATION_FAIL_OPEN],
            unit="1",
        )
        self.degradation_fail_closed_counter = self._meter.create_counter(
            M.DEGRADATION_FAIL_CLOSED,
            description=D[M.DEGRADATION_FAIL_CLOSED],
            unit="1",
        )
        self.transport_error_counter = self._meter.create_counter(
            M.TRANSPORT_ERRORS, description=D[M.TRANSPORT_ERRORS], unit="1",
        )
        self.discovery_server_failure_counter = self._meter.create_counter(
            M.DISCOVERY_SERVER_FAILURES,
            description=D[M.DISCOVERY_SERVER_FAILURES],
            unit="1",
        )
        # ----- Guardrail-detail additions ----------------------------------
        self.guardrail_pii_entity_counter = self._meter.create_counter(
            M.GUARDRAIL_PII_ENTITY,
            description=D[M.GUARDRAIL_PII_ENTITY],
            unit="1",
        )
        self.guardrail_toxicity_subtype_counter = self._meter.create_counter(
            M.GUARDRAIL_TOXICITY_SUBTYPE,
            description=D[M.GUARDRAIL_TOXICITY_SUBTYPE],
            unit="1",
        )
    ''').strip("\n")

    # Anchor inside _create_metrics: the last existing counter declaration
    # before the next def or the end of the method.  In v2.2.0 the health
    # counters are the last in _create_metrics:
    #     self.health_failure_counter = self._meter.create_counter(
    #         M.HEALTH_FAILURES, description=D[M.HEALTH_FAILURES], unit="1",
    #     )
    anchor = "self.health_failure_counter = self._meter.create_counter(\n            M.HEALTH_FAILURES, description=D[M.HEALTH_FAILURES], unit=\"1\",\n        )"
    # Combined injection: Tier-1 counters + Audit counters (audit
    # block already produced at module scope by _audit_counter_declarations()
    # so we don't have to maintain a long ``dedent('''...''')`` literal).
    audit_decls = _audit_counter_declarations()
    if anchor not in src:
        # Be more permissive: any line with health_failure_counter
        if "self.health_failure_counter = self._meter.create_counter(" not in src:
            raise RuntimeError(
                "v2.2.0 opentelemetry_provider.py missing health_failure_counter "
                "anchor; cannot safely merge Tier-1 counters"
            )
        # Fall back: insert before "def _setup_disabled_telemetry"
        anchor2 = "    def _setup_disabled_telemetry"
        indented = "\n".join("        " + ln if ln.strip() else ln for ln in real_counters.splitlines())
        src = src.replace(
            anchor2,
            indented + "\n" + audit_decls + "\n\n" + anchor2,
            1,
        )
    else:
        indented = "\n".join("        " + ln if ln.strip() else ln for ln in real_counters.splitlines())
        src = src.replace(
            anchor,
            anchor + "\n" + indented + "\n" + audit_decls,
            1,
        )

    noops = dedent('''
        # Tier-1 (PR #41) additions
        self.guardrail_compliance_hit_counter = NoOpCounter()
        self.tool_permission_denied_counter = NoOpCounter()
        self.errors_by_code_counter = NoOpCounter()
        self.degradation_fail_open_counter = NoOpCounter()
        self.degradation_fail_closed_counter = NoOpCounter()
        self.transport_error_counter = NoOpCounter()
        self.discovery_server_failure_counter = NoOpCounter()
        # Guardrail-detail no-op shims
        self.guardrail_pii_entity_counter = NoOpCounter()
        self.guardrail_toxicity_subtype_counter = NoOpCounter()
    ''').strip("\n")

    # Insert NoOps inside _setup_disabled_telemetry right before the
    # "# Health-check API metrics" block (last NoOps in v2.2.0).
    audit_noops = _audit_noop_declarations()
    noop_anchor = "        # Health-check API metrics\n        self.health_request_counter = NoOpCounter()"
    if noop_anchor in src:
        indented_noops = "\n".join("        " + ln if ln.strip() else ln for ln in noops.splitlines())
        src = src.replace(
            noop_anchor,
            indented_noops + "\n" + audit_noops + "\n" + noop_anchor,
            1,
        )
    else:
        raise RuntimeError("v2.2.0 missing _setup_disabled_telemetry health NoOp anchor")

    return src


def patch_metrics_helpers(src: str) -> str:
    """Append 6 new helpers + extend __all__.  My main-branch
    metrics_helpers.py already has the full content -- but v2.2.0's has
    a different starting set.  Strategy: append my Tier-1-only block and
    a new __all__ extension.
    """
    # v2.2.0's metrics_helpers imports ``from typing import TYPE_CHECKING,
    # Any, Optional`` -- missing ``Mapping`` and ``Iterable`` which BOTH
    # record_compliance_hits AND the new record_pii_entities /
    # record_toxicity_subtypes need.  Without this fix the appended
    # helpers NameError on first invocation; the surrounding try/except
    # at the call site swallows it -> silent no-op + permanently empty
    # dashboard panels.  Caught during dev verification of the
    # guardrail-detail overlay.
    typing_anchor = "from typing import TYPE_CHECKING, Any, Optional"
    if typing_anchor in src:
        src = src.replace(
            typing_anchor,
            "from typing import TYPE_CHECKING, Any, Iterable, Mapping, Optional",
            1,
        )
    elif "from typing import " in src and "Mapping" not in src.split("\n")[:30].__str__():
        # Fallback: if v2.2.0 changed the order, just ensure both names are present
        # by injecting a second import line.
        src = src.replace(
            "from typing import",
            "from typing import Iterable, Mapping  # patched by overlay\nfrom typing import",
            1,
        )

    # The Cache & Performance per-request timing helpers
    # (start_request_timings / phase_timer / finalize_request_timings /
    # record_phase_ms) live ABOVE the `# Compliance framework attribution`
    # marker in main, so the marker-based extraction below would miss them.
    # Need contextvars + time imports plus stdlib import block fixup, then
    # append a verbatim copy of the timing section before the rest of the
    # helper extraction kicks in.
    if "import contextvars" not in src:
        # Inject after the existing `import logging` line which v2.2.0 has.
        if "import logging" in src:
            src = src.replace(
                "import logging",
                "import contextvars\nimport logging\nimport time",
                1,
            )

    # Pull the timing block out of the source-of-truth metrics_helpers.py
    # on the working branch.  Bounded by two unique markers so we don't
    # accidentally splice in unrelated helpers if the file gets reordered.
    main_mh = (REPO / "src" / "secure_mcp_gateway" / "plugins" / "telemetry" / "metrics_helpers.py").read_text(encoding="utf-8")
    timing_start = "# Per-request phase timing  (Cache & Performance dashboard)"
    timing_end = "# ---------------------------------------------------------------------------\n# Tool call lifecycle"
    if timing_start in main_mh and timing_end in main_mh:
        start_idx = main_mh.index(timing_start)
        # Walk back to the opening "# -----" decorator above the marker.
        deco = main_mh.rfind("# ----------", 0, start_idx)
        if deco != -1:
            start_idx = deco
        end_idx = main_mh.index(timing_end)
        timing_block = main_mh[start_idx:end_idx].rstrip() + "\n\n\n"
        # Inject the block right after the imports.  Anchor on the first
        # ``def _get_manager`` definition (v2.2.0 has it).
        get_mgr_anchor = "def _get_manager()"
        if get_mgr_anchor in src:
            src = src.replace(
                get_mgr_anchor,
                timing_block + get_mgr_anchor,
                1,
            )

    additions = (REPO / "src" / "secure_mcp_gateway" / "plugins" / "telemetry" / "metrics_helpers.py").read_text(encoding="utf-8")
    # The Tier-1 helpers live after the marker comment introduced in
    # commit 3f703ab.  Extract from that marker onwards (skipping the
    # earlier helpers which v2.2.0 already has, possibly in a different
    # state).
    marker = "# ---------------------------------------------------------------------------\n# Compliance framework attribution\n"
    if marker not in additions:
        raise RuntimeError("main branch metrics_helpers.py missing Tier-1 marker comment")
    tier1_block = additions[additions.index(marker):]
    # Strip the final __all__ we wrote on main (v2.2.0 has its own).
    if "\n__all__ = [" in tier1_block:
        tier1_block = tier1_block[: tier1_block.index("\n__all__ = [")]

    # Drop tier1_block at the end of v2.2.0's file, then patch v2.2.0's
    # __all__ to also export the new helpers.
    v220 = src.rstrip() + "\n\n\n" + tier1_block.rstrip() + "\n"

    # Extend __all__ if present.
    new_names = (
        "    \"record_compliance_hits\",\n"
        "    \"record_pii_entities\",\n"
        "    \"record_toxicity_subtypes\",\n"
        "    \"record_error_by_code\",\n"
        "    \"record_tool_permission_denied\",\n"
        "    \"record_degradation\",\n"
        "    \"record_transport_error\",\n"
        "    \"record_discovery_failure\",\n"
    )
    if "__all__ = [" in v220:
        # Find first ']' after __all__ start
        idx = v220.index("__all__ = [")
        end = v220.index("]", idx)
        v220 = v220[:end] + new_names + v220[end:]
    else:
        v220 += "\n__all__ = [\n" + new_names + "]\n"
    return v220


def patch_config_manager(src: str) -> str:
    """Add 7 @property accessors -- the critical fix from commit 5f68755."""
    new_props = dedent('''
        # ----- Tier-1 (PR #41 commit 5f68755) additions --------------------
        # Without these accessors metrics_helpers._add() silently no-ops
        # because getattr(mgr, "<counter>", None) returns None for any
        # counter not declared as a @property here.
        @property
        def guardrail_compliance_hit_counter(self):
            """Tier-1 metric accessor for enkrypt.guardrail.compliance_hit."""
            return self._get_metric_from_provider("guardrail_compliance_hit_counter")

        @property
        def tool_permission_denied_counter(self):
            """Tier-1 metric accessor for enkrypt.tool.permission_denied."""
            return self._get_metric_from_provider("tool_permission_denied_counter")

        @property
        def errors_by_code_counter(self):
            """Tier-1 metric accessor for enkrypt.errors.by_code."""
            return self._get_metric_from_provider("errors_by_code_counter")

        @property
        def degradation_fail_open_counter(self):
            """Tier-1 metric accessor for enkrypt.degradation.fail_open."""
            return self._get_metric_from_provider("degradation_fail_open_counter")

        @property
        def degradation_fail_closed_counter(self):
            """Tier-1 metric accessor for enkrypt.degradation.fail_closed."""
            return self._get_metric_from_provider("degradation_fail_closed_counter")

        @property
        def transport_error_counter(self):
            """Tier-1 metric accessor for enkrypt.transport.errors."""
            return self._get_metric_from_provider("transport_error_counter")

        @property
        def discovery_server_failure_counter(self):
            """Tier-1 metric accessor for enkrypt.discovery.server_failures."""
            return self._get_metric_from_provider("discovery_server_failure_counter")

        # ----- Guardrail-detail accessors --------------------------------
        @property
        def guardrail_pii_entity_counter(self):
            """Per-entity PII counter ``enkrypt.guardrail.pii_entity``."""
            return self._get_metric_from_provider("guardrail_pii_entity_counter")

        @property
        def guardrail_toxicity_subtype_counter(self):
            """Toxicity subtype counter ``enkrypt.guardrail.toxicity_subtype``."""
            return self._get_metric_from_provider("guardrail_toxicity_subtype_counter")

    ''').strip("\n") + "\n"

    # Build the 18 audit @property accessors programmatically from the
    # counter-attr -> metric-name table.  Same pattern as the Tier-1
    # ones above (avoiding the same silent-no-op trap from PR #41 commit
    # 5f68755).
    audit_props_lines = ["# ----- Audit / compliance accessors ------------------------------"]
    for attr in _AUDIT_COUNTER_TO_METRIC:
        audit_props_lines.append("@property")
        audit_props_lines.append(f"def {attr}(self):")
        audit_props_lines.append(f"    \"\"\"Audit accessor for ``{attr}``.\"\"\"")
        audit_props_lines.append(f"    return self._get_metric_from_provider(\"{attr}\")")
        audit_props_lines.append("")
    audit_props = "\n".join(audit_props_lines)

    # Find the "# Global Instance" section (always at end of class block
    # in v2.2.0).  We inject our properties right before it.
    anchor = "\n# ============================================================================\n# Global Instance"
    if anchor not in src:
        raise RuntimeError("v2.2.0 config_manager.py missing '# Global Instance' anchor")
    combined = (
        new_props.rstrip() + "\n\n" + audit_props.rstrip() + "\n"
    )
    src = src.replace(anchor, "    " + combined.replace("\n", "\n    ").rstrip() + "\n" + anchor, 1)
    return src


def patch_exceptions(src: str) -> str:
    """Inject the auto-emission block after super().__init__(user_msg) in
    MCPGatewayError.__init__."""
    anchor = "        super().__init__(user_msg)"
    if anchor not in src:
        raise RuntimeError("v2.2.0 exceptions.py missing MCPGatewayError super().__init__(user_msg) anchor")

    # 8-space-indented body so the block lands inside the method, not at
    # module scope.  Use a single multi-line literal with explicit prefix
    # rather than dedent() (which strips uniform leading whitespace) so we
    # control the indent precisely.
    injection = (
        "\n"
        "\n"
        "        # Tier-1 (PR #41) auto-emission of enkrypt.errors.by_code.\n"
        "        # Single emission point so every MCPGatewayError counts whether or\n"
        "        # not the caller wraps in error_handling_context.  No-op safe when\n"
        "        # telemetry is not yet initialised (CLI / unit tests).\n"
        "        try:\n"
        "            from .plugins.telemetry.metrics_helpers import record_error_by_code\n"
        "\n"
        "            record_error_by_code(\n"
        "                error_code=getattr(self.code, \"value\", self.code),\n"
        "                severity=getattr(self.severity, \"value\", self.severity),\n"
        "                recovery_strategy=getattr(\n"
        "                    self.recovery_strategy,\n"
        "                    \"value\",\n"
        "                    self.recovery_strategy,\n"
        "                ),\n"
        "                component=getattr(self.context, \"component\", None),\n"
        "                server_name=getattr(self.context, \"server_name\", None),\n"
        "                tool_name=getattr(self.context, \"tool_name\", None),\n"
        "            )\n"
        "        except Exception:  # pragma: no cover - never let metrics break errors\n"
        "            pass\n"
    )

    # Replace only the FIRST occurrence -- there's only one MCPGatewayError class
    src = src.replace(anchor, anchor + injection, 1)
    return src


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _patch_stes_phase_timings(src: str) -> str:
    """Wire the 8 per-call *_duration_ms log fields into STES so the
    Cache & Performance dashboard's Latency Breakdown section populates.

    Strategy
    --------
    1. Extend the metrics_helpers import block (already patched
       elsewhere by patch_stes) to also pull in start_request_timings,
       finalize_request_timings, phase_timer.
    2. Inject start_request_timings() at execute_secure_tools entry
       (right after custom_id = generate_custom_id()).
    3. Wrap 5 timing-relevant sites with ``async with phase_timer(...)``:
         - input_guardrail.validate (sync path)        -> preprocess + guardrail
         - call_tool (sync, post-input-guardrail)      -> execution + tool_call
         - call_tool (no-input-guardrail short path)   -> execution + tool_call
         - call_tool (input_guardrail is None path)    -> execution + tool_call
         - input_guardrail+call_tool (async-input gather) -> tool_call + guardrail
         - output_guardrail.validate (sync output)      -> postprocess + guardrail
         - output_guardrail.validate (async output)     -> postprocess + guardrail
    4. Splice ``**finalize_request_timings()`` into the 3 log.info()
       calls that emit structured records on success / blocked-input /
       blocked-output paths.

    Each anchor uses enough surrounding context to be unique on v2.2.0;
    if any anchor fails, the patch raises and the build aborts (better
    than silent half-patching).
    """
    # --- 1) extend import block (the patch_stes added record_pii_entities
    #     / record_toxicity_subtypes; we add 3 more after them).
    after_tox_anchor = "    record_toxicity_subtypes,"
    if after_tox_anchor not in src:
        # patch_stes hasn't run yet OR upstream changed.  Fall back to
        # the v2.2.0 record_guardrail_violations anchor and inject all 5.
        rg_anchor = "    record_guardrail_violations,"
        src = src.replace(
            rg_anchor,
            (
                rg_anchor
                + "\n    record_pii_entities,"
                + "\n    record_toxicity_subtypes,"
                + "\n    finalize_request_timings,"
                + "\n    phase_timer,"
                + "\n    start_request_timings,"
            ),
            1,
        )
    else:
        src = src.replace(
            after_tox_anchor,
            (
                after_tox_anchor
                + "\n    finalize_request_timings,"
                + "\n    phase_timer,"
                + "\n    start_request_timings,"
            ),
            1,
        )

    # --- 2) start_request_timings() at execute_secure_tools entry.
    # Anchor on the unique "num_tool_calls" + generate_custom_id() pair
    # which appears once in the file (v2.2.0 STES line ~95).
    entry_anchor = (
        "        tool_calls = tool_calls or []\n"
        "        num_tool_calls = len(tool_calls)\n"
        "        custom_id = generate_custom_id()\n"
    )
    if entry_anchor not in src:
        raise RuntimeError(
            "patch_stes_phase_timings: execute_secure_tools entry anchor "
            "not found (custom_id = generate_custom_id() trio)"
        )
    src = src.replace(
        entry_anchor,
        entry_anchor
        + "\n"
        + "        # Per-request phase timing accumulator (Cache &\n"
        + "        # Performance dashboard).  Lives on a contextvar so\n"
        + "        # async children share it without method-signature\n"
        + "        # threading; finalised at success / blocked log\n"
        + "        # emission.\n"
        + "        start_request_timings()\n",
        1,
    )

    # --- 3) phase_timer wraps.

    # 3a) Sync input guardrail + tool call (the "else:" branch of
    # ENKRYPT_ASYNC_INPUT_GUARDRAILS_ENABLED).
    sync_in_anchor = (
        "                guardrail_response = await timeout_manager.execute_with_timeout(\n"
        "                    input_guardrail.validate, \"guardrail\", f\"guardrail_{i}\", request\n"
        "                )\n"
        "                result = await timeout_manager.execute_with_timeout(\n"
        "                    self.tool_execution_service.call_tool,\n"
        "                    \"tool_execution\",\n"
        "                    f\"tool_call_{i}\",\n"
        "                    session,\n"
        "                    tool_name,\n"
        "                    args,\n"
        "                )"
    )
    sync_in_replacement = (
        "                async with phase_timer(\"preprocess_duration_ms\", \"guardrail_duration_ms\"):\n"
        "                    guardrail_response = await timeout_manager.execute_with_timeout(\n"
        "                        input_guardrail.validate, \"guardrail\", f\"guardrail_{i}\", request\n"
        "                    )\n"
        "                async with phase_timer(\"execution_duration_ms\", \"tool_call_duration_ms\"):\n"
        "                    result = await timeout_manager.execute_with_timeout(\n"
        "                        self.tool_execution_service.call_tool,\n"
        "                        \"tool_execution\",\n"
        "                        f\"tool_call_{i}\",\n"
        "                        session,\n"
        "                        tool_name,\n"
        "                        args,\n"
        "                    )"
    )
    if sync_in_anchor in src:
        src = src.replace(sync_in_anchor, sync_in_replacement, 1)
    # else: anchor not found -- v2.2.0 may have different indentation; skip
    # this wrap rather than abort, total_request_duration_ms still works.

    # 3b) Async input guardrail + tool call gather().  Anchor on
    # asyncio.gather(guardrail_task, tool_call_task).
    async_gather_anchor = (
        "                guardrail_response, result = await asyncio.gather(\n"
        "                    guardrail_task, tool_call_task\n"
        "                )"
    )
    async_gather_replacement = (
        "                # Wrap the whole concurrent gather() with a single timer\n"
        "                # booked under tool_call_duration_ms (dominant phase) +\n"
        "                # guardrail_duration_ms (masked by the overlap).\n"
        "                async with phase_timer(\"tool_call_duration_ms\", \"guardrail_duration_ms\"):\n"
        "                    guardrail_response, result = await asyncio.gather(\n"
        "                        guardrail_task, tool_call_task\n"
        "                    )"
    )
    if async_gather_anchor in src:
        src = src.replace(async_gather_anchor, async_gather_replacement, 1)

    # 3c) call_tool when input_guardrail is None (short path).
    none_path_anchor = (
        "            if input_guardrail is None:\n"
        "                # Guardrails not enabled, proceed directly\n"
        "                result = await self.tool_execution_service.call_tool(\n"
        "                    session, tool_name, args\n"
        "                )"
    )
    none_path_replacement = (
        "            if input_guardrail is None:\n"
        "                # Guardrails not enabled, proceed directly\n"
        "                async with phase_timer(\"execution_duration_ms\", \"tool_call_duration_ms\"):\n"
        "                    result = await self.tool_execution_service.call_tool(\n"
        "                        session, tool_name, args\n"
        "                    )"
    )
    if none_path_anchor in src:
        src = src.replace(none_path_anchor, none_path_replacement, 1)

    # 3d) call_tool in the "input guardrails not enabled" log path.
    not_enabled_anchor = (
        "            logger.info(\n"
        "                \"secure_tool_execution.execute_secure_tools.input_guardrails_not_enabled\",\n"
        "                extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),\n"
        "            )\n"
        "\n"
        "            result = await self.tool_execution_service.call_tool(\n"
        "                session, tool_name, args\n"
        "            )"
    )
    not_enabled_replacement = (
        "            logger.info(\n"
        "                \"secure_tool_execution.execute_secure_tools.input_guardrails_not_enabled\",\n"
        "                extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),\n"
        "            )\n"
        "\n"
        "            async with phase_timer(\"execution_duration_ms\", \"tool_call_duration_ms\"):\n"
        "                result = await self.tool_execution_service.call_tool(\n"
        "                    session, tool_name, args\n"
        "                )"
    )
    if not_enabled_anchor in src:
        src = src.replace(not_enabled_anchor, not_enabled_replacement, 1)

    # 3e) Output guardrail validate -- 2 sites (sync + async output paths).
    # Both have the IDENTICAL anchor; use replace + count loop.
    out_anchor = (
        "        guardrail_response = await output_guardrail.validate(\n"
        "            response_content=text_result, original_request=original_request\n"
        "        )"
    )
    out_replacement = (
        "        async with phase_timer(\"postprocess_duration_ms\", \"guardrail_duration_ms\"):\n"
        "            guardrail_response = await output_guardrail.validate(\n"
        "                response_content=text_result, original_request=original_request\n"
        "            )"
    )
    # Replace both occurrences (sync + async output paths).
    for _ in range(2):
        if out_anchor not in src:
            break
        src = src.replace(out_anchor, out_replacement, 1)

    # --- 4) Splice **finalize_request_timings() into 3 log.info(...).
    # 4a) Success log -- in _build_successful_result.
    success_log_anchor = (
        "        logger.info(\n"
        "            \"secure_tool_execution.execute_secure_tools.completed_successfully\",\n"
        "            extra=build_log_extra(ctx, custom_id, server_name, tool_name=tool_name),\n"
        "        )"
    )
    success_log_replacement = (
        "        # Per-request phase timings (Cache & Performance dashboard).\n"
        "        _timings = finalize_request_timings()\n"
        "        logger.info(\n"
        "            \"secure_tool_execution.execute_secure_tools.completed_successfully\",\n"
        "            extra=build_log_extra(\n"
        "                ctx, custom_id, server_name, tool_name=tool_name, **_timings,\n"
        "            ),\n"
        "        )"
    )
    if success_log_anchor in src:
        src = src.replace(success_log_anchor, success_log_replacement, 1)

    # 4b) Blocked-input log -- already structured with input_violation_types
    # plus per-detector detail (added by patch_stes).  Add **timings dict.
    blocked_in_anchor = (
        "                logger.info(\n"
        "                    \"secure_tool_execution.execute_secure_tools.blocked_due_to_input_violations\",\n"
        "                    extra=build_log_extra(\n"
        "                        ctx,\n"
        "                        custom_id,\n"
        "                        server_name,\n"
        "                        tool_name=tool_name,\n"
        "                        input_violations_detected=True,\n"
        "                        input_violation_types=violation_types,\n"
        "                    ),\n"
        "                )"
    )
    blocked_in_replacement = (
        "                logger.info(\n"
        "                    \"secure_tool_execution.execute_secure_tools.blocked_due_to_input_violations\",\n"
        "                    extra=build_log_extra(\n"
        "                        ctx,\n"
        "                        custom_id,\n"
        "                        server_name,\n"
        "                        tool_name=tool_name,\n"
        "                        input_violations_detected=True,\n"
        "                        input_violation_types=violation_types,\n"
        "                        **finalize_request_timings(),\n"
        "                    ),\n"
        "                )"
    )
    if blocked_in_anchor in src:
        src = src.replace(blocked_in_anchor, blocked_in_replacement, 1)

    # 4c) Blocked-output log -- same shape.
    blocked_out_anchor = (
        "                logger.info(\n"
        "                    \"secure_tool_execution.execute_secure_tools.blocked_due_to_output_violations\",\n"
        "                    extra=build_log_extra(\n"
        "                        ctx,\n"
        "                        custom_id,\n"
        "                        server_name,\n"
        "                        tool_name=tool_name,\n"
        "                        output_violations_detected=True,\n"
        "                        output_violation_types=violation_types,\n"
        "                    ),\n"
        "                )"
    )
    blocked_out_replacement = (
        "                logger.info(\n"
        "                    \"secure_tool_execution.execute_secure_tools.blocked_due_to_output_violations\",\n"
        "                    extra=build_log_extra(\n"
        "                        ctx,\n"
        "                        custom_id,\n"
        "                        server_name,\n"
        "                        tool_name=tool_name,\n"
        "                        output_violations_detected=True,\n"
        "                        output_violation_types=violation_types,\n"
        "                        **finalize_request_timings(),\n"
        "                    ),\n"
        "                )"
    )
    if blocked_out_anchor in src:
        src = src.replace(blocked_out_anchor, blocked_out_replacement, 1)

    return src


def patch_stes(src: str) -> str:
    """Inject ``record_pii_entities`` + ``record_toxicity_subtypes`` plus a
    matching ``logger.info`` at the 3 guardrail-violation sites in
    secure_tool_execution_service.py.

    Why this is overlay-only
    ------------------------
    The audit / Tier-1 overlay deliberately skipped STES because their 5
    call sites included sites with significant line drift between v2.2.0
    and main (deny_list path, guardrail-None fail-closed path).  The 3
    sites we need here (input violation, sync output violation, async
    output violation) are stable -- the ``if not guardrail_response.
    is_safe:`` / ``record_guardrail_violations(...)`` pattern lives in
    the same shape on v2.2.0.  We anchor on ``record_guardrail_violations(``
    plus the trailing ``**auth_context,\\n                )`` closer and
    splice the new helpers in directly after it.

    The helpers themselves arrived via patch_metrics_helpers; the
    instruments via patch_opentelemetry_provider + patch_config_manager.
    This file-side patch is what actually CALLS them.
    """
    # Add the two imports to the existing metrics_helpers import block.
    # v2.2.0 imports record_guardrail_violations from metrics_helpers; we
    # piggyback on that line so the diff stays one-shot.
    import_anchor = "    record_guardrail_violations,"
    if import_anchor not in src:
        raise RuntimeError(
            "v2.2.0 STES missing 'record_guardrail_violations,' import "
            "anchor; cannot wire guardrail-detail helpers"
        )
    src = src.replace(
        import_anchor,
        (
            import_anchor
            + "\n    record_pii_entities,"
            + "\n    record_toxicity_subtypes,"
        ),
        1,
    )

    # Common injection -- everything after the record_guardrail_violations()
    # call returns.  We splice ONLY the two new helper calls (no log line
    # here -- the helpers' return dicts are intentionally NOT logged on
    # v2.2.0 because the violation log lines on v2.2.0 use a different
    # build_log_extra shape than main; the metric emission alone is what
    # the dashboard needs).
    def _new_block(direction: str) -> str:
        return (
            "                # Guardrail-detail: per-entity PII + per-subtype\n"
            "                # toxicity emission (overlay-injected). Feeds the\n"
            "                # Guardrails Deep Dive 'PII Entities by Direction',\n"
            "                # 'Top PII Entity Types', 'Toxicity Subtypes' and\n"
            "                # 'Top Toxicity Subtypes by Score Bucket' panels.\n"
            "                try:\n"
            "                    _pii_result = record_pii_entities(\n"
            "                        guardrail_response.violations,\n"
            f"                        \"{direction}\",\n"
            "                        server_name=server_name,\n"
            "                        tool_name=tool_name,\n"
            "                    )\n"
            "                    _tox_result = record_toxicity_subtypes(\n"
            "                        guardrail_response.violations,\n"
            f"                        \"{direction}\",\n"
            "                        server_name=server_name,\n"
            "                        tool_name=tool_name,\n"
            "                    )\n"
            "                    # Structured log line carrying the same shape\n"
            "                    # the dashboard's log-based panels query.\n"
            "                    # Also doubles as a schema-drift probe -- the\n"
            "                    # *_details_keys arrays surface what Enkrypt\n"
            "                    # actually put in metadata.details, so an\n"
            "                    # operator can spot when the upstream API\n"
            "                    # changes shape (e.g. 'entities' -> 'pii_list')\n"
            "                    # WITHOUT another deploy.\n"
            "                    logger.info(\n"
            "                        \"secure_tool_execution.guardrail.detector_detail\",\n"
            "                        extra={\n"
            f"                            \"direction\": \"{direction}\",\n"
            "                            \"server_name\": server_name,\n"
            "                            \"tool_name\": tool_name,\n"
            "                            **(_pii_result or {}),\n"
            "                            **(_tox_result or {}),\n"
            "                        },\n"
            "                    )\n"
            "                except Exception as _exc:\n"
            "                    # Don't lose the failure silently -- log it once\n"
            "                    # so we can fix the schema mismatch quickly.\n"
            "                    try:\n"
            "                        logger.warning(\n"
            "                            \"secure_tool_execution.guardrail.detector_detail.exc\",\n"
            "                            extra={\"error\": str(_exc), \"error_kind\": type(_exc).__name__},\n"
            "                        )\n"
            "                    except Exception:\n"
            "                        pass\n"
        )

    # All 3 sites use the same closing for record_guardrail_violations.
    # Order matters: input site fires BEFORE the two output sites; we use
    # replace(... count=1) on each occurrence to take them in document order.
    rg_close = (
        "                record_guardrail_violations(\n"
        "                    \"{direction}\",\n"
        "                    violation_types,\n"
        "                    server_name=server_name,\n"
        "                    tool_name=tool_name,\n"
        "                    **auth_context,\n"
        "                )"
    )
    # 1) input violation site
    anchor_in = rg_close.format(direction="input")
    if anchor_in not in src:
        raise RuntimeError("v2.2.0 STES missing input violation record_guardrail_violations anchor")
    src = src.replace(
        anchor_in,
        anchor_in + "\n" + _new_block("input"),
        1,
    )

    # 2) sync output violation site
    # 3) async output violation site
    # Both use direction="output" so they share the same anchor literal;
    # do two sequential single-replacement injections.
    anchor_out = rg_close.format(direction="output")
    if anchor_out not in src:
        raise RuntimeError("v2.2.0 STES missing output violation record_guardrail_violations anchor")
    src = src.replace(
        anchor_out,
        anchor_out + "\n" + _new_block("output"),
        1,
    )
    if anchor_out not in src:
        # Second occurrence might not be there if v2.2.0 only has the sync
        # output path -- that's fine, log and continue.
        print("[merge] STES second output anchor not found (async path absent?) -- skipping")
    else:
        src = src.replace(
            anchor_out,
            anchor_out + "\n" + _new_block("output"),
            1,
        )

    # --- Chain the phase-timing patches AFTER violation injection so the
    # import-line / log-line anchors are still resolvable.
    src = _patch_stes_phase_timings(src)

    return src


def patch_cache_service(src: str) -> str:
    """Wrap the cache lookup inside ``get_cached_tools_with_expiry`` with
    a phase_timer so the Cache & Performance dashboard's "Cache Lookup
    Duration" panel populates.  Anchors on the v2.2.0 shape:

        try:
            from secure_mcp_gateway.client import get_cached_tools

            cached = get_cached_tools(self.cache_client, server_id, server_name)

    No-op if anchor not found (phase_timer is no-op when no request
    timings dict is active, so missing the wrap is degraded-but-safe).
    """
    anchor = (
        "        try:\n"
        "            from secure_mcp_gateway.client import get_cached_tools\n"
        "\n"
        "            cached = get_cached_tools(self.cache_client, server_id, server_name)"
    )
    if anchor not in src:
        print("[merge] cache_service: cache lookup anchor not found -- skipping")
        return src
    replacement = (
        "        try:\n"
        "            # Time the cache lookup so Cache & Performance dashboard's\n"
        "            # \"Cache Lookup Duration\" panel populates.  phase_timer is\n"
        "            # a no-op when no request timings dict is active (e.g. cold\n"
        "            # discovery from a background task), which is the correct\n"
        "            # behaviour -- only per-request lookups should count.\n"
        "            from secure_mcp_gateway.client import get_cached_tools\n"
        "            from secure_mcp_gateway.plugins.telemetry.metrics_helpers import (\n"
        "                phase_timer,\n"
        "            )\n"
        "\n"
        "            with phase_timer(\"cache_lookup_duration_ms\"):\n"
        "                cached = get_cached_tools(self.cache_client, server_id, server_name)"
    )
    return src.replace(anchor, replacement, 1)


def patch_session_pool(src: str) -> str:
    """Add ``mcp_handshake_duration_ms`` timer around ``session.initialize()``
    plus ``record_session_active`` calls at pool lifecycle sites.

    session_pool.py comes from the v2.2.0-sessionpoolpatch image (not
    v2.2.0 baseline) so the anchors here are the PR #40-shape, not the
    raw v2.2.0 shape.
    """
    # 1) MCP handshake timer.  Anchor on session.initialize() inside the
    # build_server_params / ClientSession nest in _worker.
    handshake_anchor = (
        "            async with build_server_params(\n"
        "                effective_entry, command, args, env\n"
        "            ) as (read, write):\n"
        "                async with ClientSession(read, write) as session:\n"
        "                    init_result = await session.initialize()"
    )
    handshake_replacement = (
        "            # Time the MCP handshake so the Cache & Performance\n"
        "            # dashboard's \"MCP Handshake Latency\" panel populates.\n"
        "            from secure_mcp_gateway.plugins.telemetry.metrics_helpers import (\n"
        "                phase_timer,\n"
        "            )\n"
        "            async with build_server_params(\n"
        "                effective_entry, command, args, env\n"
        "            ) as (read, write):\n"
        "                async with ClientSession(read, write) as session:\n"
        "                    async with phase_timer(\"mcp_handshake_duration_ms\"):\n"
        "                        init_result = await session.initialize()"
    )
    if handshake_anchor in src:
        src = src.replace(handshake_anchor, handshake_replacement, 1)
    else:
        print("[merge] session_pool: handshake anchor not found -- skipping handshake timer")

    # 2) Session-active gauge in acquire() (after self._pool[key] = pooled).
    acquire_anchor = (
        "                if old is not None and not old._closed:\n"
        "                    await old.close()\n"
        "                self._pool[key] = pooled"
    )
    acquire_replacement = (
        "                if old is not None and not old._closed:\n"
        "                    await old.close()\n"
        "                    try:\n"
        "                        from secure_mcp_gateway.plugins.telemetry.metrics_helpers import (\n"
        "                            record_session_active,\n"
        "                        )\n"
        "                        record_session_active(-1, server_name=server_name)\n"
        "                    except Exception:\n"
        "                        pass\n"
        "                self._pool[key] = pooled\n"
        "                try:\n"
        "                    from secure_mcp_gateway.plugins.telemetry.metrics_helpers import (\n"
        "                        record_session_active,\n"
        "                    )\n"
        "                    record_session_active(+1, server_name=server_name)\n"
        "                except Exception:\n"
        "                    pass"
    )
    if acquire_anchor in src:
        src = src.replace(acquire_anchor, acquire_replacement, 1)
    else:
        print("[merge] session_pool: acquire anchor not found -- skipping session_active gauge")

    return src


PATCHERS = {
    "plugins/telemetry/conventions.py": patch_conventions,
    "plugins/telemetry/opentelemetry_provider.py": patch_opentelemetry_provider,
    "plugins/telemetry/metrics_helpers.py": patch_metrics_helpers,
    "plugins/telemetry/config_manager.py": patch_config_manager,
    "exceptions.py": patch_exceptions,
    # Guardrail-detail: inject record_pii_entities + record_toxicity_subtypes
    # at the 3 violation sites in secure_tool_execution_service.py.  This is
    # the FIRST time we patch STES via overlay -- the audit/Tier-1 work
    # deliberately skipped it because their 5 call sites had bigger line
    # drift, but the violation-handling sites we need here are stable
    # between v2.2.0 and main, so a surgical anchor-based patch works.
    "services/execution/secure_tool_execution_service.py": patch_stes,
    # Cache & Performance: wrap the cache lookup so cache_lookup_duration_ms
    # gets recorded on every per-request cache hit/miss.
    "services/cache/cache_service.py": patch_cache_service,
}


def main() -> int:
    if OVERLAY_DIR.exists():
        shutil.rmtree(OVERLAY_DIR)
    OVERLAY_DIR.mkdir(parents=True)

    for rel, fn in PATCHERS.items():
        print(f"[merge] {rel}")
        v220_src = _dump_from_image(rel)
        merged = fn(v220_src)
        _write(rel, merged)

    # session_pool.py: pull it OUT OF the existing v2.2.0-sessionpoolpatch
    # image (which is already deployed to dev with PR #40 applied) rather
    # than from this branch -- because `main` (which this branch is based
    # on) does NOT contain the PR #40 fix yet, so copying main's file
    # would regress dev's hang-protection.
    sp_proc = subprocess.run(
        [
            "docker", "run", "--rm", "--entrypoint", "cat",
            "enkryptai/secure-mcp-gateway:v2.2.0-sessionpoolpatch",
            f"{PKG_ROOT}/services/session/session_pool.py",
        ],
        check=True,
        capture_output=True,
    )
    sp_src = sp_proc.stdout.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    if "acquire_timeout" not in sp_src or "connect_timeout" not in sp_src:
        raise RuntimeError(
            "v2.2.0-sessionpoolpatch session_pool.py missing acquire/connect "
            "timeouts -- the source-of-truth patch image is stale; aborting"
        )
    # Apply MCP handshake timer + session-active gauge wiring on top.
    sp_src = patch_session_pool(sp_src)
    _write("services/session/session_pool.py", sp_src)
    print(f"[copy+patch] services/session/session_pool.py from v2.2.0-sessionpoolpatch image (PR #40) + cacheperf timers")

    # ---- audit.py + audit_middleware.py + gateway_playground_routes.py ----
    # These are NEW modules; v2.2.0 doesn't have them, so we copy from
    # the working branch directly.  No merge needed.
    for new_file in (
        "audit.py",
        "audit_middleware.py",
        "gateway_playground_routes.py",
    ):
        src_text = (REPO / "src" / "secure_mcp_gateway" / new_file).read_text(
            encoding="utf-8"
        )
        _write(new_file, src_text)
        print(f"[copy] {new_file} from main branch (new module)")

    # ---- api_server.py: inject the audit middleware registration ----
    # The HTTPException handler my branch added is also there but it's
    # bigger and overlapped with v2.2.0's other handlers; we ship just
    # the 2-line middleware registration that's the *minimum* delta to
    # turn the audit emission on.
    api_server_src = _dump_from_image("api_server.py")
    api_server_patched = patch_api_server(api_server_src)
    _write("api_server.py", api_server_patched)

    # ---- gateway.py: register the playground routes on FastMCP --------
    # Mounts /mcp-playground/{test-server,get-tools,call-tool} onto the
    # FastMCP gateway via custom_route so the playground UI works on
    # the existing port 8000 / ingress -- no api_server.py process or
    # k8s changes needed.
    gateway_src = _dump_from_image("gateway.py")
    gateway_patched = patch_gateway(gateway_src)
    _write("gateway.py", gateway_patched)
    print("[merge] gateway.py + playground routes registration")

    # ---- gateway_cache_routes.py: inject log_audit for cache flush ----
    # This file lives in v2.2.0 only (main doesn't have it yet) so the
    # call sites can't be on the branch -- we surgically inject them at
    # overlay-build time so the deployed image emits cache_flush events.
    gcr_src = _dump_from_image("gateway_cache_routes.py")
    gcr_patched = patch_gateway_cache_routes(gcr_src)
    _write("gateway_cache_routes.py", gcr_patched)
    print("[merge] gateway_cache_routes.py (v2.2.0-only)")

    print("\nOK overlay ready at", OVERLAY_DIR)
    return 0


def patch_gateway_cache_routes(src: str) -> str:
    """Inject ``log_audit('cache_flush', ...)`` into v2.2.0's
    ``_flush_handler`` (both success and failure paths).

    Why this is overlay-only (not on the branch)
    --------------------------------------------
    ``gateway_cache_routes.py`` only exists on v2.2.0 / the dashboards
    branch -- main doesn't have it yet, so we can't carry the call sites
    on the branch where the rest of the audit instrumentation lives.
    Instead we surgically inject them at overlay-build time so the
    deployed image emits cache_flush audit events even though main's
    source doesn't reference the file.
    """

    # Anchor 1: success path -- the existing logger.info('cache flushed').
    success_anchor = (
        "    logger.info(\n"
        "        \"[gateway_cache_routes] cache flushed\","
    )
    if success_anchor not in src:
        raise RuntimeError(
            "v2.2.0 gateway_cache_routes.py missing success log anchor; "
            "cannot inject audit emission safely"
        )
    success_injection = (
        "    try:\n"
        "        from secure_mcp_gateway.audit import log_audit\n"
        "\n"
        "        log_audit(\n"
        "            action=\"cache_flush\",\n"
        "            resource_type=\"cache\",\n"
        "            surface=\"mcp_gateway\",\n"
        "            actor=authz.get(\"principal\"),\n"
        "            actor_id=mask_key(apikey),\n"
        "            target_id=\"all\" if include_tool_cache else \"gateway_config\",\n"
        "            success=True,\n"
        "            scope=\"all\" if include_tool_cache else \"gateway_config\",\n"
        "            authorization_path=authz[\"via\"],\n"
        "        )\n"
        "    except Exception:\n"
        "        pass\n"
    )
    src = src.replace(
        success_anchor, success_injection + success_anchor, 1,
    )

    # Anchor 2: unauthorized path -- when _auth_admin returns a rejection
    # JSONResponse, the handler short-circuits.  We want to emit a
    # failed audit event there too.
    unauthorized_anchor = (
        "    auth_err, authz = await _auth_admin(request)\n"
        "    if auth_err is not None:\n"
        "        return auth_err"
    )
    if unauthorized_anchor not in src:
        raise RuntimeError(
            "v2.2.0 gateway_cache_routes.py missing _auth_admin anchor; "
            "cannot inject unauthorized audit emission"
        )
    unauthorized_injection = (
        "    auth_err, authz = await _auth_admin(request)\n"
        "    if auth_err is not None:\n"
        "        try:\n"
        "            from secure_mcp_gateway.audit import log_audit\n"
        "\n"
        "            log_audit(\n"
        "                action=\"cache_flush\",\n"
        "                resource_type=\"cache\",\n"
        "                surface=\"mcp_gateway\",\n"
        "                actor_id=mask_key(request.headers.get(\"apikey\") or \"\"),\n"
        "                success=False,\n"
        "                failure_reason=\"unauthorized\",\n"
        "            )\n"
        "        except Exception:\n"
        "            pass\n"
        "        return auth_err"
    )
    src = src.replace(unauthorized_anchor, unauthorized_injection, 1)

    return src


def patch_gateway(src: str) -> str:
    """Add ``register_gateway_playground_routes(mcp)`` to v2.2.0's
    gateway.py so the FastMCP server mounts the 3 playground HTTP
    routes (/mcp-playground/test-server, /mcp-playground/get-tools,
    /mcp-playground/call-tool) on port 8000 -- making the playground
    UI reachable via the existing ingress without needing api_server.py
    to run in a separate process.

    Anchors on the END of v2.2.0's existing try/except that registers
    gateway_cache_routes (around line 955-970).  We inject a parallel
    try/except right after the closing ``)`` of the cache-routes
    except-block.

    Why this is a SEPARATE try/except (not appended inside the cache one)
    --------------------------------------------------------------------
    Bundling them means a failure to import playground would also kill
    cache-flush registration, regressing PR #40 functionality.  Keeping
    them isolated lets either one degrade independently -- the gateway
    starts up and runs whether one, both, or neither route module
    imports cleanly.
    """
    anchor = (
        "try:\n"
        "    from secure_mcp_gateway.gateway_cache_routes import (\n"
        "        register_gateway_cache_routes,\n"
        "    )\n"
        "\n"
        "    register_gateway_cache_routes(mcp)\n"
        "except Exception as e:\n"
        "    logger.error(\n"
        "        \"[gateway] failed to register gateway cache routes\",\n"
        "        error=str(e),\n"
        "        exc_info=True,\n"
        "    )"
    )
    if anchor not in src:
        raise RuntimeError(
            "patch_gateway: v2.2.0 cache-routes registration anchor not "
            "found; cannot safely append playground-routes registration"
        )
    injection = (
        "\n\n"
        "# Mount the playground HTTP routes onto the gateway so the\n"
        "# playground UI works against the SAME port + ingress as the\n"
        "# MCP protocol -- no separate api_server.py process required.\n"
        "# See gateway_playground_routes.py for the full rationale.\n"
        "try:\n"
        "    from secure_mcp_gateway.gateway_playground_routes import (\n"
        "        register_gateway_playground_routes,\n"
        "    )\n"
        "\n"
        "    register_gateway_playground_routes(mcp)\n"
        "except Exception as e:\n"
        "    logger.error(\n"
        "        \"[gateway] failed to register gateway playground routes\",\n"
        "        error=str(e),\n"
        "        exc_info=True,\n"
        "    )"
    )
    return src.replace(anchor, anchor + injection, 1)


def patch_api_server(src: str) -> str:
    """Inject the audit middleware registration into v2.2.0's api_server.py.

    Anchor: the closing call of ``app.add_middleware(CORSMiddleware,
    ...)`` -- always present in v2.2.0 because CORS is configured for
    every admin REST surface.  We insert the audit middleware
    registration block immediately after that call so the order is:
    CORS first, then audit -- middlewares fire LIFO so audit observes
    requests post-CORS-handling.

    Also injects the HTTPException handler block for
    ``enkrypt.auth.unauthorized_http`` because that emission is what
    powers the dashboard's "Unauthorized HTTP" KPI tile.
    """
    middleware_block = (
        "\n\n"
        "# ---- Audit middleware (auto-injected by build_tier1_overlay.py) ----\n"
        "# Emits log_audit() events for every admin mutation via a single\n"
        "# (method, path) -> action regex table.  See audit_middleware.py.\n"
        "from secure_mcp_gateway.audit_middleware import audit_http_middleware  # noqa: E402\n"
        "\n"
        "app.middleware(\"http\")(audit_http_middleware)\n"
    )

    # CORS anchor: the closing paren of the add_middleware call.  Use
    # the full signature to avoid matching any other add_middleware call.
    cors_open = "app.add_middleware(\n    CORSMiddleware,"
    if cors_open not in src:
        raise RuntimeError(
            "v2.2.0 api_server.py missing CORSMiddleware anchor; cannot "
            "inject audit middleware safely"
        )
    # Find the matching close paren for that call.
    start = src.index(cors_open)
    depth = 0
    end = None
    for i, ch in enumerate(src[start:], start=start):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise RuntimeError("could not find CORS add_middleware closing paren")
    src = src[:end] + middleware_block + src[end:]

    # HTTPException handler for unauthorized_http.  Inject it right
    # before the existing global @app.exception_handler(Exception) so
    # the more-specific HTTPException handler is registered first.
    http_handler_block = (
        '\n\n'
        '@app.exception_handler(HTTPException)\n'
        'async def http_exception_handler(request, exc):\n'
        '    """Emit enkrypt.auth.unauthorized_http on every 401/403.\n'
        '\n'
        '    Injected by build_tier1_overlay.py so the audit middleware\n'
        '    doesn\'t double-count unauthorized responses (the middleware\n'
        '    explicitly skips status 401/403; this handler claims them).\n'
        '    """\n'
        '    if exc.status_code in (401, 403):\n'
        '        try:\n'
        '            from secure_mcp_gateway.plugins.telemetry.metrics_helpers import (\n'
        '                record_unauthorized_http,\n'
        '            )\n'
        '\n'
        '            record_unauthorized_http(\n'
        '                endpoint=request.url.path,\n'
        '                surface="rest_api",\n'
        '                method=request.method,\n'
        '                status_code=exc.status_code,\n'
        '                reason=(\n'
        '                    exc.detail.get("error", {}).get("message")\n'
        '                    if isinstance(exc.detail, dict) else str(exc.detail)\n'
        '                ),\n'
        '            )\n'
        '        except Exception:\n'
        '            pass\n'
        '    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})\n'
    )
    eh_anchor = "@app.exception_handler(Exception)"
    if eh_anchor not in src:
        raise RuntimeError(
            "v2.2.0 api_server.py missing @app.exception_handler(Exception); "
            "cannot inject HTTPException handler"
        )
    src = src.replace(eh_anchor, http_handler_block + "\n" + eh_anchor, 1)
    return src


if __name__ == "__main__":
    sys.exit(main())
