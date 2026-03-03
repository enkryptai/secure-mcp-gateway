"""Unified configuration loader.

Loading priority (standardised across all products):
  1. Explicit Python config object  (programmatic)
  2. Environment variables           (env always wins over file)
  3. JSON config file                (``~/.enkrypt/enkrypt_config.json``
     or ``ENKRYPT_CONFIG_PATH``)
  4. Built-in defaults

This fixes:
  - Gateway having zero env-var support
  - Claude Code hooks' reversed priority (file > env)
  - ``ENKRYPT_API_URL`` vs ``ENKRYPT_BASE_URL`` naming mismatch
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from enkrypt_security.config.models import (
    EnkryptApiConfig,
    EnkryptConfig,
    ExporterType,
    GuardrailPolicy,
    SDKSection,
    TelemetryConfig,
    hook_platform_from_dict,
    sdk_section_from_dict,
)

logger = logging.getLogger("enkrypt_security.config")

# ---------------------------------------------------------------------------
# Well-known paths and environment variable names
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_FILENAME = "enkrypt_config.json"
DEFAULT_CONFIG_DIR = ".enkrypt"

ENV_CONFIG_PATH = "ENKRYPT_CONFIG_PATH"
ENV_API_KEY = "ENKRYPT_API_KEY"
ENV_BASE_URL = "ENKRYPT_BASE_URL"
ENV_GUARDRAIL_NAME = "ENKRYPT_GUARDRAIL_NAME"
ENV_GUARDRAIL_POLICY = "ENKRYPT_GUARDRAIL_POLICY"  # deprecated alias
ENV_BLOCK_LIST = "ENKRYPT_BLOCK_LIST"
ENV_FAIL_OPEN = "ENKRYPT_FAIL_OPEN"
ENV_TIMEOUT = "ENKRYPT_TIMEOUT"
ENV_SSL_VERIFY = "ENKRYPT_SSL_VERIFY"
ENV_TELEMETRY_ENABLED = "ENKRYPT_TELEMETRY_ENABLED"
ENV_TELEMETRY_EXPORTER = "ENKRYPT_TELEMETRY_EXPORTER"
ENV_TELEMETRY_ENDPOINT = "ENKRYPT_TELEMETRY_ENDPOINT"
ENV_TELEMETRY_SERVICE_NAME = "ENKRYPT_TELEMETRY_SERVICE_NAME"

# SDK checkpoint env vars
ENV_CHECK_PRE_LLM = "ENKRYPT_CHECK_PRE_LLM"
ENV_CHECK_PRE_TOOL = "ENKRYPT_CHECK_PRE_TOOL"
ENV_CHECK_POST_TOOL = "ENKRYPT_CHECK_POST_TOOL"
ENV_CHECK_POST_LLM = "ENKRYPT_CHECK_POST_LLM"


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _default_config_path() -> Path:
    """``~/.enkrypt/enkrypt_config.json``."""
    return Path.home() / DEFAULT_CONFIG_DIR / DEFAULT_CONFIG_FILENAME


def _resolve_config_path(explicit: str | Path | None = None) -> Path | None:
    """Find the config file, checking explicit path, env var, then default."""
    if explicit is not None:
        p = Path(explicit)
        if p.is_file():
            return p
        logger.warning("Explicit config path does not exist: %s", explicit)
        return None

    env_path = os.environ.get(ENV_CONFIG_PATH)
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p
        logger.warning(
            "%s points to non-existent file: %s", ENV_CONFIG_PATH, env_path
        )

    default = _default_config_path()
    if default.is_file():
        return default

    return None


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load config from %s: %s", path, exc)
        return {}


# ---------------------------------------------------------------------------
# Dict → dataclass helpers
# ---------------------------------------------------------------------------

def _parse_bool(value: str) -> bool:
    return value.lower() in ("1", "true", "yes", "on")


def _api_from_dict(data: dict[str, Any]) -> EnkryptApiConfig:
    return EnkryptApiConfig(
        api_key=str(data.get("api_key", "")),
        base_url=str(data.get("base_url", "https://api.enkryptai.com")),
        fail_open=bool(data.get("fail_open", True)),
        timeout=float(data.get("timeout", 15.0)),
        ssl_verify=bool(data.get("ssl_verify", True)),
    )


def _guardrail_from_dict(data: dict[str, Any]) -> GuardrailPolicy:
    return GuardrailPolicy(
        enabled=bool(data.get("enabled", False)),
        guardrail_name=str(data.get("guardrail_name", "")),
        block=list(data.get("block", [])),
        pii_redaction=bool(data.get("pii_redaction", False)),
        additional_config=dict(data.get("additional_config", {})),
    )


def _telemetry_from_dict(data: dict[str, Any]) -> TelemetryConfig:
    exporter_raw = data.get("exporter", "none")
    try:
        exporter = ExporterType(exporter_raw)
    except ValueError:
        logger.warning("Unknown exporter type %r, falling back to NONE", exporter_raw)
        exporter = ExporterType.NONE

    return TelemetryConfig(
        enabled=bool(data.get("enabled", False)),
        exporter=exporter,
        endpoint=str(data.get("endpoint", "")),
        service_name=str(data.get("service_name", "enkrypt-security")),
        headers=dict(data.get("headers", {})),
        insecure=bool(data.get("insecure", False)),
    )


def _config_from_dict(data: dict[str, Any]) -> EnkryptConfig:
    _KNOWN_KEYS = {"api", "input_guardrails", "output_guardrails", "telemetry"}
    extra: dict[str, Any] = {}
    for k, v in data.items():
        if k in _KNOWN_KEYS:
            continue
        if k == "sdk" and isinstance(v, dict):
            extra["sdk"] = sdk_section_from_dict(v)
        elif k == "hooks" and isinstance(v, dict):
            extra["hooks"] = {
                platform: hook_platform_from_dict(cfg) if isinstance(cfg, dict) else cfg
                for platform, cfg in v.items()
            }
        else:
            extra[k] = v

    return EnkryptConfig(
        api=_api_from_dict(data.get("api", {})),
        input_guardrails=_guardrail_from_dict(data.get("input_guardrails", {})),
        output_guardrails=_guardrail_from_dict(data.get("output_guardrails", {})),
        telemetry=_telemetry_from_dict(data.get("telemetry", {})),
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Environment-variable overrides
# ---------------------------------------------------------------------------

def _apply_env_overrides(config: EnkryptConfig) -> EnkryptConfig:
    """Layer environment variables on top of the config (env wins)."""

    # API settings
    val = os.environ.get(ENV_API_KEY)
    if val:
        config.api.api_key = val

    val = os.environ.get(ENV_BASE_URL) or os.environ.get("ENKRYPT_API_URL")
    if val:
        for suffix in ("/guardrails/policy/detect", "/guardrails/policy", "/guardrails"):
            if val.endswith(suffix):
                val = val[: -len(suffix)]
                break
        config.api.base_url = val.rstrip("/")

    val = os.environ.get(ENV_FAIL_OPEN)
    if val:
        config.api.fail_open = _parse_bool(val)

    val = os.environ.get(ENV_TIMEOUT)
    if val:
        try:
            config.api.timeout = float(val)
        except ValueError:
            logger.warning("Invalid %s value: %r", ENV_TIMEOUT, val)

    val = os.environ.get(ENV_SSL_VERIFY)
    if val:
        config.api.ssl_verify = _parse_bool(val)

    # Guardrail name: ENKRYPT_GUARDRAIL_NAME preferred, ENKRYPT_GUARDRAIL_POLICY as alias
    val = os.environ.get(ENV_GUARDRAIL_NAME) or os.environ.get(ENV_GUARDRAIL_POLICY)
    if val:
        config.input_guardrails.guardrail_name = val
        config.output_guardrails.guardrail_name = val

    val = os.environ.get(ENV_BLOCK_LIST)
    if val:
        block = [b.strip() for b in val.split(",") if b.strip()]
        config.input_guardrails.block = block
        config.output_guardrails.block = block

    # Telemetry settings
    val = os.environ.get(ENV_TELEMETRY_ENABLED)
    if val:
        config.telemetry.enabled = _parse_bool(val)

    val = os.environ.get(ENV_TELEMETRY_EXPORTER)
    if val:
        try:
            config.telemetry.exporter = ExporterType(val)
        except ValueError:
            logger.warning("Unknown %s value: %r", ENV_TELEMETRY_EXPORTER, val)

    val = os.environ.get(ENV_TELEMETRY_ENDPOINT)
    if val:
        config.telemetry.endpoint = val

    val = os.environ.get(ENV_TELEMETRY_SERVICE_NAME)
    if val:
        config.telemetry.service_name = val

    # SDK checkpoint overrides
    sdk: SDKSection = config.get_sdk()
    _any_checkpoint_set = False
    for env_name, key in (
        (ENV_CHECK_PRE_LLM, "pre_llm"),
        (ENV_CHECK_PRE_TOOL, "pre_tool"),
        (ENV_CHECK_POST_TOOL, "post_tool"),
        (ENV_CHECK_POST_LLM, "post_llm"),
    ):
        val = os.environ.get(env_name)
        if val:
            sdk.checkpoints[key] = _parse_bool(val)
            _any_checkpoint_set = True
    if _any_checkpoint_set:
        config.extra["sdk"] = sdk

    return config


# ---------------------------------------------------------------------------
# Hot-reload support
# ---------------------------------------------------------------------------

_cached_config: EnkryptConfig | None = None
_cached_mtime: float = 0.0
_cached_path: Path | None = None
_lock = threading.Lock()


def _invalidate_cache() -> None:
    global _cached_config, _cached_mtime, _cached_path
    with _lock:
        _cached_config = None
        _cached_mtime = 0.0
        _cached_path = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(
    *,
    config: EnkryptConfig | None = None,
    config_path: str | Path | None = None,
    apply_env: bool = True,
    use_cache: bool = True,
) -> EnkryptConfig:
    """Load configuration with standardised priority.

    Priority:
      1. ``config`` — explicit programmatic object (highest)
      2. Environment variables (if ``apply_env=True``)
      3. JSON file at ``config_path`` / ``ENKRYPT_CONFIG_PATH`` / default
      4. Built-in defaults (lowest)

    Args:
        config: Pre-built config.  If provided, file loading is skipped.
        config_path: Explicit file path (overrides env and default discovery).
        apply_env: Whether to layer env-var overrides on top.
        use_cache: Cache file-loaded configs and hot-reload on mtime change.

    Returns:
        Fully resolved :class:`EnkryptConfig`.
    """
    global _cached_config, _cached_mtime, _cached_path

    if config is not None:
        result = config
    else:
        path = _resolve_config_path(config_path)

        if path and use_cache:
            with _lock:
                mtime = path.stat().st_mtime if path.is_file() else 0.0
                if (
                    _cached_config is not None
                    and _cached_path == path
                    and _cached_mtime == mtime
                ):
                    result = _cached_config
                else:
                    data = _load_json_file(path)
                    result = _config_from_dict(data)
                    _cached_config = result
                    _cached_mtime = mtime
                    _cached_path = path
                    logger.debug("Loaded config from %s (mtime=%.0f)", path, mtime)
        elif path:
            data = _load_json_file(path)
            result = _config_from_dict(data)
            logger.debug("Loaded config from %s", path)
        else:
            result = EnkryptConfig()

    if apply_env:
        result = _apply_env_overrides(result)

    return result


# ---------------------------------------------------------------------------
# Gateway config adapter
# ---------------------------------------------------------------------------

def from_gateway_config(
    gateway_dict: dict[str, Any],
    plugins_config: dict[str, Any] | None = None,
) -> EnkryptConfig:
    """Convert a gateway-format config dict to a shared EnkryptConfig.

    The gateway's config has a different structure:
      - API key/URL in plugins.guardrails.config or plugins.auth.config
      - No top-level "api" section
      - Per-server guardrails instead of global guardrails

    This adapter extracts what it can for the shared model.
    """
    plugins = plugins_config or gateway_dict.get("plugins", {})

    guardrails_plugin = plugins.get("guardrails", {}).get("config", {})
    auth_plugin = plugins.get("auth", {}).get("config", {})

    api_key = (
        guardrails_plugin.get("api_key")
        or auth_plugin.get("api_key", "")
    )
    base_url = (
        guardrails_plugin.get("base_url")
        or auth_plugin.get("base_url", "https://api.enkryptai.com")
    )

    telemetry_plugin = plugins.get("telemetry", {}).get("config", {})
    telemetry_provider = plugins.get("telemetry", {}).get("provider", "")

    exporter = ExporterType.NONE
    if telemetry_provider == "opentelemetry":
        exporter = ExporterType.OTLP_GRPC

    return EnkryptConfig(
        api=EnkryptApiConfig(
            api_key=api_key,
            base_url=base_url,
        ),
        telemetry=TelemetryConfig(
            enabled=telemetry_provider != "",
            exporter=exporter,
            endpoint=telemetry_plugin.get("url", ""),
            insecure=telemetry_plugin.get("insecure", False),
        ),
        extra={
            "gateway": {
                k: v for k, v in gateway_dict.items()
                if k not in ("plugins",)
            },
            "plugins": plugins,
        },
    )


def to_gateway_config(ec: EnkryptConfig) -> dict[str, Any]:
    """Convert a shared EnkryptConfig back to the legacy gateway format.

    This is the reverse of :func:`from_gateway_config`.  The gateway section
    stored in ``ec.extra["gateway"]`` is merged with top-level API / telemetry
    settings re-mapped into the ``plugins`` structure.
    """
    gateway_section = ec.extra.get("gateway", {})
    plugins = ec.extra.get("plugins", {
        "auth": {"provider": "local_apikey", "config": {}},
        "guardrails": {"provider": "enkrypt", "config": {}},
        "telemetry": {"provider": "", "config": {}},
    })

    # Push api settings back into plugins.guardrails.config
    gr_cfg = plugins.setdefault("guardrails", {}).setdefault("config", {})
    gr_cfg["api_key"] = ec.api.api_key
    gr_cfg["base_url"] = ec.api.base_url

    # Push telemetry settings back into plugins.telemetry
    tel_cfg = plugins.setdefault("telemetry", {}).setdefault("config", {})
    if ec.telemetry.enabled:
        plugins["telemetry"]["provider"] = "opentelemetry"
        tel_cfg["enabled"] = True
        tel_cfg["url"] = ec.telemetry.endpoint
        tel_cfg["insecure"] = ec.telemetry.insecure

    result = dict(gateway_section)
    result["plugins"] = plugins
    return result
