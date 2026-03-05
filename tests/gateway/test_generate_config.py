"""Tests for generate_unified_config() across hook platforms and SDK combinations."""

import pytest

from enkryptai_agent_security.gateway.cli import generate_unified_config
from enkryptai_agent_security.config.hook_defaults import (
    PLATFORM_DEFAULTS,
    SUPPORTED_PLATFORMS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOP_LEVEL_ALWAYS = {"api", "telemetry", "gateway"}
_GATEWAY_EXPECTED_KEYS = {
    "admin_apikey", "log_level", "use_remote_config", "cache",
    "async_guardrails", "timeout_settings", "mcp_configs",
    "projects", "users", "apikeys",
}
_SDK_CHECKPOINTS = {"pre_llm", "pre_tool", "post_tool", "post_llm"}


def _assert_top_level(cfg: dict) -> None:
    """Every config must contain api, telemetry, and gateway."""
    for key in _TOP_LEVEL_ALWAYS:
        assert key in cfg, f"Missing top-level key: {key}"


def _assert_gateway(cfg: dict) -> None:
    gw = cfg["gateway"]
    for key in _GATEWAY_EXPECTED_KEYS:
        assert key in gw, f"Missing gateway sub-key: {key}"


# ---------------------------------------------------------------------------
# 1. Default (no flags)
# ---------------------------------------------------------------------------

def test_default_no_flags():
    cfg = generate_unified_config()
    _assert_top_level(cfg)
    _assert_gateway(cfg)
    assert "hooks" not in cfg
    assert "sdk" not in cfg


# ---------------------------------------------------------------------------
# 2. Each single hook platform (parametrized)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("platform", SUPPORTED_PLATFORMS)
def test_single_hook_platform(platform):
    cfg = generate_unified_config(hook_platforms=[platform])
    _assert_top_level(cfg)
    _assert_gateway(cfg)
    assert "hooks" in cfg
    assert platform in cfg["hooks"]
    assert len(cfg["hooks"]) == 1
    assert "sdk" not in cfg


# ---------------------------------------------------------------------------
# 3. Multiple hooks
# ---------------------------------------------------------------------------

def test_multiple_hooks():
    platforms = ["cursor", "claude_code"]
    cfg = generate_unified_config(hook_platforms=platforms)
    _assert_top_level(cfg)
    assert set(cfg["hooks"].keys()) == set(platforms)


# ---------------------------------------------------------------------------
# 4. SDK only
# ---------------------------------------------------------------------------

def test_sdk_only():
    cfg = generate_unified_config(include_sdk=True)
    _assert_top_level(cfg)
    _assert_gateway(cfg)
    assert "sdk" in cfg
    assert "hooks" not in cfg

    sdk = cfg["sdk"]
    assert "provider_keys" in sdk
    assert "checkpoints" in sdk
    assert "guardrails" in sdk
    assert set(sdk["guardrails"].keys()) == _SDK_CHECKPOINTS


# ---------------------------------------------------------------------------
# 5. SDK + single hook
# ---------------------------------------------------------------------------

def test_sdk_plus_hook():
    cfg = generate_unified_config(include_sdk=True, hook_platforms=["cursor"])
    _assert_top_level(cfg)
    assert "sdk" in cfg
    assert "hooks" in cfg
    assert "cursor" in cfg["hooks"]


# ---------------------------------------------------------------------------
# 6. All platforms
# ---------------------------------------------------------------------------

def test_all_platforms():
    cfg = generate_unified_config(hook_platforms=list(SUPPORTED_PLATFORMS))
    _assert_top_level(cfg)
    assert set(cfg["hooks"].keys()) == set(SUPPORTED_PLATFORMS)


# ---------------------------------------------------------------------------
# 7. Unknown platform
# ---------------------------------------------------------------------------

def test_unknown_platform():
    cfg = generate_unified_config(hook_platforms=["nonexistent"])
    _assert_top_level(cfg)
    assert "hooks" not in cfg


# ---------------------------------------------------------------------------
# 8. Hyphenated name normalised
# ---------------------------------------------------------------------------

def test_hyphenated_name_normalised():
    cfg = generate_unified_config(hook_platforms=["claude-code"])
    _assert_top_level(cfg)
    assert "hooks" in cfg
    assert "claude_code" in cfg["hooks"]


# ---------------------------------------------------------------------------
# 9. Hook structure validation (parametrized)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("platform", SUPPORTED_PLATFORMS)
def test_hook_structure(platform):
    cfg = generate_unified_config(hook_platforms=[platform])
    hook = cfg["hooks"][platform]

    # sensitive_tools must be a list (may be absent if empty)
    if "sensitive_tools" in hook:
        assert isinstance(hook["sensitive_tools"], list)

    # Each policy key (non-meta) must have the right shape
    _meta = {"sensitive_tools", "sensitive_file_patterns"}
    for key, val in hook.items():
        if key in _meta:
            continue
        assert isinstance(val, dict), f"{platform}.{key} should be a dict"
        assert isinstance(val.get("enabled"), bool), f"{platform}.{key}.enabled"
        assert isinstance(val.get("guardrail_name"), str), f"{platform}.{key}.guardrail_name"
        assert isinstance(val.get("block"), list), f"{platform}.{key}.block"


# ---------------------------------------------------------------------------
# 10. SDK structure validation
# ---------------------------------------------------------------------------

def test_sdk_structure():
    cfg = generate_unified_config(include_sdk=True)
    sdk = cfg["sdk"]

    # provider_keys is a dict
    assert isinstance(sdk["provider_keys"], dict)

    # checkpoints has the 4 expected keys
    assert set(sdk["checkpoints"].keys()) == _SDK_CHECKPOINTS

    # guardrails has the 4 checkpoint policies
    guardrails = sdk["guardrails"]
    assert set(guardrails.keys()) == _SDK_CHECKPOINTS
    for cp_name in _SDK_CHECKPOINTS:
        policy = guardrails[cp_name]
        assert isinstance(policy["enabled"], bool)
        assert isinstance(policy["guardrail_name"], str)
        assert isinstance(policy["block"], list)
