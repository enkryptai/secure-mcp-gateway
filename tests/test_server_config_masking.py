"""Remote (url) servers keep their credential in ``config.headers``.

Listing servers returns that block to the MCP client, so it must be masked the
same way ``config.env`` is for stdio servers.
"""

from __future__ import annotations

from secure_mcp_gateway.utils import mask_server_config_sensitive_data

PAT = "ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH1234"


def test_authorization_header_is_masked() -> None:
    out = mask_server_config_sensitive_data(
        {
            "server_name": "demo-github-server",
            "config": {
                "type": "http",
                "url": "https://api.githubcopilot.com/mcp/",
                "headers": {"Authorization": f"Bearer {PAT}"},
            },
        }
    )
    masked = out["config"]["headers"]["Authorization"]
    assert PAT not in masked
    assert masked != f"Bearer {PAT}"
    assert out["config"]["url"] == "https://api.githubcopilot.com/mcp/"


def test_env_masking_still_applies() -> None:
    out = mask_server_config_sensitive_data(
        {"server_name": "s", "config": {"command": "npx", "env": {"GITHUB_TOKEN": PAT}}}
    )
    assert PAT not in out["config"]["env"]["GITHUB_TOKEN"]


def test_caller_config_is_not_mutated() -> None:
    original = {
        "server_name": "s",
        "config": {"url": "https://x/", "headers": {"Authorization": f"Bearer {PAT}"}},
    }
    mask_server_config_sensitive_data(original)
    assert original["config"]["headers"]["Authorization"] == f"Bearer {PAT}"


def test_non_dict_config_sections_are_ignored() -> None:
    out = mask_server_config_sensitive_data(
        {"server_name": "s", "config": {"headers": None, "env": "not-a-dict"}}
    )
    assert out["config"]["headers"] is None
