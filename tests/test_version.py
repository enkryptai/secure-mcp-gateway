"""Smoke test — verifies the package can be imported and exposes a version."""

from secure_mcp_gateway.version import __version__


def test_version_is_string():
    assert isinstance(__version__, str)


def test_version_not_empty():
    assert len(__version__) > 0
