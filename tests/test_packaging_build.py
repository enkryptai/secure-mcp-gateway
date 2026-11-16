"""Build the wheel and sdist with the installed setuptools backend and check what ships."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("setuptools")

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> dict[str, Path]:
    # Copy first: the backend writes egg-info into the source tree.
    root = tmp_path_factory.mktemp("pkg")
    shutil.copytree(
        REPO / "src",
        root / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "*.pyc"),
    )
    for name in ("pyproject.toml", "MANIFEST.in", "README_PYPI.md", "LICENSE"):
        shutil.copy2(REPO / name, root / name)

    script = "from setuptools import build_meta as b; b.build_wheel('dist'); b.build_sdist('dist')"
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-4000:]
    (wheel,) = (root / "dist").glob("*.whl")
    (sdist,) = (root / "dist").glob("*.tar.gz")
    return {"wheel": wheel, "sdist": sdist}


def _version() -> str:
    text = (REPO / "src" / "secure_mcp_gateway" / "version.py").read_text(
        encoding="utf-8"
    )
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


def test_wheel_is_pure_python_and_versioned(built):
    assert built["wheel"].name == f"secure_mcp_gateway-{_version()}-py3-none-any.whl"


def test_wheel_ships_package_data(built):
    with zipfile.ZipFile(built["wheel"]) as wheel:
        names = set(wheel.namelist())

    for required in (
        "secure_mcp_gateway/__init__.py",
        "secure_mcp_gateway/gateway.py",
        "secure_mcp_gateway/cli.py",
        "secure_mcp_gateway/openapi.json",
        "secure_mcp_gateway/example_enkrypt_mcp_config.json",
        "secure_mcp_gateway/example_enkrypt_cloud_config.json",
        "secure_mcp_gateway/plugins/auth/example_providers.py",
        "secure_mcp_gateway/bad_mcps/echo_mcp.py",
    ):
        assert required in names, required
    assert not any(name.startswith(("tests/", "src/")) for name in names)


def test_wheel_metadata_and_entry_point(built):
    dist_info = f"secure_mcp_gateway-{_version()}.dist-info"
    with zipfile.ZipFile(built["wheel"]) as wheel:
        metadata = wheel.read(f"{dist_info}/METADATA").decode()
        entry_points = wheel.read(f"{dist_info}/entry_points.txt").decode()

    assert "Name: secure-mcp-gateway" in metadata
    assert f"Version: {_version()}" in metadata
    assert "License-Expression: Apache-2.0" in metadata
    assert "Requires-Python: >=3.10" in metadata
    assert re.search(r"^Requires-Dist: pyjwt", metadata, re.M)
    assert re.search(r"^Requires-Dist: mcp\[cli\]", metadata, re.M)
    assert re.search(r"^Provides-Extra: dev", metadata, re.M)
    assert "secure-mcp-gateway = secure_mcp_gateway.cli:main" in entry_points


def test_sdist_ships_sources_and_manifest_data(built):
    prefix = f"secure_mcp_gateway-{_version()}/"
    with tarfile.open(built["sdist"]) as sdist:
        names = {name.removeprefix(prefix) for name in sdist.getnames()}

    for required in (
        "pyproject.toml",
        "PKG-INFO",
        "src/secure_mcp_gateway/gateway.py",
        "src/secure_mcp_gateway/openapi.json",
        "src/secure_mcp_gateway/example_enkrypt_mcp_config.json",
    ):
        assert required in names, required
