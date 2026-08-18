"""Unit tests for ``secure_mcp_gateway.utils.is_docker`` container detection.

The function is named ``is_docker`` for backwards compatibility but is really a
``is_in_container`` check. It must return True for:

* Kubernetes pods (any CRI: containerd, CRI-O, dockershim — k8s injects
  ``KUBERNETES_SERVICE_HOST`` into every pod).
* Plain Docker containers (``/.dockerenv`` marker).
* podman / CRI-O containers (``/run/.containerenv`` marker).
* cgroups v1 containers whose ``/proc/1/cgroup`` lines name a container
  runtime (``docker``, ``kubepods``, ``containerd``, ``lxc``).
* cgroups v2 unified-hierarchy containers whose PID 1 reports the bare
  ``0::/`` line (no scope/slice path).

It must return False for:

* A real Linux host on cgroups v2 (``/proc/1/cgroup`` reports a non-empty
  scope or slice path).
* A machine where ``/proc/1/cgroup`` does not exist (macOS, Windows).

These cases collectively guarantee that gateway pods on modern EKS / GKE /
AKS clusters resolve ``DOCKER_CONFIG_PATH`` instead of silently falling
back to the bundled example config.
"""

from __future__ import annotations

import builtins
import io
import os

import pytest

from secure_mcp_gateway import utils


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip KUBERNETES_SERVICE_HOST so each test starts from a clean baseline."""
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    yield


def _patch_cgroup(monkeypatch, cgroup_text: str | None) -> None:
    """Stub ``open('/proc/1/cgroup', ...)`` to return ``cgroup_text``.

    Pass ``cgroup_text=None`` to simulate a host where the file does not
    exist (raises FileNotFoundError, as on macOS / Windows).
    """
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):  # type: ignore[override]
        if path == "/proc/1/cgroup":
            if cgroup_text is None:
                raise FileNotFoundError(path)
            return io.StringIO(cgroup_text)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)


def _patch_marker_files(monkeypatch, present: set[str]) -> None:
    """Stub ``os.path.exists`` so only paths in ``present`` return True."""
    real_exists = os.path.exists

    def fake_exists(path):
        if path in {"/.dockerenv", "/run/.containerenv"}:
            return path in present
        return real_exists(path)

    monkeypatch.setattr(os.path, "exists", fake_exists)


# ---------------------------------------------------------------------------
# Positive cases — is_docker() must return True
# ---------------------------------------------------------------------------


def test_kubernetes_service_host_is_authoritative(monkeypatch):
    """A K8s pod is detected even when no other marker is present.

    Reproduces the live bug: EKS pod on containerd + cgroups v2 has no
    ``/.dockerenv``, no ``/run/.containerenv``, and an empty cgroup line.
    KUBERNETES_SERVICE_HOST alone must flip the answer to True.
    """
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "172.20.0.1")
    _patch_marker_files(monkeypatch, present=set())
    _patch_cgroup(monkeypatch, "0::/\n")

    assert utils.is_docker() is True


def test_dockerenv_marker_detected(monkeypatch):
    _patch_marker_files(monkeypatch, present={"/.dockerenv"})
    _patch_cgroup(monkeypatch, None)

    assert utils.is_docker() is True


def test_podman_containerenv_marker_detected(monkeypatch):
    _patch_marker_files(monkeypatch, present={"/run/.containerenv"})
    _patch_cgroup(monkeypatch, None)

    assert utils.is_docker() is True


def test_cgroups_v1_kubepods_detected(monkeypatch):
    """Legacy K8s + Docker shim path: cgroup line names ``kubepods``."""
    _patch_marker_files(monkeypatch, present=set())
    _patch_cgroup(
        monkeypatch,
        "12:devices:/kubepods/burstable/podabc123/def456\n"
        "11:cpu,cpuacct:/kubepods/burstable/podabc123/def456\n",
    )

    assert utils.is_docker() is True


def test_cgroups_v1_docker_keyword_detected(monkeypatch):
    """Plain Docker container on cgroups v1."""
    _patch_marker_files(monkeypatch, present=set())
    _patch_cgroup(
        monkeypatch,
        "11:cpu,cpuacct:/docker/0123456789abcdef\n",
    )

    assert utils.is_docker() is True


def test_cgroups_v2_unified_empty_path_detected(monkeypatch):
    """cgroups v2 container PID 1 is exactly ``0::/`` (no scope)."""
    _patch_marker_files(monkeypatch, present=set())
    _patch_cgroup(monkeypatch, "0::/\n")

    assert utils.is_docker() is True


# ---------------------------------------------------------------------------
# Negative cases — is_docker() must return False
# ---------------------------------------------------------------------------


def test_cgroups_v2_host_with_init_scope_not_container(monkeypatch):
    """Real systemd host on cgroups v2 reports a non-empty path."""
    _patch_marker_files(monkeypatch, present=set())
    _patch_cgroup(monkeypatch, "0::/init.scope\n")

    assert utils.is_docker() is False


def test_cgroups_v2_host_with_system_slice_not_container(monkeypatch):
    _patch_marker_files(monkeypatch, present=set())
    _patch_cgroup(monkeypatch, "0::/system.slice/walinuxagent.service\n")

    assert utils.is_docker() is False


def test_no_cgroup_file_macos_or_windows_returns_false(monkeypatch):
    """On macOS / Windows ``/proc/1/cgroup`` raises FileNotFoundError."""
    _patch_marker_files(monkeypatch, present=set())
    _patch_cgroup(monkeypatch, None)

    assert utils.is_docker() is False


# ---------------------------------------------------------------------------
# Companion behaviour — log-spam de-duplication in get_common_config()
# ---------------------------------------------------------------------------


class _RecordingLogger:
    """Minimal structlog-compatible stand-in that records ``warning`` calls."""

    def __init__(self) -> None:
        self.warnings: list[tuple[tuple, dict]] = []

    def warning(self, *args, **kwargs) -> None:
        self.warnings.append((args, kwargs))

    # The real logger receives plenty of other calls during config load. We
    # silently absorb them so the test focuses only on warning de-duplication.
    def __getattr__(self, _name):
        def _noop(*_args, **_kwargs):
            return None

        return _noop


def test_missing_config_warning_emitted_only_once(tmp_path, monkeypatch):
    """The hot-reload poller must not flood logs when the config is missing.

    Before the fix this logged ``[utils] No config file found...`` on every
    call, so a 2-second poll loop produced ~30k INFO lines per minute in
    OpenSearch. After the fix it logs once per (path, fallback-state) pair.
    """
    bogus = tmp_path / "does-not-exist.json"
    monkeypatch.setattr(utils, "CONFIG_PATH", str(bogus), raising=False)
    monkeypatch.setattr(utils, "DOCKER_CONFIG_PATH", str(bogus), raising=False)
    monkeypatch.setattr(utils, "is_docker", lambda: False)

    recorder = _RecordingLogger()
    monkeypatch.setattr(utils, "logger", recorder)
    utils.clear_config_cache()

    for _ in range(5):
        utils.get_common_config()

    missing = [
        args for args, _kw in recorder.warnings if "No config file found" in args[0]
    ]
    assert len(missing) == 1, (
        f"expected exactly 1 missing-config warning across 5 calls, got "
        f"{len(missing)}: {missing}"
    )


def test_missing_config_warning_re_emits_after_recovery_cycle(tmp_path, monkeypatch):
    """Latch must reset on a successful load so a later loss warns again."""
    import json as _json

    cfg = tmp_path / "enkrypt_mcp_config.json"
    monkeypatch.setattr(utils, "CONFIG_PATH", str(cfg), raising=False)
    monkeypatch.setattr(utils, "DOCKER_CONFIG_PATH", str(cfg), raising=False)
    monkeypatch.setattr(utils, "is_docker", lambda: False)

    recorder = _RecordingLogger()
    monkeypatch.setattr(utils, "logger", recorder)

    utils.clear_config_cache()
    utils.get_common_config()  # 1st miss -> warn
    utils.get_common_config()  # 2nd miss -> deduped

    cfg.write_text(_json.dumps({"common_mcp_gateway_config": {}}), encoding="utf-8")
    utils.get_common_config()  # success -> latch resets

    cfg.unlink()
    utils.clear_config_cache()
    utils.get_common_config()  # miss again -> warn again

    missing = [
        args for args, _kw in recorder.warnings if "No config file found" in args[0]
    ]
    assert len(missing) == 2, (
        f"expected 2 warnings across miss->load->miss cycle, got {len(missing)}"
    )
