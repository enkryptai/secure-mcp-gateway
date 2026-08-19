"""Unit tests for render_pipelines.render().

Run from the repo root:
    python -m pytest observability/data_prepper/test_render_pipelines.py -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from render_pipelines import main, render

# ---------- Substitution semantics ----------------------------------------


def test_basic_substitution() -> None:
    out = render("hosts: ${HOSTS}", {"HOSTS": "https://opensearch:9200"}, ["HOSTS"])
    assert out == "hosts: https://opensearch:9200"


def test_multiple_placeholders() -> None:
    template = "user: ${U}\npass: ${P}\nhost: ${H}"
    env = {"U": "alice", "P": "s3cret", "H": "example.com"}
    assert (
        render(template, env, ["U", "P", "H"])
        == "user: alice\npass: s3cret\nhost: example.com"
    )


def test_same_placeholder_repeated() -> None:
    out = render("${H}, ${H}, ${H}", {"H": "x"}, ["H"])
    assert out == "x, x, x"


def test_no_placeholders_passthrough() -> None:
    template = "key: value\nlist:\n  - a\n  - b\n"
    assert render(template, {}, []) == template


def test_empty_template() -> None:
    assert render("", {}, []) == ""


# ---------- Allowlist semantics ------------------------------------------


def test_placeholder_not_in_allowlist_is_left_alone() -> None:
    """Documentation in comments uses ${VAR} notation literally."""
    template = "# Example: ${SOME_DOC}\nreal: ${KEEP}"
    out = render(template, {"KEEP": "ok", "SOME_DOC": "ignored"}, ["KEEP"])
    assert out == "# Example: ${SOME_DOC}\nreal: ok"


def test_doc_in_comment_no_env_no_error() -> None:
    """${X} in a comment with no allowlist entry and no env var must NOT error."""
    template = "# uses ${VAR:-default} syntax (not supported)\nfoo: ${BAR}"
    out = render(template, {"BAR": "val"}, ["BAR"])
    assert out == "# uses ${VAR:-default} syntax (not supported)\nfoo: val"


# ---------- The regression that motivated this script --------------------


def test_pipe_in_value_survives() -> None:
    """Used to be broken with `sed -e 's|${VAR}|<value>|g'` if value had |."""
    pw = "p|p|p"
    out = render("password: ${P}", {"P": pw}, ["P"])
    assert out == f"password: {pw}"


def test_ampersand_in_value_survives() -> None:
    """`sed` treats & as the matched-text reference; also a footgun."""
    out = render("password: ${P}", {"P": "a&b&c"}, ["P"])
    assert out == "password: a&b&c"


def test_backslash_in_value_survives() -> None:
    """`sed` treats \\1, \\2 etc. as backreferences."""
    out = render("password: ${P}", {"P": "a\\b\\c"}, ["P"])
    assert out == "password: a\\b\\c"


def test_dollar_in_value_does_not_recurse() -> None:
    """A value that itself contains ${OTHER} must NOT trigger another pass."""
    out = render("a: ${A}\nb: ${B}", {"A": "${B}", "B": "real-b"}, ["A", "B"])
    assert out == "a: ${B}\nb: real-b"


def test_newline_in_value() -> None:
    """Multi-line secrets (e.g. PEM-style) should survive unchanged."""
    multiline = "-----BEGIN-----\nfoo\nbar\n-----END-----"
    out = render("cert: |\n  ${CERT}", {"CERT": multiline}, ["CERT"])
    assert out == f"cert: |\n  {multiline}"


def test_quotes_in_value() -> None:
    out = render("p: ${P}", {"P": "a\"b'c"}, ["P"])
    assert out == "p: a\"b'c"


def test_unicode_in_value() -> None:
    out = render("p: ${P}", {"P": "пароль🔒"}, ["P"])
    assert out == "p: пароль🔒"


def test_all_special_chars_simultaneously() -> None:
    """Belt-and-braces: all the sed-killers in one password."""
    nasty = "p|w&d\\\\$x\"y'z@#%!"
    out = render('password: "${P}"', {"P": nasty}, ["P"])
    assert out == f'password: "{nasty}"'


# ---------- Error handling ------------------------------------------------


def test_missing_env_var_raises_keyerror() -> None:
    with pytest.raises(KeyError) as excinfo:
        render("a: ${MISSING}", {}, ["MISSING"])
    assert "MISSING" in excinfo.value.args[0]


def test_missing_env_var_reports_all_unique() -> None:
    """Catches every missing var in one pass, deduplicated, sorted."""
    with pytest.raises(KeyError) as excinfo:
        render("${A} ${B} ${A} ${C}", {"B": "ok"}, ["A", "B", "C"])
    msg = excinfo.value.args[0]
    assert "A" in msg and "C" in msg
    # sorted unique form
    assert "['A', 'C']" in msg


def test_unknown_syntax_left_alone() -> None:
    """We deliberately don't support ${VAR:-default}; it should NOT match."""
    out = render("${VAR:-fallback}", {}, [])
    assert out == "${VAR:-fallback}"


def test_lone_dollar_left_alone() -> None:
    assert render("price: $5.00", {}, []) == "price: $5.00"


def test_dollar_brace_no_name() -> None:
    """`${}` is not a valid env-var name; left untouched."""
    assert render("${}", {}, []) == "${}"


def test_leading_digit_invalid() -> None:
    """POSIX env-var names can't start with a digit; left untouched."""
    assert render("${1FOO}", {}, []) == "${1FOO}"


# ---------- CLI entry point ----------------------------------------------


def test_cli_renders_to_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = tmp_path / "in.yaml"
    output = tmp_path / "out.yaml"
    template.write_text("host: ${OPENSEARCH_HOSTS}\n")
    monkeypatch.setenv("OPENSEARCH_HOSTS", "https://os:9200")

    rc = main(["render_pipelines.py", str(template), str(output), "OPENSEARCH_HOSTS"])

    assert rc == 0
    assert output.read_text() == "host: https://os:9200\n"


def test_cli_missing_env_var_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    template = tmp_path / "in.yaml"
    output = tmp_path / "out.yaml"
    template.write_text("host: ${OS_MISSING_VAR_XYZ}\n")

    rc = main(["render_pipelines.py", str(template), str(output), "OS_MISSING_VAR_XYZ"])

    assert rc == 1
    assert not output.exists()
    err = capsys.readouterr().err
    assert "OS_MISSING_VAR_XYZ" in err


def test_cli_typo_in_allowlist_caught(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Allowlisting a var that isn't anywhere in the template -> error.

    Catches `python render_pipelines.py tmpl out OPENSEARH_HOSTS` typos
    that would otherwise silently no-op.
    """
    template = tmp_path / "in.yaml"
    output = tmp_path / "out.yaml"
    template.write_text("host: ${OPENSEARCH_HOSTS}\n")
    monkeypatch.setenv("OPENSEARH_HOSTS", "https://os:9200")

    rc = main(["render_pipelines.py", str(template), str(output), "OPENSEARH_HOSTS"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "OPENSEARH_HOSTS" in err
    assert "does not appear" in err


def test_cli_wrong_arg_count_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["render_pipelines.py"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "usage:" in err


def test_cli_missing_template_returns_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        ["render_pipelines.py", str(tmp_path / "nope"), str(tmp_path / "out"), "X"]
    )
    assert rc == 1


# ---------- Smoke test against the real pipeline template ----------------


def test_real_template_renders_with_supplied_env() -> None:
    """The actual production template must render cleanly given the 3 env
    vars the operator is documented to provide."""
    repo_root = Path(__file__).resolve().parents[2]
    template = repo_root / "observability/data_prepper/pipelines.yaml"
    assert template.exists(), template

    env = {
        "OPENSEARCH_HOSTS": "https://opensearch:9200",
        "OPENSEARCH_USERNAME": "mcp_gateway_telemetry_plugin",
        "OPENSEARCH_PASSWORD": "tricky|password&with$special",
    }
    out = render(
        template.read_text(),
        env,
        ["OPENSEARCH_HOSTS", "OPENSEARCH_USERNAME", "OPENSEARCH_PASSWORD"],
    )

    # Every allowlisted placeholder must have been replaced everywhere
    # outside comments. (The template has documentation lines like
    # "# Env vars are substituted by Data Prepper's plain ${VAR} syntax"
    # whose ${VAR} survives, which is fine -- VAR is not in the allowlist.)
    for k, v in env.items():
        assert "${" + k + "}" not in out
        assert v in out

    # And the pipe-in-password actually landed verbatim
    assert "tricky|password&with$special" in out

    # The comments documenting ${VAR}, ${VAR:-default} survive untouched
    assert "${VAR}" in out
    assert "${VAR:-default}" in out


# ---------- Drift guard against the k8s configmap embed -------------------


def _extract_embedded_script() -> str | None:
    """Read the configmap.yaml in the apiaas repo and pull out the
    embedded render_pipelines.py source.

    Returns None if the apiaas repo isn't checked out side-by-side; that's
    expected in CI runs that only have one repo.
    """
    apiaas_configmap = (
        Path(__file__).resolve().parents[3]
        / "enkryptai-apiaas/code/infra/kubernetes/platform/data-prepper/configmap.yaml"
    )
    if not apiaas_configmap.is_file():
        return None
    try:
        import yaml  # pyyaml is in the gateway's test deps
    except ImportError:
        return None
    doc = yaml.safe_load(apiaas_configmap.read_text())
    return doc.get("data", {}).get("render_pipelines.py")


def test_k8s_configmap_embed_matches_canonical_behaviour(tmp_path: Path) -> None:
    """The embedded k8s configmap copy must behave identically to the
    canonical script. Catches accidental drift between the two
    (sync-check.sh doesn't cover the configmap because it's k8s-specific)."""
    embedded = _extract_embedded_script()
    if embedded is None:
        pytest.skip("apiaas repo not co-located; can't compare configmap embed")

    # Drop the embedded script to disk and run a smoke render with it
    embedded_script = tmp_path / "render_embedded.py"
    embedded_script.write_text(embedded)

    template = tmp_path / "in.yaml"
    output_embedded = tmp_path / "out_embedded.yaml"
    output_canonical = tmp_path / "out_canonical.yaml"

    # Exercise every special char that motivated this rewrite, plus a
    # placeholder that should be left alone (allowlist semantics).
    template.write_text(
        "host: ${OPENSEARCH_HOSTS}\n"
        "user: ${OPENSEARCH_USERNAME}\n"
        "pass: ${OPENSEARCH_PASSWORD}\n"
        "# doc: ${SOME_DOC} -- not in allowlist\n"
    )
    env_overrides = {
        "OPENSEARCH_HOSTS": "https://os:9200",
        "OPENSEARCH_USERNAME": "mcp_gateway_telemetry_plugin",
        "OPENSEARCH_PASSWORD": "p|w&d\\$\"q'`!@#",
    }

    import subprocess

    canonical_script = Path(__file__).parent / "render_pipelines.py"

    def _run(script: Path, output: Path) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                str(template),
                str(output),
                "OPENSEARCH_HOSTS",
                "OPENSEARCH_USERNAME",
                "OPENSEARCH_PASSWORD",
            ],
            env={**os.environ, **env_overrides},
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"failed: {result.stderr}"

    _run(canonical_script, output_canonical)
    _run(embedded_script, output_embedded)

    assert output_canonical.read_text() == output_embedded.read_text(), (
        "k8s configmap embed of render_pipelines.py has drifted from canonical"
    )
