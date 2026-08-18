#!/usr/bin/env python3
"""Render Data Prepper's pipelines.yaml template with env-var substitution.

Data Prepper 2.11's parser does not natively interpolate ${VAR} placeholders
in pipelines.yaml. We pre-render the template at container start.

Previously this was done with `sed`, which fails when a value contains the
sed delimiter character (typically `|`). This script does literal,
index-based substitution via re.sub with a callback -- arbitrary characters
in env-var values (including `|`, `&`, `$`, newlines, quotes) survive
verbatim.

Usage:
    render_pipelines.py <template-path> <output-path> VAR1 VAR2 ...

Only the named vars are substituted (allowlist). Any `${X}`-shaped tokens
inside YAML comments that aren't in the allowlist are left untouched -- the
template's own comments document the `${VAR}` syntax and we don't want to
false-match those. Exits non-zero if any allowlisted var is missing from
the environment OR not referenced in the template (likely a typo).
"""

from __future__ import annotations

import os
import re
import sys

# ${VAR} where VAR matches POSIX env-var-name rules: leading [A-Za-z_],
# then [A-Za-z0-9_]. We intentionally do NOT support ${VAR:-default} or
# ${VAR+alt}; Data Prepper's own syntax is plain ${VAR} too, so anything
# more elaborate would be a footgun.
_PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def render(template: str, env: dict[str, str], allowlist: list[str]) -> str:
    """Substitute ${VAR} -> env[VAR] for VAR in allowlist.

    - Placeholders matching the regex but NOT in the allowlist are left
      verbatim (they're treated as documentation, not substitution
      targets).
    - Raises KeyError if any allowlist var is missing from env.
    """
    missing = [name for name in allowlist if name not in env]
    if missing:
        raise KeyError(
            f"missing required env vars for pipelines.yaml rendering: "
            f"{sorted(set(missing))}"
        )

    allowed = set(allowlist)

    def _sub(match: re.Match[str]) -> str:
        var = match.group(1)
        if var not in allowed:
            return match.group(0)  # documentation -- leave it
        return env[var]

    return _PLACEHOLDER_RE.sub(_sub, template)


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(
            f"usage: {argv[0]} <template-path> <output-path> VAR1 [VAR2 ...]",
            file=sys.stderr,
        )
        return 2

    template_path, output_path = argv[1], argv[2]
    allowlist = argv[3:]

    try:
        with open(template_path, encoding="utf-8") as f:
            template = f.read()
    except OSError as exc:
        print(f"ERROR: reading template {template_path}: {exc}", file=sys.stderr)
        return 1

    # Sanity check: every allowlisted var must actually appear in the
    # template. Catches typos in the operator's invocation that would
    # otherwise silently no-op.
    for var in allowlist:
        if "${" + var + "}" not in template:
            print(
                f"ERROR: env var '{var}' is in the allowlist but does not "
                f"appear in {template_path}",
                file=sys.stderr,
            )
            return 1

    try:
        rendered = render(template, os.environ, allowlist)
    except KeyError as exc:
        print(f"ERROR: {exc.args[0]}", file=sys.stderr)
        return 1

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)
    except OSError as exc:
        print(f"ERROR: writing output {output_path}: {exc}", file=sys.stderr)
        return 1

    lines = rendered.count("\n") + (0 if rendered.endswith("\n") else 1)
    print(f"rendered {output_path} ({lines} lines)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
