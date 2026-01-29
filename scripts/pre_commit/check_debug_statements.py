"""Check Python files for debugger imports and breakpoints."""
import re
import sys

DEBUG_PATTERNS = [
    re.compile(r"^\s*import\s+pdb"),
    re.compile(r"^\s*import\s+ipdb"),
    re.compile(r"^\s*import\s+pudb"),
    re.compile(r"^\s*from\s+pdb\s+import"),
    re.compile(r"^\s*from\s+ipdb\s+import"),
    re.compile(r"^\s*from\s+pudb\s+import"),
    re.compile(r"^\s*import\s+debugpy"),
    re.compile(r"^\s*from\s+debugpy\s+import"),
    re.compile(r"\bpdb\.set_trace\(\)"),
    re.compile(r"\bipdb\.set_trace\(\)"),
    re.compile(r"\bpudb\.set_trace\(\)"),
    re.compile(r"\bbreakpoint\(\)"),
    re.compile(r"\bdebugpy\.listen\("),
    re.compile(r"\bdebugpy\.wait_for_client\("),
]


def check_debug(filename):
    try:
        with open(filename, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return 0

    ret = 0
    for i, line in enumerate(lines, 1):
        for pattern in DEBUG_PATTERNS:
            if pattern.search(line):
                print(f"{filename}:{i}: debug statement found: {line.rstrip()}")
                ret = 1
                break
    return ret


def main():
    ret = 0
    for filename in sys.argv[1:]:
        ret |= check_debug(filename)
    return ret


if __name__ == "__main__":
    sys.exit(main())
