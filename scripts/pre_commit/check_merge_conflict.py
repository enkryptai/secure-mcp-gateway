"""Check files for merge conflict markers."""
import re
import sys

CONFLICT_PATTERNS = [
    re.compile(rb"^<{7}\s"),
    re.compile(rb"^={7}$"),
    re.compile(rb"^>{7}\s"),
    re.compile(rb"^\|{7}\s"),
]


def check_merge_conflict(filename):
    try:
        with open(filename, "rb") as f:
            for i, line in enumerate(f, 1):
                for pattern in CONFLICT_PATTERNS:
                    if pattern.match(line):
                        print(f"{filename}:{i}: merge conflict marker found")
                        return 1
    except OSError:
        return 0
    return 0


def main():
    ret = 0
    for filename in sys.argv[1:]:
        ret |= check_merge_conflict(filename)
    return ret


if __name__ == "__main__":
    sys.exit(main())
