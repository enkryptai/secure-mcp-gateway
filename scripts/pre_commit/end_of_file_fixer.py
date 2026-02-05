"""Ensure files end with exactly one newline."""
import sys


def fix_file(filename):
    try:
        with open(filename, "rb") as f:
            contents = f.read()
    except OSError:
        return 0

    if not contents:
        return 0

    # Check if file ends with exactly one newline
    if contents.endswith(b"\n") and not contents.endswith(b"\n\n"):
        return 0

    # Fix: strip trailing newlines/whitespace and add exactly one
    fixed = contents.rstrip(b"\n\r") + b"\n"
    if fixed != contents:
        with open(filename, "wb") as f:
            f.write(fixed)
        print(f"Fixing {filename}")
        return 1
    return 0


def main():
    ret = 0
    for filename in sys.argv[1:]:
        ret |= fix_file(filename)
    return ret


if __name__ == "__main__":
    sys.exit(main())
