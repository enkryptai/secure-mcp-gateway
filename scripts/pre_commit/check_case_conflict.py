"""Check for files that would conflict on case-insensitive filesystems."""
import sys


def main():
    filenames = sys.argv[1:]
    seen = {}
    ret = 0
    for filename in filenames:
        lower = filename.lower()
        if lower in seen:
            print(
                f"Case conflict: {filename} conflicts with {seen[lower]}"
            )
            ret = 1
        else:
            seen[lower] = filename
    return ret


if __name__ == "__main__":
    sys.exit(main())
