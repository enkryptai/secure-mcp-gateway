"""Check for files exceeding a maximum size."""
import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--maxkb", type=int, default=500)
    parser.add_argument("filenames", nargs="*")
    args = parser.parse_args()

    max_bytes = args.maxkb * 1024
    ret = 0
    for filename in args.filenames:
        try:
            size = os.path.getsize(filename)
            if size > max_bytes:
                print(
                    f"{filename} ({size // 1024}KB) exceeds "
                    f"{args.maxkb}KB limit"
                )
                ret = 1
        except OSError:
            pass
    return ret


if __name__ == "__main__":
    sys.exit(main())
