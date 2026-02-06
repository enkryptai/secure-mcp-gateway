"""Check that test files are named correctly (test_*.py or *_test.py)."""
import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pytest-test-first",
        action="store_true",
        help="Require test files to start with test_",
    )
    parser.add_argument("filenames", nargs="*")
    args = parser.parse_args()

    ret = 0
    for filename in args.filenames:
        base = os.path.basename(filename)
        if base == "__init__.py" or base == "conftest.py":
            continue
        if args.pytest_test_first:
            if not base.startswith("test_"):
                print(f"{filename}: test file should start with 'test_'")
                ret = 1
        else:
            if not (base.startswith("test_") or base.endswith("_test.py")):
                print(
                    f"{filename}: test file should match "
                    f"'test_*.py' or '*_test.py'"
                )
                ret = 1
    return ret


if __name__ == "__main__":
    sys.exit(main())
