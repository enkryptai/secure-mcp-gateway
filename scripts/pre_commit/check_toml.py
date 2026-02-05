"""Check TOML files for valid syntax."""
import sys

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print("No TOML parser available, skipping TOML check")
        sys.exit(0)


def check_toml(filename):
    try:
        with open(filename, "rb") as f:
            tomllib.load(f)
    except Exception as e:
        print(f"{filename}: {e}")
        return 1
    return 0


def main():
    ret = 0
    for filename in sys.argv[1:]:
        ret |= check_toml(filename)
    return ret


if __name__ == "__main__":
    sys.exit(main())
