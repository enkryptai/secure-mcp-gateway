"""Check JSON files for valid syntax."""
import json
import sys


def check_json(filename):
    try:
        with open(filename, encoding="utf-8") as f:
            json.load(f)
    except json.JSONDecodeError as e:
        print(f"{filename}: {e}")
        return 1
    except Exception as e:
        print(f"{filename}: {e}")
        return 1
    return 0


def main():
    ret = 0
    for filename in sys.argv[1:]:
        ret |= check_json(filename)
    return ret


if __name__ == "__main__":
    sys.exit(main())
