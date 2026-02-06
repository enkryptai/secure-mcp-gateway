"""Check YAML files for valid syntax."""
import sys

try:
    import yaml
except ImportError:
    print("PyYAML not installed, skipping YAML check")
    sys.exit(0)


def check_yaml(filename):
    try:
        with open(filename, encoding="utf-8") as f:
            yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"{filename}: {e}")
        return 1
    except Exception as e:
        print(f"{filename}: {e}")
        return 1
    return 0


def main():
    ret = 0
    for filename in sys.argv[1:]:
        ret |= check_yaml(filename)
    return ret


if __name__ == "__main__":
    sys.exit(main())
