"""Check Python files for valid AST (syntax)."""
import ast
import sys


def check_ast(filename):
    try:
        with open(filename, "rb") as f:
            source = f.read()
        ast.parse(source, filename=filename)
    except SyntaxError as e:
        print(f"{filename}:{e.lineno}: {e.msg}")
        return 1
    except Exception as e:
        print(f"{filename}: {e}")
        return 1
    return 0


def main():
    ret = 0
    for filename in sys.argv[1:]:
        ret |= check_ast(filename)
    return ret


if __name__ == "__main__":
    sys.exit(main())
