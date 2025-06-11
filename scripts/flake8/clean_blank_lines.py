import sys
from pathlib import Path

if len(sys.argv) < 2:
    print("Error: No file name provided")
    print("Usage: python clean_blank_lines.py <filename>")
    print("Provide a file name which is inside src directory")
    sys.exit(1)

file_name = sys.argv[1]
if not file_name:
    print("No file name provided. Provide a file name which is inside src directory")
    sys.exit(1)

# Get the script's directory and resolve the src path
script_dir = Path(__file__).parent
src_dir = script_dir.parent.parent / "src" / "secure_mcp_gateway"
file_path = src_dir / file_name

if not file_path.exists():
    print(f"File does not exist at: {file_path}")
    sys.exit(1)

print("Cleaning blank lines from: ", file_path)

lines = file_path.read_text(encoding="utf-8").splitlines()

# Keep lines, replacing empty-with-whitespace with just newline
cleaned = [(line if line.strip() else "") for line in lines]

file_path.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
print("Cleaned:", file_path)
