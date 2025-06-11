from pathlib import Path

file = Path("utils.py")
lines = file.read_text(encoding="utf-8").splitlines()

# Keep lines, replacing empty-with-whitespace with just newline
cleaned = [(line if line.strip() else "") for line in lines]

file.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
print("Cleaned:", file)
