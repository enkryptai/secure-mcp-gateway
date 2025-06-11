from pathlib import Path

for file in Path("src").rglob("*.py"):
    content = file.read_text(encoding="utf-8")
    cleaned = "\n".join(line.rstrip() for line in content.splitlines()) + "\n"
    file.write_text(cleaned, encoding="utf-8")

print("✅ All trailing whitespace removed.")
