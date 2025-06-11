import re
from pathlib import Path

def has_fstring_without_placeholders(line):
    return re.search(r'^\s*(?:[^#\n]*?)f"[^{}]*?"', line) or re.search(r"^\s*(?:[^#\n]*?)f'[^{}]*?'", line)

def fix_line(line):
    return line.replace('"', '"').replace("'", "'")

count = 0
for file in Path("E:\github\integrauth\enkrypt-mcp-gateway\src\secure_mcp_gateway").rglob("*.py"):
    new_lines = []
    changed = False
    for line in file.read_text(encoding="utf-8").splitlines(keepends=True):
        if has_fstring_without_placeholders(line):
            new_line = fix_line(line)
            new_lines.append(new_line)
            changed = True
            count += 1
        else:
            new_lines.append(line)
    if changed:
        file.write_text("".join(new_lines), encoding="utf-8")

print(f"✅ Cleaned {count} unnecessary f-strings.")
