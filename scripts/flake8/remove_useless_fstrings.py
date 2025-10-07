import re
import sys
from pathlib import Path

def has_fstring_without_placeholders(line):
    return re.search(r'^\s*(?:[^#\n]*?)f"[^{}]*?"', line) or re.search(r"^\s*(?:[^#\n]*?)f'[^{}]*?'", line)

def fix_line(line):
    return line.replace('f"', '"').replace("f'", "'")

# Handle command line arguments for pre-commit
if len(sys.argv) > 1:
    # Pre-commit passes filenames as arguments
    files_to_process = sys.argv[1:]
else:
    # Default behavior - process all Python files in src
    files_to_process = [str(f) for f in Path("src").rglob("*.py")]

count = 0
changed_files = 0
for file_path in files_to_process:
    file = Path(file_path)
    if file.exists() and file.suffix == ".py":
        new_lines = []
        file_changed = False
        for line in file.read_text(encoding="utf-8").splitlines(keepends=True):
            if has_fstring_without_placeholders(line):
                new_line = fix_line(line)
                new_lines.append(new_line)
                file_changed = True
                count += 1
            else:
                new_lines.append(line)
        if file_changed:
            file.write_text("".join(new_lines), encoding="utf-8")
            changed_files += 1

if count > 0:
    print(f"Cleaned {count} unnecessary f-strings from {changed_files} files")
