import sys
from pathlib import Path

# Handle command line arguments for pre-commit
if len(sys.argv) > 1:
    # Pre-commit passes filenames as arguments
    files_to_process = sys.argv[1:]
else:
    # Default behavior - process all Python files in src
    files_to_process = [str(f) for f in Path("src").rglob("*.py")]

changed_files = 0
for file_path in files_to_process:
    file = Path(file_path)
    if file.exists() and file.suffix == ".py":
        content = file.read_text(encoding="utf-8")
        cleaned = "\n".join(line.rstrip() for line in content.splitlines()) + "\n"

        # Only write if there are changes
        if cleaned != content:
            file.write_text(cleaned, encoding="utf-8")
            changed_files += 1

if changed_files > 0:
    print(f"Removed trailing whitespace from {changed_files} files")
