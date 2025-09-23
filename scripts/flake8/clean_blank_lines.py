import sys
import shutil
from pathlib import Path
from datetime import datetime

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
        lines = file.read_text(encoding="utf-8").splitlines()

        # Keep lines, replacing empty-with-whitespace with just newline
        cleaned = [(line if line.strip() else "") for line in lines]

        # Only write if there are changes
        if cleaned != lines:
            # Create backups directory if it doesn't exist
            script_dir = Path(__file__).parent
            backups_dir = script_dir / "backups"
            backups_dir.mkdir(exist_ok=True)

            # Create backup with timestamp
            backup_filename = f"{file.stem}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}{file.suffix}"
            backup_path = backups_dir / backup_filename
            shutil.copy2(file, backup_path)

            file.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
            changed_files += 1

if changed_files > 0:
    print(f"Cleaned blank lines from {changed_files} files")
