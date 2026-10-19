# json converts Python dictionaries into JSON.
import json

# Path provides a platform-independent way to handle file paths.
from pathlib import Path

# datetime creates unique timestamps for report filenames.
from datetime import datetime, timezone


def save_report(report: dict) -> Path:

    # Locate the project's root directory.
    # __file__ refers to core/reporter.py.
    project_root = Path(__file__).resolve().parent.parent

    # Define where security reports should be stored.
    reports_dir = project_root / "reports"

    # Create the folder if it doesn't already exist.
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Generate a timestamp to distinguish different scans.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

    # Construct the complete output filename.
    report_path = reports_dir / f"pathfinder_{timestamp}.json"

    # Write the report as formatted JSON.
    # UTF-8 ensures special characters are preserved.
    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    # Return the file path so main.py can display it.
    return report_path