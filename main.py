
import platform
import json
from datetime import datetime, timezone


def get_system_info():
    """Collect basic information about the operating system."""
    return {
        "operating_system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
    }


def main():
    print("=== Pathfinder Security Auditor v0.1 ===")

    report = {
        "scanner": "Pathfinder Internal Auditor",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": get_system_info(),
        "findings": [],
    }

    print(json.dumps(report, indent=4))


if __name__ == "__main__":
    main()
