# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: NET-005 - Installed Software Inventory
#
# Purpose:
# Identify installed Windows applications and their versions.
#
# Method:
# Read uninstall registry entries from HKLM and HKCU.
#
# Limitations:
# - Portable software may not be registered.
# - Microsoft Store apps may not appear.
# - Version information may be missing or inaccurate.
# - Does not identify vulnerabilities.
#
# READ-ONLY
# ============================================================

import json
import winreg

from core.findings import Finding


REGISTRY_LOCATIONS = [
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM-64"
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM-32"
    ),
    (
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU"
    ),
]


def read_registry_value(key, name):
    """
    Read a registry value.

    Missing or inaccessible values return None.
    """
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return str(value).strip() if value is not None else None
    except OSError:
        return None


def collect_installed_software():
    """
    Collect installed applications from Windows uninstall keys.

    Returns a list of dictionaries containing application metadata.
    """

    software = []
    seen = set()

    for root, registry_path, source in REGISTRY_LOCATIONS:

        try:
            registry_key = winreg.OpenKey(
                root,
                registry_path,
                0,
                winreg.KEY_READ
            )
        except OSError:
            continue

        with registry_key:

            index = 0

            while True:

                try:
                    subkey_name = winreg.EnumKey(registry_key, index)
                    index += 1
                except OSError:
                    break

                try:
                    subkey = winreg.OpenKey(
                        registry_key,
                        subkey_name,
                        0,
                        winreg.KEY_READ
                    )
                except OSError:
                    continue

                with subkey:

                    name = read_registry_value(
                        subkey,
                        "DisplayName"
                    )

                    version = read_registry_value(
                        subkey,
                        "DisplayVersion"
                    )

                    publisher = read_registry_value(
                        subkey,
                        "Publisher"
                    )

                    if not name:
                        continue

                    identity = (
                        name.lower(),
                        (version or "").lower(),
                        (publisher or "").lower()
                    )

                    if identity in seen:
                        continue

                    seen.add(identity)

                    software.append({
                        "name": name,
                        "version": version,
                        "publisher": publisher,
                        "source": source
                    })

    software.sort(
        key=lambda item: item["name"].lower()
    )

    return software


def check_software_inventory() -> Finding:
    """
    Create a Finding containing the installed software inventory.

    Missing version information is reported separately.
    It is not automatically considered a vulnerability.
    """

    software = collect_installed_software()

    missing_versions = sum(
        1 for item in software
        if not item["version"]
    )

    evidence = {
        "method": "Windows uninstall registry",
        "software_count": len(software),
        "missing_version_count": missing_versions,
        "software": software,
        "limitations": [
            "Portable applications may be absent.",
            "Microsoft Store applications may be absent.",
            "Registry version strings are not independently verified.",
            "An installed software version does not establish a vulnerability."
        ]
    }

    return Finding(
        check_id="NET-005",
        title="Installed software inventory",
        status="PASS",
        severity="INFO",
        description=(
            f"Identified {len(software)} installed applications. "
            f"{missing_versions} entries have no version information."
        ),
        evidence=json.dumps(
            evidence,
            ensure_ascii=False
        ),
        recommendation=(
            "Review installed applications, remove unnecessary "
            "software and verify that supported versions receive "
            "security updates."
        )
    )