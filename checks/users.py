# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: USR-001 - Local Administrator Accounts
#
# Purpose:
# Identify accounts with local administrator privileges.
#
# READ-ONLY: Does not modify users or group membership.
# ============================================================

import json
import subprocess

from core.findings import Finding


def check_users() -> Finding:

    # The Administrators group has the well-known SID
    # S-1-5-32-544, regardless of Windows display language.
    #
    # We retrieve its members and convert the result to JSON.
    command = """
    $group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop

    @(
        Get-LocalGroupMember -Group $group.Name -ErrorAction Stop |
        Select-Object Name, SID, ObjectClass, PrincipalSource
    ) | ConvertTo-Json -Compress -Depth 3
    """

    try:
        # Query Windows using PowerShell.
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        # Reject unsuccessful collection.
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
                or "Administrator enumeration failed."
            )

        # Parse PowerShell's JSON output.
        members = json.loads(result.stdout)

        # Normalize a single member into a list.
        if isinstance(members, dict):
            members = [members]

        # Reject unexpected output.
        if not isinstance(members, list):
            raise ValueError("Invalid administrator group data.")

        # Validate each member.
        for member in members:
            if not isinstance(member, dict):
                raise ValueError("Invalid administrator entry.")

            if not isinstance(member.get("Name"), str):
                raise ValueError("Invalid administrator name.")

            if not member["Name"].strip():
                raise ValueError("Empty administrator name.")

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        return Finding(
            check_id="USR-001",
            title="Local administrator accounts",
            status="ERROR",
            severity="INFO",
            description=(
                "Unable to enumerate local administrator accounts."
            ),
            evidence=str(error),
            recommendation=(
                "Verify PowerShell permissions and local group access."
            )
        )

    # An administrator account is not automatically insecure.
    #
    # Without an approved account baseline, Pathfinder cannot
    # determine whether each account is authorized.
    #
    # Therefore, report WARN rather than FAIL.
    status = "WARN"
    severity = "LOW"

    description = (
        f"Found {len(members)} members of the local "
        "Administrators group. Membership should be "
        "reviewed against an approved account baseline."
    )

    # Return structured evidence for future correlation.
    return Finding(
        check_id="USR-001",
        title="Local administrator accounts",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps({
            "administrator_count": len(members),
            "members": members
        }, default=str),
        recommendation=(
            "Review administrator membership and remove "
            "unnecessary privileges according to the "
            "principle of least privilege."
        )
    )