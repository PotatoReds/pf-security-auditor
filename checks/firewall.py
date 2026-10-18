# subprocess allows Python to execute PowerShell commands.
import subprocess

# json converts PowerShell output into Python data structures.
import json

# Import our standardized security finding class.
from core.findings import Finding


# Check whether all three Windows Firewall profiles are enabled.
# Returns a Finding object containing the audit result.
def check_firewall() -> Finding:

    # Query Windows Firewall using PowerShell.
    # ConvertTo-Json produces structured output for Python.
    command = (
        "Get-NetFirewallProfile -ErrorAction Stop | "
        "Select-Object Name, Enabled | "
        "ConvertTo-Json -Compress"
    )

    try:
        # Execute PowerShell without modifying system settings.
        # A timeout prevents the command from hanging indefinitely.
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

    # Handle situations where PowerShell cannot be started
    # or the command takes too long to execute.
    except (OSError, subprocess.TimeoutExpired) as error:
        return Finding(
            check_id="FW-001",
            title="Windows Firewall profiles",
            status="ERROR",
            severity="INFO",
            description="Could not execute the Windows Firewall check.",
            evidence=str(error),
            recommendation="Verify PowerShell availability and permissions."
        )

    # A nonzero return code indicates that PowerShell failed.
    # We must not interpret a failed command as a secure system.
    if result.returncode != 0:
        return Finding(
            check_id="FW-001",
            title="Windows Firewall profiles",
            status="ERROR",
            severity="INFO",
            description="Could not retrieve Windows Firewall configuration.",
            evidence=result.stderr.strip(),
            recommendation="Verify PowerShell access and firewall permissions."
        )

    try:
        # Convert PowerShell's JSON output into Python objects.
        profiles = json.loads(result.stdout)

    # Invalid or empty JSON means we cannot trust the result.
    except json.JSONDecodeError as error:
        return Finding(
            check_id="FW-001",
            title="Windows Firewall profiles",
            status="ERROR",
            severity="INFO",
            description="PowerShell returned invalid JSON.",
            evidence=str(error),
            recommendation="Investigate the PowerShell command output."
        )

    # PowerShell may return a single dictionary instead of a list.
    # Normalize the result so the remaining code always uses a list.
    if isinstance(profiles, dict):
        profiles = [profiles]

    # Validate that the result is a list containing profile objects.
    # This prevents unexpected data from being reported as PASS.
    if not isinstance(profiles, list) or not all(
        isinstance(profile, dict)
        and isinstance(profile.get("Name"), str)
        and "Enabled" in profile
        for profile in profiles
    ):
        return Finding(
            check_id="FW-001",
            title="Windows Firewall profiles",
            status="ERROR",
            severity="INFO",
            description="PowerShell returned an unexpected data structure.",
            evidence=json.dumps(profiles),
            recommendation="Verify the firewall query output."
        )

    # Windows Firewall has three standard profiles.
    expected_profiles = {"Domain", "Private", "Public"}

    # Extract the profile names returned by PowerShell.
    actual_profiles = {
        profile["Name"]
        for profile in profiles
    }

    # Check whether any required profiles are missing.
    missing_profiles = expected_profiles - actual_profiles

    # Also reject unexpected or duplicate profile entries.
    # Both could indicate that the collected data is unreliable.
    unexpected_profiles = actual_profiles - expected_profiles
    duplicate_profiles = len(profiles) != len(actual_profiles)

    if missing_profiles or unexpected_profiles or duplicate_profiles:
        return Finding(
            check_id="FW-001",
            title="Windows Firewall profiles",
            status="ERROR",
            severity="INFO",
            description="The firewall audit returned incomplete or unexpected results.",
            evidence=json.dumps(profiles),
            recommendation="Verify that all three Windows Firewall profiles are returned exactly once."
        )

    # Validate the Enabled values before evaluating them.
    # PowerShell may serialize these as booleans or integers.
    # Only True, False, 1 and 0 are accepted.
    if any(
        type(profile["Enabled"]) not in (bool, int)
        or profile["Enabled"] not in (True, False, 1, 0)
        for profile in profiles
    ):
        return Finding(
            check_id="FW-001",
            title="Windows Firewall profiles",
            status="ERROR",
            severity="INFO",
            description="One or more firewall profiles have an invalid status value.",
            evidence=json.dumps(profiles),
            recommendation="Investigate the firewall status returned by PowerShell."
        )

    # Collect the names of profiles where the firewall is disabled.
    disabled = [
        profile["Name"]
        for profile in profiles
        if profile["Enabled"] not in (True, 1)
    ]

    # If at least one profile is disabled, report a security finding.
    if disabled:
        return Finding(
            check_id="FW-001",
            title="Windows Firewall profiles",
            status="FAIL",
            severity="MEDIUM",
            description="One or more Windows Firewall profiles are disabled.",
            evidence=json.dumps(profiles),
            recommendation="Review and enable the affected firewall profiles."
        )

    # All three profiles were found and confirmed enabled.
    return Finding(
        check_id="FW-001",
        title="Windows Firewall profiles",
        status="PASS",
        severity="INFO",
        description="All three Windows Firewall profiles are enabled.",
        evidence=json.dumps(profiles),
        recommendation="Review firewall rules periodically."
    )