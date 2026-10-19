# subprocess lets Python execute Windows PowerShell commands.
import subprocess

# json converts PowerShell's JSON output into Python data.
import json

# Finding represents the result of a security check.
from core.findings import Finding


def check_rdp() -> Finding:

    # Read RDP configuration from the Windows registry.
    # These commands only retrieve information.
    command = """
    $rdp = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction Stop
    $nla = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction Stop

    [PSCustomObject]@{
        RDPEnabled = ($rdp.fDenyTSConnections -eq 0)
        NLARequired = ($nla.UserAuthentication -eq 1)
    } | ConvertTo-Json -Compress
    """

    try:
        # Execute PowerShell without loading the user's profile.
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

        # A failed PowerShell command means we lack reliable evidence.
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())

        # Parse the returned JSON.
        configuration = json.loads(result.stdout)

        # Reject unexpected output rather than guessing.
        if (
            not isinstance(configuration, dict)
            or type(configuration.get("RDPEnabled")) is not bool
            or type(configuration.get("NLARequired")) is not bool
        ):
            raise ValueError("Invalid RDP configuration data.")

    # Handle command failures, timeouts and invalid data.
    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:
        return Finding(
            check_id="RDP-001",
            title="Remote Desktop security configuration",
            status="ERROR",
            severity="INFO",
            description="RDP configuration could not be verified.",
            evidence=str(error),
            recommendation="Review registry access and PowerShell output."
        )

    # RDP is disabled: the RDP service is not enabled for remote access.
    if not configuration["RDPEnabled"]:
        status = "PASS"
        severity = "INFO"
        description = "Remote Desktop connections are disabled."
        recommendation = "Keep RDP disabled unless required."

    # RDP enabled without NLA is a security misconfiguration.
    elif not configuration["NLARequired"]:
        status = "FAIL"
        severity = "HIGH"
        description = "Remote Desktop is enabled without requiring NLA."
        recommendation = "Enable Network Level Authentication for RDP."

    # RDP enabled with NLA still represents an attack surface.
    else:
        status = "WARN"
        severity = "LOW"
        description = "Remote Desktop is enabled with NLA required."
        recommendation = (
            "Restrict RDP access to authorized networks and users."
        )

    # Return the security finding with the original evidence.
    return Finding(
        check_id="RDP-001",
        title="Remote Desktop security configuration",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps(configuration),
        recommendation=recommendation
    )