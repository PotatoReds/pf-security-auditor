import subprocess
import json

from core.findings import Finding


def check_smb() -> Finding:

    # Read the SMBv1 server configuration from Windows.
    command = """
    Get-SmbServerConfiguration -ErrorAction Stop |
    Select-Object -ExpandProperty EnableSMB1Protocol |
    ConvertTo-Json -Compress
    """

    try:
        # Execute PowerShell without changing system settings.
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

        # Report PowerShell execution failures.
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "SMB query failed."
            )

        # Convert the returned JSON value to a Python boolean.
        smb1_enabled = json.loads(result.stdout)

        # Reject unexpected values.
        if type(smb1_enabled) is not bool:
            raise ValueError("Invalid SMBv1 configuration value.")

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        return Finding(
            check_id="SMB-001",
            title="SMBv1 server protocol configuration",
            status="ERROR",
            severity="INFO",
            description="Unable to verify SMBv1 server configuration.",
            evidence=str(error),
            recommendation="Verify PowerShell permissions and SMB configuration."
        )

    # SMBv1 is an obsolete protocol with known security risks.
    if smb1_enabled:
        status = "FAIL"
        severity = "HIGH"
        description = "The insecure SMBv1 server protocol is enabled."
        recommendation = "Disable SMBv1 after checking legacy dependencies."

    else:
        status = "PASS"
        severity = "INFO"
        description = "The SMBv1 server protocol is disabled."
        recommendation = "Keep SMBv1 disabled."

    return Finding(
        check_id="SMB-001",
        title="SMBv1 server protocol configuration",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps({
            "EnableSMB1Protocol": smb1_enabled
        }),
        recommendation=recommendation
    )