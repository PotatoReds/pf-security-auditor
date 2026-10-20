
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: SMB-001 - SMB Security Configuration
#
# Purpose:
# Assess the Windows SMB server and client configuration.
#
# Checks:
# - SMBv1 server protocol
# - SMBv2/v3 server protocol
# - SMB signing requirements
# - SMB encryption settings
#
# Security:
# Read-only PowerShell queries.
#
# Limitations:
# - Does not test actual SMB network reachability.
# - Does not negotiate an SMB session.
# - Does not validate Windows security patches or CVEs.
# - SMBv2 and SMBv3 share a Windows configuration flag.
# ============================================================

import json
import subprocess

from core.findings import Finding


def collect_smb_configuration() -> dict:
    """
    Retrieve SMB server and client configuration.

    PowerShell returns one JSON object containing selected
    configuration properties. Missing properties remain null.
    """

    command = r"""
    $ErrorActionPreference = 'Stop'

    $server = Get-SmbServerConfiguration -ErrorAction Stop
    $client = Get-SmbClientConfiguration -ErrorAction Stop

    [PSCustomObject]@{
        server = [PSCustomObject]@{
            EnableSMB1Protocol = $server.EnableSMB1Protocol
            EnableSMB2Protocol = $server.EnableSMB2Protocol
            RequireSecuritySignature = $server.RequireSecuritySignature
            EnableSecuritySignature = $server.EnableSecuritySignature
            EncryptData = $server.EncryptData
            RejectUnencryptedAccess = $server.RejectUnencryptedAccess
        }
        client = [PSCustomObject]@{
            RequireSecuritySignature = $client.RequireSecuritySignature
            EnableSecuritySignature = $client.EnableSecuritySignature
        }
    } | ConvertTo-Json -Depth 5 -Compress
    """

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
        timeout=20
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "SMB configuration query failed."
        )

    configuration = json.loads(result.stdout)

    if not isinstance(configuration, dict):
        raise ValueError("Invalid SMB configuration response.")

    return configuration


def check_smb() -> Finding:
    """
    Evaluate SMB security configuration.

    FAIL:
        SMBv1 is enabled.

    WARN:
        SMB signing is not required, or another relevant
        configuration requires review.

    PASS:
        SMBv1 is disabled, SMBv2/v3 is enabled,
        and signing is required on both client and server.

    ERROR:
        Configuration could not be reliably retrieved.
    """

    try:
        configuration = collect_smb_configuration()

        server = configuration.get("server", {})
        client = configuration.get("client", {})

        if not isinstance(server, dict) or not isinstance(client, dict):
            raise ValueError("Missing SMB server or client configuration.")

        required_fields = {
            "server": [
                "EnableSMB1Protocol",
                "EnableSMB2Protocol",
                "RequireSecuritySignature",
            ],
            "client": [
                "RequireSecuritySignature",
            ]
        }

        for field in required_fields["server"]:
            if type(server.get(field)) is not bool:
                raise ValueError(
                    f"Invalid or unavailable SMB server field: {field}"
                )

        for field in required_fields["client"]:
            if type(client.get(field)) is not bool:
                raise ValueError(
                    f"Invalid or unavailable SMB client field: {field}"
                )

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        return Finding(
            check_id="SMB-001",
            title="SMB security configuration",
            status="ERROR",
            severity="INFO",
            description="Unable to assess SMB security configuration.",
            evidence=str(error),
            recommendation=(
                "Verify PowerShell permissions and availability "
                "of the SMB configuration cmdlets."
            )
        )

    smb1_enabled = server["EnableSMB1Protocol"]
    smb2_enabled = server["EnableSMB2Protocol"]

    server_signing_required = server["RequireSecuritySignature"]
    client_signing_required = client["RequireSecuritySignature"]

    observations = []
    recommendations = []

    # SMBv1 is obsolete and should normally remain disabled.
    if smb1_enabled:
        observations.append("SMBv1 server protocol is enabled.")
        recommendations.append(
            "Disable SMBv1 after assessing legacy dependencies."
        )

    # Windows uses the same flag for SMBv2 and SMBv3 support.
    if not smb2_enabled:
        observations.append("SMBv2/v3 server protocol is disabled.")
        recommendations.append(
            "Review whether SMBv2/v3 server support is required."
        )

    # SMB signing protects against certain forms of tampering
    # and relay-related attack scenarios.
    if not server_signing_required:
        observations.append("SMB server signing is not required.")
        recommendations.append(
            "Consider requiring SMB server signing after "
            "checking compatibility requirements."
        )

    if not client_signing_required:
        observations.append("SMB client signing is not required.")
        recommendations.append(
            "Consider requiring SMB client signing after "
            "checking compatibility requirements."
        )

    # Encryption is not universally required for every SMB
    # deployment. Report its configuration without treating
    # disabled global encryption as a vulnerability by itself.
    encryption_enabled = server.get("EncryptData")

    if type(encryption_enabled) is bool and not encryption_enabled:
        observations.append(
            "Global SMB server encryption is not enabled; "
            "share-level encryption has not been assessed."
        )

    # Prioritize clearly insecure protocol support.
    if smb1_enabled:
        status = "FAIL"
        severity = "HIGH"

    elif (
        not smb2_enabled
        or not server_signing_required
        or not client_signing_required
    ):
        status = "WARN"
        severity = "MEDIUM"

    else:
        status = "PASS"
        severity = "INFO"

    if not observations:
        observations.append(
            "SMBv1 is disabled, SMBv2/v3 is enabled, "
            "and signing is required on both client and server."
        )

    if not recommendations:
        recommendations.append(
            "Maintain the current SMB configuration and "
            "review security updates regularly."
        )

    evidence = {
        "server": server,
        "client": client,
        "observations": observations,
        "limitations": [
            "SMBv2 and SMBv3 are not distinguished.",
            "Share-level encryption is not assessed.",
            "No SMB connection or network reachability test was performed.",
            "Windows patch status and SMB CVEs were not validated."
        ]
    }

    return Finding(
        check_id="SMB-001",
        title="SMB security configuration",
        status=status,
        severity=severity,
        description=" ".join(observations),
        evidence=json.dumps(
            evidence,
            ensure_ascii=False
        ),
        recommendation=" ".join(recommendations)
    )
