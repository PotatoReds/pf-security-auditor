import json
import subprocess

from core.findings import Finding


def check_bitlocker() -> Finding:
    # Retrieve encryption and protection status for local volumes.
    # This is a read-only operation.
    command = r"""
    $volumes = @(
        Get-BitLockerVolume -ErrorAction Stop |
        Select-Object MountPoint, VolumeStatus,
            ProtectionStatus, EncryptionPercentage
    )

    ConvertTo-Json -InputObject $volumes -Depth 4 -Compress
    """

    try:
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
                result.stderr.strip() or "BitLocker query failed."
            )

        volumes = json.loads(result.stdout)

        if not isinstance(volumes, list):
            raise ValueError("Invalid BitLocker volume data.")

        if not volumes:
            raise ValueError("No BitLocker volumes returned.")

        for volume in volumes:
            if not isinstance(volume, dict):
                raise ValueError("Invalid volume entry.")

            if not isinstance(volume.get("MountPoint"), str):
                raise ValueError("Invalid volume mount point.")

            if type(volume.get("EncryptionPercentage")) not in (int, float):
                raise ValueError("Invalid encryption percentage.")

            if not 0 <= volume["EncryptionPercentage"] <= 100:
                raise ValueError("Encryption percentage outside valid range.")

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:
        return Finding(
            check_id="BL-001",
            title="BitLocker volume encryption",
            status="ERROR",
            severity="INFO",
            description="Unable to verify BitLocker encryption.",
            evidence=str(error),
            recommendation=(
                "Verify BitLocker availability and PowerShell permissions."
            )
        )

    # PowerShell serializes these enum values as integers.
    # VolumeStatus: 1 = FullyEncrypted
    # ProtectionStatus: 1 = On
    unprotected = []

    for volume in volumes:
        status = volume.get("VolumeStatus")
        protection = volume.get("ProtectionStatus")

        # Accept either numeric or string enum representations.
        fully_encrypted = status in (1, "FullyEncrypted")
        protection_on = protection in (1, "On")

        if not fully_encrypted or not protection_on:
            unprotected.append(volume["MountPoint"])

    if unprotected:
        status = "WARN"
        severity = "MEDIUM"
        description = (
            f"Found {len(unprotected)} volumes without confirmed "
            "full encryption and active BitLocker protection."
        )
        recommendation = (
            "Review volume encryption requirements and enable "
            "BitLocker where appropriate."
        )
    else:
        status = "PASS"
        severity = "INFO"
        description = (
            f"All {len(volumes)} reported volumes have full encryption "
            "and active BitLocker protection."
        )
        recommendation = (
            "Maintain encryption and securely back up recovery keys."
        )

    return Finding(
        check_id="BL-001",
        title="BitLocker volume encryption",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps({
            "volume_count": len(volumes),
            "unprotected_volumes": unprotected,
            "volumes": volumes
        }),
        recommendation=recommendation
    )