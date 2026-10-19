import json
import subprocess

from core.findings import Finding


def check_shares() -> Finding:
    # Enumerate SMB shares and their share-level permissions.
    # No configurations or permissions are modified.
    command = r"""
    $shares = @(Get-SmbShare -ErrorAction Stop |
        Where-Object { -not $_.Special })

    $results = @(
        foreach ($share in $shares) {
            $permissions = @(
                Get-SmbShareAccess -Name $share.Name -ErrorAction Stop |
                Select-Object AccountName, AccessControlType, AccessRight
            )

            [PSCustomObject]@{
                Name = $share.Name
                Path = $share.Path
                Permissions = $permissions
            }
        }
    )

    ConvertTo-Json -InputObject $results -Depth 5 -Compress
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
                result.stderr.strip() or "SMB share enumeration failed."
            )

        shares = json.loads(result.stdout)

        if not isinstance(shares, list):
            raise ValueError("Invalid SMB share data.")

        for share in shares:
            if not isinstance(share, dict):
                raise ValueError("Invalid share entry.")

            if not isinstance(share.get("Name"), str):
                raise ValueError("Invalid share name.")

            if not isinstance(share.get("Permissions"), list):
                raise ValueError("Invalid permissions data.")

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:
        return Finding(
            check_id="SHARE-001",
            title="SMB share permissions",
            status="ERROR",
            severity="INFO",
            description="Unable to enumerate SMB shares and permissions.",
            evidence=str(error),
            recommendation="Verify SMB PowerShell access and permissions."
        )

    # Well-known SID S-1-1-0 identifies Everyone.
    # Names can be localized, so this initial version checks
    # common English representations only.
    risky_permissions = []

    for share in shares:
        for permission in share["Permissions"]:
            if not isinstance(permission, dict):
                continue

            account = str(permission.get("AccountName", "")).lower()
            access_type = str(permission.get("AccessControlType", ""))
            access_right = str(permission.get("AccessRight", ""))

            if (
                account in ("everyone", "alle", "s-1-1-0")
                and access_type == "Allow"
                and access_right in ("Full", "Change")
            ):
                risky_permissions.append({
                    "share": share["Name"],
                    "account": permission.get("AccountName"),
                    "access": access_right
                })

    if risky_permissions:
        status = "WARN"
        severity = "HIGH"
        description = (
            f"Found {len(risky_permissions)} potentially excessive "
            "SMB share permissions."
        )
        recommendation = (
            "Review broad share permissions and apply least privilege. "
            "Also inspect NTFS permissions before assessing effective access."
        )
    else:
        status = "PASS"
        severity = "INFO"
        description = (
            f"Inspected {len(shares)} non-special SMB shares. "
            "No broad write permissions were identified by this check."
        )
        recommendation = (
            "Continue reviewing SMB and NTFS permissions periodically."
        )

    return Finding(
        check_id="SHARE-001",
        title="SMB share permissions",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps({
            "share_count": len(shares),
            "risky_permissions": risky_permissions,
            "shares": shares
        }),
        recommendation=recommendation
    )