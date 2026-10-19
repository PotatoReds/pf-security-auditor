
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Microsoft Defender Security Assessment
# Check ID: DEF-001
# Version: 0.2.1
#
# Purpose:
# Assess Microsoft Defender's operating state and security
# configuration, including systems using third-party AV.
#
# Security:
# READ-ONLY. No antivirus settings or services are modified.
#
# Important:
# Antivirus registration does not prove active protection.
# Missing Defender data must not automatically become FAIL.
# ============================================================

import json
import subprocess
from datetime import datetime, timezone

from core.findings import Finding


# ============================================================
# STEP 1: STANDARDIZED FINDINGS
# ============================================================

def _finding(status, severity, description, evidence, recommendation):
    """Return a standardized Pathfinder DEF-001 finding."""
    return Finding(
        check_id="DEF-001",
        title="Microsoft Defender security assessment",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps(evidence, indent=2, ensure_ascii=False),
        recommendation=recommendation,
    )


def _signature_age_days(value):
    """
    Calculate the age of antivirus definitions.

    An absent, invalid or timezone-unaware timestamp
    remains unknown instead of being assumed current.
    """
    if not isinstance(value, str) or not value:
        return None

    try:
        updated = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if updated.tzinfo is None:
            return None

        age = datetime.now(timezone.utc) - updated.astimezone(
            timezone.utc
        )

        if age.total_seconds() < 0:
            return None

        return round(age.total_seconds() / 86400, 2)

    except ValueError:
        return None


# ============================================================
# STEP 2: COLLECT INDEPENDENT WINDOWS DATA SOURCES
# ============================================================

def check_defender() -> Finding:
    """
    Collect antivirus registration, Defender service state
    and Defender configuration.

    Each collection step handles errors independently,
    allowing useful evidence even if Defender is stopped.
    """

    # Each source is wrapped in its own try/catch.
    # A failure in Get-MpPreference must not discard
    # Windows Security Center registration information.
    command = r"""
$ErrorActionPreference = 'Stop'

$data = [ordered]@{
    AntivirusProducts = @()
    SecurityCenterError = $null
    DefenderService = $null
    DefenderServiceError = $null
    DefenderStatus = $null
    DefenderStatusError = $null
    DefenderPreferences = $null
    DefenderPreferencesError = $null
}

# SOURCE 1: Windows Security Center registration.
try {
    $products = @(
        Get-CimInstance `
            -Namespace 'root/SecurityCenter2' `
            -ClassName 'AntivirusProduct' `
            -ErrorAction Stop |
        ForEach-Object {
            [PSCustomObject]@{
                Name = [string]$_.displayName
                ProductState = [int]$_.productState
            }
        }
    )

    $data.AntivirusProducts = $products
}
catch {
    $data.SecurityCenterError = $_.Exception.Message
}

# SOURCE 2: Microsoft Defender Antivirus service.
try {
    $service = Get-Service `
        -Name 'WinDefend' `
        -ErrorAction Stop

    $data.DefenderService = [PSCustomObject]@{
        Status = [string]$service.Status
        StartType = [string]$service.StartType
    }
}
catch {
    $data.DefenderServiceError = $_.Exception.Message
}

# SOURCE 3: Defender runtime protection state.
try {
    $status = Get-MpComputerStatus -ErrorAction Stop

    $signatureDate = $null

    if ($null -ne $status.AntivirusSignatureLastUpdated) {
        $signatureDate = (
            $status.AntivirusSignatureLastUpdated.
                ToUniversalTime().ToString('o')
        )
    }

    $data.DefenderStatus = [PSCustomObject]@{
        AMRunningMode = [string]$status.AMRunningMode
        AntivirusEnabled = $status.AntivirusEnabled
        AntispywareEnabled = $status.AntispywareEnabled
        RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
        OnAccessProtectionEnabled = $status.OnAccessProtectionEnabled
        IsTamperProtected = $status.IsTamperProtected
        AntivirusSignatureLastUpdated = $signatureDate
    }
}
catch {
    $data.DefenderStatusError = $_.Exception.Message
}

# SOURCE 4: Defender configuration.
try {
    $preferences = Get-MpPreference -ErrorAction Stop

    $data.DefenderPreferences = [PSCustomObject]@{
        MAPSReporting = [string]$preferences.MAPSReporting
        DisableBlockAtFirstSeen = $preferences.DisableBlockAtFirstSeen
        DisableRealtimeMonitoring = $preferences.DisableRealtimeMonitoring

        # Only report exclusion counts, not sensitive paths.
        ExclusionPathCount = @(
            $preferences.ExclusionPath |
            Where-Object { $_ }
        ).Count

        ExclusionProcessCount = @(
            $preferences.ExclusionProcess |
            Where-Object { $_ }
        ).Count

        ExclusionExtensionCount = @(
            $preferences.ExclusionExtension |
            Where-Object { $_ }
        ).Count
    }
}
catch {
    $data.DefenderPreferencesError = $_.Exception.Message
}

# Return one JSON object even when individual sources fail.
ConvertTo-Json -InputObject $data -Depth 6 -Compress
"""

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=45,
        )

    except (OSError, subprocess.TimeoutExpired) as error:
        return _finding(
            "ERROR",
            "INFO",
            "Unable to execute antivirus assessment.",
            {"error": str(error)},
            "Verify PowerShell availability and permissions.",
        )

    if result.returncode != 0:
        return _finding(
            "ERROR",
            "INFO",
            "Antivirus evidence collection failed.",
            {"error": result.stderr.strip()},
            "Investigate PowerShell execution errors.",
        )

    try:
        evidence = json.loads(result.stdout.strip())

        if not isinstance(evidence, dict):
            raise ValueError("Expected a JSON object.")

    except (json.JSONDecodeError, ValueError) as error:
        return _finding(
            "ERROR",
            "INFO",
            "Invalid antivirus evidence returned.",
            {"error": str(error)},
            "Inspect PowerShell JSON output.",
        )

    # ========================================================
    # STEP 3: NORMALIZE COLLECTED EVIDENCE
    # ========================================================

    products = evidence.get("AntivirusProducts") or []
    service = evidence.get("DefenderService") or {}
    status = evidence.get("DefenderStatus") or {}

    # Keep product names for documentation.
    # ProductState is preserved as raw evidence rather
    # than interpreted as proof of active protection.
    product_names = [
        str(product.get("Name", ""))
        for product in products
        if isinstance(product, dict)
    ]

    # Exclude Microsoft Defender specifically.
# Do not exclude third-party products such as Bitdefender.
    other_products = [
        name
        for name in product_names
        if name.strip().casefold() not in (
            "windows defender",
            "microsoft defender",
            "microsoft defender antivirus",
        )
    ]

    service_state = str(service.get("Status") or "").lower()
    mode = str(status.get("AMRunningMode") or "").lower()

    signature_age = _signature_age_days(
        status.get("AntivirusSignatureLastUpdated")
    )

    evidence["AntivirusSignatureAgeDays"] = signature_age
    evidence["AlternativeAntivirusProducts"] = other_products

    # ========================================================
    # STEP 4: ASSESS STOPPED OR PASSIVE DEFENDER
    # ========================================================

    if service_state == "stopped" or "passive" in mode:

        if other_products:
            return _finding(
                "WARN",
                "INFO",
                (
                    "Microsoft Defender is not providing confirmed "
                    "active protection. Another antivirus product "
                    "is registered, but its protection state "
                    "has not been independently verified."
                ),
                evidence,
                (
                    "Verify the registered antivirus product is "
                    "actively protecting the system and receiving "
                    "security updates."
                ),
            )

        # No alternative product was found. If Security Center
        # failed, we cannot claim there is no other antivirus.
        if evidence.get("SecurityCenterError"):
            return _finding(
                "WARN",
                "MEDIUM",
                (
                    "Microsoft Defender is inactive and antivirus "
                    "registration could not be verified."
                ),
                evidence,
                "Verify active endpoint protection manually.",
            )

        return _finding(
            "WARN",
            "HIGH",
            (
                "Microsoft Defender is inactive and no alternative "
                "antivirus product was registered."
            ),
            evidence,
            (
                "Verify whether the system has active antivirus "
                "protection before treating it as protected."
            ),
        )

    # ========================================================
    # STEP 5: HANDLE UNAVAILABLE DEFENDER STATUS
    # ========================================================

    if not status:

        if other_products:
            return _finding(
                "WARN",
                "INFO",
                (
                    "Defender configuration is unavailable. "
                    "An alternative antivirus product is registered, "
                    "but active protection is unverified."
                ),
                evidence,
                "Verify the alternative antivirus protection state.",
            )

        return _finding(
            "WARN",
            "MEDIUM",
            (
                "Defender configuration could not be evaluated "
                "and active antivirus protection is unverified."
            ),
            evidence,
            "Investigate antivirus service and protection status.",
        )

    # ========================================================
    # STEP 6: ASSESS ACTIVE DEFENDER
    # ========================================================

    if mode != "normal":
        return _finding(
            "WARN",
            "MEDIUM",
            (
                "Defender reported an operating mode that "
                "requires further investigation."
            ),
            evidence,
            "Verify Defender operating mode and active protection.",
        )

    problems = []

    required_states = (
        "AntivirusEnabled",
        "AntispywareEnabled",
        "RealTimeProtectionEnabled",
        "OnAccessProtectionEnabled",
    )

    for field in required_states:
        if status.get(field) is False:
            problems.append(f"{field} is disabled.")

    # Seven days is a Pathfinder project threshold,
    # not an official compliance benchmark.
    if signature_age is not None and signature_age > 7:
        problems.append(
            f"Security intelligence is {signature_age} days old."
        )

    if problems:
        return _finding(
            "WARN",
            "HIGH",
            "Defender protection requires review: " + " ".join(problems),
            evidence,
            "Review Defender protection settings and updates.",
        )

    # Do not issue PASS if key evidence is missing.
    if any(
        type(status.get(field)) is not bool
        for field in required_states
    ):
        return _finding(
            "WARN",
            "INFO",
            "Some Defender protection states could not be verified.",
            evidence,
            "Review the missing Defender protection states.",
        )

    if signature_age is None:
        return _finding(
            "WARN",
            "INFO",
            "Defender is active, but signature age is unknown.",
            evidence,
            "Verify Defender security intelligence updates.",
        )

    # Tamper protection, cloud configuration and exclusion
    # counts are documented but not fully policy-assessed.
    return _finding(
        "PASS",
        "INFO",
        (
            "Microsoft Defender is active with real-time "
            "protection and recent security intelligence."
        ),
        evidence,
        (
            "Maintain updates and review cloud protection, "
            "tamper protection and exclusions."
        ),
    )
