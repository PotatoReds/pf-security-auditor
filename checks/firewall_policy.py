
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Windows Firewall Policy Context
# Check ID: FW-002
#
# Purpose:
# Collect firewall profile configuration and network
# interface context for subsequent exposure analysis.
#
# This module does not modify firewall settings.
# ============================================================

import json
import subprocess

from core.findings import Finding


def check_firewall_policy() -> Finding:
    """
    Collect effective firewall profile and network context.

    Returns:
        A Finding containing:
        - Firewall profile configuration from ActiveStore.
        - Network connection profiles.
        - Associated network interface information.

    The collected evidence will support correlation with
    NET-001 listening sockets and NET-002 firewall rules.
    """

    # --------------------------------------------------------
    # STEP 1: PREPARE READ-ONLY POWERSHELL QUERIES
    # --------------------------------------------------------

    command = r"""
    $ErrorActionPreference = 'Stop'

    # Read firewall profiles from the effective policy store.
    $firewallProfiles = @(
        Get-NetFirewallProfile -PolicyStore ActiveStore |
        ForEach-Object {
            [PSCustomObject]@{
                Name = [string]$_.Name
                Enabled = [bool]$_.Enabled
                DefaultInboundAction = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
                AllowInboundRules = [string]$_.AllowInboundRules
                AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
            }
        }
    )

    # Identify active Windows network connection profiles.
    $networkProfiles = @(
        Get-NetConnectionProfile |
        ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias = [string]$_.InterfaceAlias
                InterfaceIndex = [int]$_.InterfaceIndex
                NetworkCategory = [string]$_.NetworkCategory
                IPv4Connectivity = [string]$_.IPv4Connectivity
                IPv6Connectivity = [string]$_.IPv6Connectivity
            }
        }
    )

    # Collect interface type and status information.
    $networkAdapters = @(
        Get-NetAdapter |
        ForEach-Object {
            [PSCustomObject]@{
                Name = [string]$_.Name
                InterfaceIndex = [int]$_.ifIndex
                Status = [string]$_.Status
                InterfaceDescription = [string]$_.InterfaceDescription
                HardwareInterface = [bool]$_.HardwareInterface
            }
        }
    )

    # Return a single structured JSON object.
    [PSCustomObject]@{
        FirewallProfiles = $firewallProfiles
        NetworkProfiles = $networkProfiles
        NetworkAdapters = $networkAdapters
    } | ConvertTo-Json -Depth 5 -Compress
    """

    # --------------------------------------------------------
    # STEP 2: EXECUTE POWERSHELL
    # --------------------------------------------------------

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
            timeout=30
        )

        # PowerShell failures must be reported explicitly.
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "Firewall policy query failed."
            )

        # Convert PowerShell's JSON output into a dictionary.
        data = json.loads(result.stdout)

        if not isinstance(data, dict):
            raise ValueError("Expected firewall policy object.")

        # Validate the three required evidence collections.
        required_sections = (
            "FirewallProfiles",
            "NetworkProfiles",
            "NetworkAdapters"
        )

        for section in required_sections:
            if not isinstance(data.get(section), list):
                raise ValueError(
                    f"Missing or invalid firewall policy section: {section}"
                )

        # An empty firewall profile collection is not valid
        # evidence of a secure configuration.
        if not data["FirewallProfiles"]:
            raise ValueError("No firewall profiles were returned.")

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError
    ) as error:

        # A failed assessment is ERROR, never PASS.
        return Finding(
            check_id="FW-002",
            title="Windows Firewall policy context",
            status="ERROR",
            severity="INFO",
            description="Unable to collect firewall policy context.",
            evidence=str(error),
            recommendation=(
                "Verify PowerShell firewall cmdlet availability "
                "and permissions."
            )
        )

    # --------------------------------------------------------
    # STEP 3: RETURN STRUCTURED POLICY EVIDENCE
    # --------------------------------------------------------

    # PASS means collection succeeded. It does not mean
    # the firewall policy is necessarily secure.
    return Finding(
        check_id="FW-002",
        title="Windows Firewall policy context",
        status="PASS",
        severity="INFO",
        description=(
            f"Collected {len(data['FirewallProfiles'])} firewall "
            f"profiles, {len(data['NetworkProfiles'])} network "
            f"connection profiles and "
            f"{len(data['NetworkAdapters'])} adapters."
        ),
        evidence=json.dumps(data),
        recommendation=(
            "Use the collected policy context when assessing "
            "inbound firewall rules and listening services."
        )
    )
