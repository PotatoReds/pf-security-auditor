
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Windows Firewall Policy Context
# Check ID: FW-002
#
# Purpose:
# Collect firewall profile configuration, network
# interfaces and their assigned IP addresses.
#
# Supports:
# - NET-001: Listening TCP services
# - NET-002: Inbound firewall rule analysis
# - COR-002: Network exposure correlation
#
# Security:
# READ-ONLY. No Windows settings are modified.
# ============================================================

import json
import subprocess

from core.findings import Finding


def check_firewall_policy() -> Finding:
    """
    Collect effective firewall policy and network context.

    Returns:
        A Finding containing structured JSON evidence:

        - FirewallProfiles:
          Effective Windows Firewall profile settings.

        - NetworkProfiles:
          Network categories associated with interfaces.

        - NetworkAdapters:
          Interface names, indexes and operational status.

        - IPAddresses:
          Assigned IPv4 and IPv6 addresses, including
          prefix lengths and interface associations.

    Limitations:
        Successful collection does not prove that the
        firewall configuration is secure.

        Interface configuration and firewall rules must
        be correlated before evaluating exposure.
    """

    # --------------------------------------------------------
    # STEP 1: PREPARE READ-ONLY POWERSHELL QUERIES
    # --------------------------------------------------------

    command = r"""
    $ErrorActionPreference = 'Stop'

    # --------------------------------------------------------
    # COLLECT FIREWALL PROFILE CONFIGURATION
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # COLLECT ACTIVE NETWORK CONNECTION PROFILES
    # --------------------------------------------------------

    # Identify Windows network categories.
    # Typical categories are Public, Private and Domain.
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

    # --------------------------------------------------------
    # COLLECT NETWORK ADAPTER INFORMATION
    # --------------------------------------------------------

    # Record interface identity and operational status.
    # InterfaceIndex allows correlation with IP addresses
    # and Windows network connection profiles.
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

    # --------------------------------------------------------
    # COLLECT IPv4 AND IPv6 ADDRESS CONFIGURATION
    # --------------------------------------------------------

    # Collect locally assigned IP addresses.
    #
    # InterfaceIndex links each address to its adapter
    # and, when available, its network connection profile.
    #
    # AddressState identifies whether an address is
    # preferred, tentative, deprecated or otherwise
    # unsuitable for ordinary communication.
    #
    # PrefixLength describes the configured subnet.
    #
    # SkipAsSource indicates whether Windows should
    # avoid selecting the address for outgoing traffic.
    # It does not mean inbound traffic is blocked.
    $ipAddresses = @(
        Get-NetIPAddress |
        ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias = [string]$_.InterfaceAlias
                InterfaceIndex = [int]$_.InterfaceIndex
                AddressFamily = [string]$_.AddressFamily
                IPAddress = [string]$_.IPAddress
                PrefixLength = [int]$_.PrefixLength
                AddressState = [string]$_.AddressState
                PrefixOrigin = [string]$_.PrefixOrigin
                SuffixOrigin = [string]$_.SuffixOrigin
                SkipAsSource = [bool]$_.SkipAsSource
            }
        }
    )

    # --------------------------------------------------------
    # RETURN STRUCTURED JSON
    # --------------------------------------------------------

    # Preserve arrays even when only one object exists.
    [PSCustomObject]@{
        FirewallProfiles = $firewallProfiles
        NetworkProfiles = $networkProfiles
        NetworkAdapters = $networkAdapters
        IPAddresses = $ipAddresses
    } | ConvertTo-Json -Depth 6 -Compress
    """

    # --------------------------------------------------------
    # STEP 2: EXECUTE POWERSHELL
    # --------------------------------------------------------

    try:
        # Execute read-only Windows networking commands.
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
            timeout=45
        )

        # A failed PowerShell query must never produce PASS.
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
                or "Firewall policy query failed."
            )

        # Convert PowerShell's JSON output into Python data.
        data = json.loads(result.stdout)

        if not isinstance(data, dict):
            raise ValueError(
                "Expected firewall policy evidence object."
            )

        # ----------------------------------------------------
        # VALIDATE REQUIRED EVIDENCE COLLECTIONS
        # ----------------------------------------------------

        # All four sections must be present as lists.
        required_sections = (
            "FirewallProfiles",
            "NetworkProfiles",
            "NetworkAdapters",
            "IPAddresses"
        )

        for section in required_sections:
            if not isinstance(data.get(section), list):
                raise ValueError(
                    f"Missing or invalid firewall policy "
                    f"section: {section}"
                )

        # Firewall profile information is essential.
        if not data["FirewallProfiles"]:
            raise ValueError(
                "No firewall profiles were returned."
            )

        # ----------------------------------------------------
        # VALIDATE IP ADDRESS RECORDS
        # ----------------------------------------------------

        # Each IP address must identify its interface.
        # This prevents COR-002 from correlating an address
        # with the wrong network adapter.
        required_ip_fields = (
            "InterfaceAlias",
            "InterfaceIndex",
            "AddressFamily",
            "IPAddress",
            "PrefixLength",
            "AddressState",
            "PrefixOrigin",
            "SuffixOrigin",
            "SkipAsSource"
        )

        for index, address in enumerate(data["IPAddresses"]):

            if not isinstance(address, dict):
                raise ValueError(
                    f"Invalid IP address record at index {index}."
                )

            for field in required_ip_fields:
                if field not in address:
                    raise ValueError(
                        f"Missing IP address field '{field}' "
                        f"at index {index}."
                    )

            # Validate interface identifiers and prefixes.
            if not isinstance(address["InterfaceIndex"], int):
                raise ValueError(
                    f"Invalid InterfaceIndex at index {index}."
                )

            if not isinstance(address["PrefixLength"], int):
                raise ValueError(
                    f"Invalid PrefixLength at index {index}."
                )

            if address["AddressFamily"] not in ("IPv4", "IPv6"):
                raise ValueError(
                    f"Unsupported address family at index {index}."
                )

            if not isinstance(address["IPAddress"], str):
                raise ValueError(
                    f"Invalid IPAddress at index {index}."
                )

            if not address["IPAddress"].strip():
                raise ValueError(
                    f"Empty IPAddress at index {index}."
                )

            if not isinstance(address["SkipAsSource"], bool):
                raise ValueError(
                    f"Invalid SkipAsSource at index {index}."
                )

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError
    ) as error:

        # Failed collection must be reported as ERROR.
        return Finding(
            check_id="FW-002",
            title="Windows Firewall policy context",
            status="ERROR",
            severity="INFO",
            description=(
                "Unable to collect firewall policy "
                "and network interface context."
            ),
            evidence=str(error),
            recommendation=(
                "Verify PowerShell networking cmdlets, "
                "firewall query permissions and IP address data."
            )
        )

    # --------------------------------------------------------
    # STEP 3: RETURN STRUCTURED POLICY EVIDENCE
    # --------------------------------------------------------

    # PASS confirms successful data collection only.
    # It does not certify firewall security.
    return Finding(
        check_id="FW-002",
        title="Windows Firewall policy context",
        status="PASS",
        severity="INFO",
        description=(
            f"Collected {len(data['FirewallProfiles'])} firewall "
            f"profiles, {len(data['NetworkProfiles'])} network "
            f"connection profiles, "
            f"{len(data['NetworkAdapters'])} adapters and "
            f"{len(data['IPAddresses'])} IP addresses."
        ),
        evidence=json.dumps(data),
        recommendation=(
            "Correlate firewall profiles, network interfaces "
            "and assigned IP addresses with inbound firewall "
            "rules and listening TCP services."
        )
    )
