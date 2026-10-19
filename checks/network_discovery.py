
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: NET-003 - Network Discovery
#
# Purpose:
# Identify network neighbors previously observed by Windows.
#
# Method:
# Read the Windows ARP / IPv6 neighbor cache using PowerShell.
#
# Limitations:
# - Does not actively scan the network.
# - Only identifies entries already present in Windows' cache.
# - Does not prove that discovered devices are currently online.
# - Virtual adapters may appear in the results.
#
# This module is READ-ONLY.
# ============================================================

import json
import subprocess
import ipaddress

from core.findings import Finding


def check_network_discovery() -> Finding:
    """
    Collect and filter network neighbors observed by Windows.

    The Windows neighbor cache contains IP and link-layer
    addresses learned through ARP and IPv6 NDP.

    Multicast, broadcast, loopback and invalid addresses
    should not be counted as discovered network devices.
    """

    # --------------------------------------------------------
    # STEP 1: Collect network neighbor information
    # --------------------------------------------------------

    # Get-NetNeighbor reads Windows' existing neighbor cache.
    #
    # We exclude entries without a meaningful link-layer
    # address, but perform additional filtering in Python.
    #
    # ConvertTo-Json allows structured processing of results.
    powershell_command = """
    Get-NetNeighbor |
    Where-Object {
        $_.State -ne 'Unreachable' -and
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress -ne '00-00-00-00-00-00'
    } |
    Select-Object IPAddress, LinkLayerAddress, InterfaceIndex, State |
    ConvertTo-Json -Depth 4 -Compress
    """

    # Execute PowerShell without changing network settings.
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            powershell_command
        ],
        capture_output=True,
        text=True,
        timeout=30
    )

    # --------------------------------------------------------
    # STEP 2: Validate PowerShell execution
    # --------------------------------------------------------

    # A PowerShell failure must not produce a PASS result.
    # Raising an exception allows the Scanner to record ERROR.
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "Network discovery PowerShell command failed."
        )

    raw_output = result.stdout.strip()

    # --------------------------------------------------------
    # STEP 3: Parse JSON output
    # --------------------------------------------------------

    # No output means Windows returned no matching entries.
    if not raw_output:
        neighbors = []

    else:
        parsed = json.loads(raw_output)

        # PowerShell returns an object for one result
        # and an array for multiple results.
        if isinstance(parsed, list):
            neighbors = parsed
        elif isinstance(parsed, dict):
            neighbors = [parsed]
        elif parsed is None:
            neighbors = []
        else:
            raise ValueError(
                "Unexpected JSON structure from Get-NetNeighbor."
            )

    # --------------------------------------------------------
    # STEP 4: Filter invalid and non-device addresses
    # --------------------------------------------------------

    unique_neighbors = []
    seen = set()

    # Count excluded entries for transparency in the report.
    excluded_count = 0

    for neighbor in neighbors:

        # Validate the structure of each neighbor record.
        if not isinstance(neighbor, dict):
            excluded_count += 1
            continue

        ip_string = neighbor.get("IPAddress", "")

        # Convert the string to an IPv4Address or IPv6Address.
        # Invalid IP addresses are excluded.
        try:
            address = ipaddress.ip_address(ip_string)
        except (ValueError, TypeError):
            excluded_count += 1
            continue

        # Exclude addresses that do not represent
        # ordinary unicast network endpoints.
        #
        # Multicast examples:
        #   224.0.0.251
        #   ff02::1
        #
        # Limited broadcast:
        #   255.255.255.255
        #
        # Loopback:
        #   127.0.0.1
        #   ::1
        if (
            address.is_multicast
            or address.is_loopback
            or address.is_unspecified
            or str(address) == "255.255.255.255"
        ):
            excluded_count += 1
            continue

        # Exclude link-layer broadcast MAC addresses.
        # These do not identify an individual device.
        mac_address = str(
            neighbor.get("LinkLayerAddress", "")
        ).upper()

        if mac_address in (
            "FF-FF-FF-FF-FF-FF",
            "00-00-00-00-00-00",
            ""
        ):
            excluded_count += 1
            continue

        # ----------------------------------------------------
        # STEP 5: Remove duplicate neighbors
        # ----------------------------------------------------

        # The same IP address can appear on different
        # interfaces, so both values form the identity.
        identity = (
            str(address),
            neighbor.get("InterfaceIndex")
        )

        if identity in seen:
            excluded_count += 1
            continue

        seen.add(identity)

        # Keep the original PowerShell evidence.
        unique_neighbors.append(neighbor)

    # --------------------------------------------------------
    # STEP 6: Prepare structured evidence
    # --------------------------------------------------------

    evidence = {
        "method": "Windows neighbor cache",
        "discovered_count": len(unique_neighbors),
        "raw_entry_count": len(neighbors),
        "excluded_entry_count": excluded_count,
        "neighbors": unique_neighbors,
        "limitations": [
            "This is passive discovery, not an active network scan.",
            "Cached devices may no longer be online.",
            "Devices absent from the cache cannot be identified.",
            "Virtual network adapters may appear in the results.",
            "Subnet-directed broadcast addresses are not fully "
            "classified without interface subnet information.",
            "A discovered address does not establish a vulnerability."
        ]
    }

    # --------------------------------------------------------
    # STEP 7: Return a Pathfinder Finding
    # --------------------------------------------------------

    # PASS means the inventory collection completed
    # successfully. It does not mean the network is secure.
    return Finding(
        check_id="NET-003",
        title="Local network neighbor discovery",
        status="PASS",
        severity="INFO",
        description=(
            f"Identified {len(unique_neighbors)} cached network "
            f"neighbors after excluding {excluded_count} "
            "non-device or duplicate entries. "
            "This is an inventory observation, not a "
            "vulnerability assessment."
        ),
        evidence=json.dumps(
            evidence,
            ensure_ascii=False
        ),
        recommendation=(
            "Review observed network neighbors against the "
            "authorized device inventory. Verify unknown "
            "devices separately before drawing conclusions."
        )
    )
