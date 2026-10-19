# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: NET-001 - Network Reconnaissance
#
# Purpose:
# Identify listening TCP ports, their associated processes,
# and potential network attack surfaces on Windows.
#
# This module is READ-ONLY.
# It does not modify firewall rules or network configuration.
# ============================================================

import subprocess
import json

from core.findings import Finding


def check_network() -> Finding:

    # --------------------------------------------------------
    # STEP 1: Collect network information using PowerShell
    # --------------------------------------------------------

    # Get-NetTCPConnection identifies listening TCP sockets.
    #
    # OwningProcess contains the process ID (PID).
    # Get-Process attempts to resolve the PID to a process name.
    #
    # Some protected processes may not expose their names.
    # In those cases, we record "Unknown".
    #
    # ConvertTo-Json produces structured output for Python.

    command = """
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
    ForEach-Object {

        # Store the current TCP connection.
        $connection = $_

        # Default value if process identification fails.
        $processName = "Unknown"

        try {
            # Resolve the process ID to a readable process name.
            $processName = (Get-Process -Id $connection.OwningProcess -ErrorAction Stop).ProcessName
        }
        catch {
            # A process may have terminated or be inaccessible.
            $processName = "Unknown"
        }

        # Return a structured record for this TCP listener.
        [PSCustomObject]@{
            LocalAddress  = $connection.LocalAddress
            LocalPort     = $connection.LocalPort
            OwningProcess = $connection.OwningProcess
            ProcessName   = $processName
        }

    } | ConvertTo-Json -Compress
    """

    # --------------------------------------------------------
    # STEP 2: Execute PowerShell and validate its output
    # --------------------------------------------------------

    try:

        # Execute PowerShell without loading user profiles.
        # The timeout prevents a stalled command from
        # blocking the entire security scan indefinitely.
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

        # A nonzero return code means collection failed.
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or
                "PowerShell network enumeration failed."
            )

        # Convert the JSON response into Python objects.
        connections = json.loads(result.stdout)

        # PowerShell can return one object instead of a list
        # when exactly one TCP listener is found.
        if isinstance(connections, dict):
            connections = [connections]

        # An empty result may be represented by JSON null.
        if connections is None:
            connections = []

        # Reject unexpected data structures.
        if not isinstance(connections, list):
            raise ValueError(
                "Unexpected network data format."
            )

        # ----------------------------------------------------
        # STEP 3: Validate every network connection
        # ----------------------------------------------------

        for connection in connections:

            # Each connection must be a dictionary.
            if not isinstance(connection, dict):
                raise ValueError(
                    "Invalid connection entry."
                )

            # The local IP address must be text.
            if not isinstance(
                connection.get("LocalAddress"), str
            ):
                raise ValueError(
                    "Invalid local address."
                )

            # Port numbers must be integers from 1 to 65535.
            port = connection.get("LocalPort")

            if type(port) is not int or not (1 <= port <= 65535):
                raise ValueError(
                    "Invalid local port."
                )

            # Process IDs must be nonnegative integers.
            pid = connection.get("OwningProcess")

            if type(pid) is not int or pid < 0:
                raise ValueError(
                    "Invalid process ID."
                )

            # Process names must be strings.
            # "Unknown" is acceptable if Windows restricts access.
            if not isinstance(
                connection.get("ProcessName"), str
            ):
                raise ValueError(
                    "Invalid process name."
                )

    # --------------------------------------------------------
    # STEP 4: Handle collection and parsing errors
    # --------------------------------------------------------

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        # A collection failure must never be reported as PASS.
        # We cannot conclude the system is secure if evidence
        # could not be collected or validated.
        return Finding(
            check_id="NET-001",
            title="Listening TCP services",
            status="ERROR",
            severity="INFO",
            description=(
                "Unable to reliably enumerate listening TCP services."
            ),
            evidence=str(error),
            recommendation=(
                "Review PowerShell execution, permissions, "
                "and network data collection."
            )
        )

    # --------------------------------------------------------
    # STEP 5: Identify potential network attack surfaces
    # --------------------------------------------------------

    # These addresses mean a service is listening on all
    # IPv4 or IPv6 interfaces respectively.
    #
    # This does NOT prove that the service is reachable
    # through Windows Firewall or from the internet.
    wildcard_addresses = ("0.0.0.0", "::")

    wildcard_listeners = [
        connection
        for connection in connections
        if connection["LocalAddress"] in wildcard_addresses
    ]

    # Identify listening ports commonly associated with
    # remote administration or Windows network services.
    #
    # Port numbers are only indicators.
    # They do not independently prove which service is running.
    security_relevant_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        135: "Microsoft RPC",
        139: "NetBIOS",
        445: "SMB",
        3389: "Remote Desktop",
        5985: "WinRM HTTP",
        5986: "WinRM HTTPS"
    }

    # Store security-relevant listeners separately.
    interesting_listeners = []

    for connection in connections:

        port = connection["LocalPort"]

        if port in security_relevant_ports:

            # Copy the original record so we do not alter
            # the collected evidence.
            interesting = connection.copy()

            # Add the service commonly associated with the port.
            interesting["PossibleService"] = (
                security_relevant_ports[port]
            )

            interesting_listeners.append(interesting)

    # --------------------------------------------------------
    # STEP 6: Determine the security finding
    # --------------------------------------------------------

    # A wildcard listener represents a potentially broader
    # attack surface than a loopback-only listener.
    #
    # However, listening ports alone are not vulnerabilities.
    # Therefore, we use WARN rather than FAIL.
    if wildcard_listeners:

        status = "WARN"
        severity = "LOW"

        description = (
            f"Found {len(connections)} listening TCP sockets. "
            f"{len(wildcard_listeners)} are bound to all interfaces. "
            f"{len(interesting_listeners)} use ports commonly "
            "associated with security-relevant services."
        )

    else:

        status = "PASS"
        severity = "INFO"

        description = (
            f"Found {len(connections)} listening TCP sockets. "
            "No wildcard-bound listeners were identified."
        )

    # --------------------------------------------------------
    # STEP 7: Prepare structured evidence
    # --------------------------------------------------------

    # Separate the full inventory from noteworthy listeners.
    # This will make the data easier to display in a future
    # HTML report or graphical interface.
    evidence = {
        "total_listeners": len(connections),
        "wildcard_listeners": len(wildcard_listeners),
        "security_relevant_listeners": interesting_listeners,
        "connections": connections
    }

    # --------------------------------------------------------
    # STEP 8: Return the security finding
    # --------------------------------------------------------

    return Finding(
        check_id="NET-001",
        title="Listening TCP services",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps(evidence, indent=4),
        recommendation=(
            "Review listening services and their owning processes. "
            "Disable unnecessary services, restrict network access "
            "using Windows Firewall, and investigate exposed "
            "remote administration protocols."
        )
    )