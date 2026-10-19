
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: NET-001 - Network Reconnaissance
#
# Purpose:
# Identify listening TCP ports, their associated processes,
# executable paths, and potential network attack surfaces.
#
# The executable path can subsequently be correlated with
# Windows Firewall application-specific rules.
#
# Security:
# READ-ONLY. No firewall or network settings are modified.
# ============================================================

import subprocess
import json

from core.findings import Finding


def check_network() -> Finding:
    """
    Enumerate Windows TCP listeners and associated processes.

    Returns:
        A Finding containing structured JSON evidence.

    Process names and executable paths may be unavailable
    for protected processes or insufficient permissions.
    Missing process information is not treated as proof
    that a process or executable does not exist.
    """

    # --------------------------------------------------------
    # STEP 1: Collect network and process information
    # --------------------------------------------------------

    # Get-NetTCPConnection provides listening TCP sockets.
    #
    # Get-CimInstance Win32_Process provides process names
    # and executable paths where Windows permits access.
    #
    # We first collect the TCP connections and then query
    # each unique PID only once. This avoids repeated CIM
    # queries for processes with multiple listening sockets.
    #
    # A missing executable path is represented as JSON null.
    # It must not be interpreted as a path mismatch.

    command = r"""
    $ErrorActionPreference = "Stop"

    # Collect all listening TCP sockets.
    $listeners = @(
        Get-NetTCPConnection -State Listen -ErrorAction Stop
    )

    # Build a lookup table containing process information.
    $processCache = @{}

    # Resolve each unique process ID only once.
    $uniquePids = @(
        $listeners |
        Select-Object -ExpandProperty OwningProcess -Unique
    )

    foreach ($processId in $uniquePids) {

        # Use a string key for consistent hashtable access.
        $key = [string]$processId

        # Default to unknown process information.
        $processName = "Unknown"
        $executablePath = $null

        try {
            # Query Windows Management Instrumentation
            # for the process name and executable path.
            $processInfo = Get-CimInstance Win32_Process `
                -Filter "ProcessId = $processId" `
                -ErrorAction Stop

            if ($null -ne $processInfo) {

                # Record the process name when available.
                if (-not [string]::IsNullOrWhiteSpace(
                    $processInfo.Name
                )) {
                    $processName = [string]$processInfo.Name
                }

                # Record the full executable path only
                # when Windows actually provides it.
                if (-not [string]::IsNullOrWhiteSpace(
                    $processInfo.ExecutablePath
                )) {
                    $executablePath = [string](
                        $processInfo.ExecutablePath
                    )
                }
            }
        }
        catch {
            # Protected or terminated processes may not
            # expose their information through CIM.
            #
            # Continue without failing the entire scan.
        }

        # Fall back to Get-Process for the process name.
        # This does not invent an executable path.
        if ($processName -eq "Unknown") {

            try {
                $fallback = Get-Process `
                    -Id $processId `
                    -ErrorAction Stop

                if ($null -ne $fallback) {
                    $processName = [string]$fallback.ProcessName
                }
            }
            catch {
                # Preserve "Unknown" if access is denied.
            }
        }

        # Store the resolved information for this PID.
        $processCache[$key] = [PSCustomObject]@{
            ProcessName    = $processName
            ExecutablePath = $executablePath
        }
    }

    # Build the structured TCP listener inventory.
    $records = @(
        foreach ($connection in $listeners) {

            $key = [string]$connection.OwningProcess
            $processInfo = $processCache[$key]

            [PSCustomObject]@{
                LocalAddress   = [string]$connection.LocalAddress
                LocalPort      = [int]$connection.LocalPort
                OwningProcess  = [int]$connection.OwningProcess
                ProcessName    = [string]$processInfo.ProcessName
                ExecutablePath = $processInfo.ExecutablePath
            }
        }
    )

    # Always serialize an array, including when there
    # are zero or one listening TCP sockets.
    ConvertTo-Json -InputObject $records -Depth 5 -Compress
    """

    # --------------------------------------------------------
    # STEP 2: Execute PowerShell and parse the response
    # --------------------------------------------------------

    try:

        # The additional CIM queries can take longer than
        # the previous process-name-only implementation.
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

        # A failed PowerShell command invalidates the
        # network evidence collected by this check.
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
                or "PowerShell network enumeration failed."
            )

        # Convert the PowerShell JSON output to Python.
        connections = json.loads(result.stdout)

        # Retain compatibility with single-object output.
        if isinstance(connections, dict):
            connections = [connections]

        # Treat JSON null as an empty listener inventory.
        if connections is None:
            connections = []

        # Reject unexpected output formats.
        if not isinstance(connections, list):
            raise ValueError(
                "Unexpected network data format."
            )

        # ----------------------------------------------------
        # STEP 3: Validate the collected network records
        # ----------------------------------------------------

        for connection in connections:

            # Each listener must be represented as an object.
            if not isinstance(connection, dict):
                raise ValueError(
                    "Invalid connection entry."
                )

            # Validate the local listening address.
            if not isinstance(
                connection.get("LocalAddress"), str
            ):
                raise ValueError(
                    "Invalid local address."
                )

            # TCP port numbers must be between 1 and 65535.
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
            if not isinstance(
                connection.get("ProcessName"), str
            ):
                raise ValueError(
                    "Invalid process name."
                )

            # ExecutablePath may be a string or JSON null.
            #
            # Null means Windows did not provide the path.
            # It is not evidence that the process is safe
            # or that a firewall application rule excludes it.
            executable_path = connection.get("ExecutablePath")

            if (
                executable_path is not None
                and not isinstance(executable_path, str)
            ):
                raise ValueError(
                    "Invalid executable path."
                )

    # --------------------------------------------------------
    # STEP 4: Handle collection and validation errors
    # --------------------------------------------------------

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        # Failed evidence collection must never become PASS.
        return Finding(
            check_id="NET-001",
            title="Listening TCP services",
            status="ERROR",
            severity="INFO",
            description=(
                "Unable to reliably enumerate listening "
                "TCP services and associated processes."
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

    # Wildcard listeners bind to all IPv4 or IPv6
    # interfaces respectively.
    #
    # A wildcard listener does not prove that a remote
    # computer can reach the listening service.
    wildcard_addresses = ("0.0.0.0", "::")

    wildcard_listeners = [
        connection
        for connection in connections
        if connection["LocalAddress"] in wildcard_addresses
    ]

    # Ports commonly associated with network services
    # and remote administration.
    #
    # These are indicators, not confirmed service identities.
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

    # Keep noteworthy listeners in a separate inventory.
    interesting_listeners = []

    for connection in connections:

        port = connection["LocalPort"]

        if port in security_relevant_ports:

            # Copy the original record without changing it.
            interesting = connection.copy()

            # Add the service commonly associated with
            # the port number.
            interesting["PossibleService"] = (
                security_relevant_ports[port]
            )

            interesting_listeners.append(interesting)

    # --------------------------------------------------------
    # STEP 6: Measure process identification coverage
    # --------------------------------------------------------

    # Count listener records with available executable paths.
    #
    # This measures evidence completeness rather than
    # the number of distinct executable files.
    identified_paths = sum(
        1
        for connection in connections
        if connection["ExecutablePath"]
    )

    unidentified_paths = (
        len(connections) - identified_paths
    )

    # --------------------------------------------------------
    # STEP 7: Determine the security finding
    # --------------------------------------------------------

    if wildcard_listeners:

        status = "WARN"
        severity = "LOW"

        description = (
            f"Found {len(connections)} listening TCP sockets. "
            f"{len(wildcard_listeners)} are bound to all interfaces. "
            f"{len(interesting_listeners)} use ports commonly "
            "associated with security-relevant services. "
            f"Resolved executable paths for "
            f"{identified_paths} listeners."
        )

    else:

        status = "PASS"
        severity = "INFO"

        description = (
            f"Found {len(connections)} listening TCP sockets. "
            "No wildcard-bound listeners were identified. "
            f"Resolved executable paths for "
            f"{identified_paths} listeners."
        )

    # --------------------------------------------------------
    # STEP 8: Prepare structured JSON evidence
    # --------------------------------------------------------

    # Preserve the existing evidence structure.
    #
    # Add path coverage metrics and ExecutablePath fields
    # without removing information used by other modules.
    evidence = {
        "total_listeners": len(connections),
        "wildcard_listeners": len(wildcard_listeners),
        "security_relevant_listeners": interesting_listeners,
        "connections": connections,
        "executable_paths_identified": identified_paths,
        "executable_paths_unavailable": unidentified_paths
    }

    # --------------------------------------------------------
    # STEP 9: Return the security finding
    # --------------------------------------------------------

    return Finding(
        check_id="NET-001",
        title="Listening TCP services",
        status=status,
        severity=severity,
        description=description,
        evidence=json.dumps(evidence, indent=4),
        recommendation=(
            "Review listening services and their owning "
            "processes. Disable unnecessary services, "
            "restrict network access using Windows Firewall, "
            "and investigate exposed remote administration "
            "protocols."
        )
    )
