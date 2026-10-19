
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Network Exposure Analysis
# Check ID: NET-002
#
# Purpose:
# Collect enabled inbound Windows Firewall rules,
# including Allow/Block actions and seven filter types.
#
# Supports:
# - NET-001: Listening TCP services
# - FW-002: Firewall policy and network context
# - COR-002: Future effective-policy correlation
#
# Security:
# READ-ONLY. No Windows settings are modified.
# ============================================================

import json
import subprocess

from core.findings import Finding


def check_exposure() -> Finding:
    """
    Collect enabled inbound firewall rules and their filters.

    Returns:
        A Finding containing structured JSON evidence.

    Filter categories:
        1. Port and protocol
        2. Local and remote addresses
        3. Application
        4. Windows service
        5. Interface type
        6. Specific interface alias
        7. Authentication and IPsec security conditions

    Limitations:
        Collecting firewall policy is not equivalent to
        proving network reachability. COR-002 must assess
        the relevant conditions before drawing conclusions.
    """

    # --------------------------------------------------------
    # STEP 1: COLLECT FIREWALL RULES AND FILTERS
    # --------------------------------------------------------

    # All filter collections are retrieved in batches.
    # InstanceID links each filter to its parent rule.

    command = r"""
    $ErrorActionPreference = 'Stop'

    # Retrieve enabled inbound Allow and Block rules.
    $rules = @(
        Get-NetFirewallRule -PolicyStore ActiveStore `
            -Direction Inbound -Enabled True
    )

    # Retrieve the seven filter collections.
    $portFilters = @(
        Get-NetFirewallPortFilter -PolicyStore ActiveStore
    )

    $addressFilters = @(
        Get-NetFirewallAddressFilter -PolicyStore ActiveStore
    )

    $applicationFilters = @(
        Get-NetFirewallApplicationFilter -PolicyStore ActiveStore
    )

    $serviceFilters = @(
        Get-NetFirewallServiceFilter -PolicyStore ActiveStore
    )

    $interfaceTypeFilters = @(
        Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore
    )

    $interfaceFilters = @(
        Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore
    )

    $securityFilters = @(
        Get-NetFirewallSecurityFilter -PolicyStore ActiveStore
    )

    # --------------------------------------------------------
    # STEP 2: INDEX FILTERS BY INSTANCE ID
    # --------------------------------------------------------

    # Using lookup tables avoids searching every filter
    # collection separately for each firewall rule.

    $portsById = @{}
    foreach ($item in $portFilters) {
        $portsById[[string]$item.InstanceID] = $item
    }

    $addressesById = @{}
    foreach ($item in $addressFilters) {
        $addressesById[[string]$item.InstanceID] = $item
    }

    $applicationsById = @{}
    foreach ($item in $applicationFilters) {
        $applicationsById[[string]$item.InstanceID] = $item
    }

    $servicesById = @{}
    foreach ($item in $serviceFilters) {
        $servicesById[[string]$item.InstanceID] = $item
    }

    $interfaceTypesById = @{}
    foreach ($item in $interfaceTypeFilters) {
        $interfaceTypesById[[string]$item.InstanceID] = $item
    }

    $interfacesById = @{}
    foreach ($item in $interfaceFilters) {
        $interfacesById[[string]$item.InstanceID] = $item
    }

    $securityById = @{}
    foreach ($item in $securityFilters) {
        $securityById[[string]$item.InstanceID] = $item
    }

    # --------------------------------------------------------
    # STEP 3: COMBINE RULES WITH ALL SEVEN FILTERS
    # --------------------------------------------------------

    $results = @(
        foreach ($rule in $rules) {

            # Identify the firewall rule.
            $id = [string]$rule.InstanceID

            # Retrieve associated filter objects.
            $port = $portsById[$id]
            $address = $addressesById[$id]
            $application = $applicationsById[$id]
            $service = $servicesById[$id]
            $interfaceType = $interfaceTypesById[$id]
            $interface = $interfacesById[$id]
            $security = $securityById[$id]

            # Stop if any required filter is missing.
            # Otherwise the auditor could overlook a
            # security restriction or blocking condition.
            if (
                $null -eq $port -or
                $null -eq $address -or
                $null -eq $application -or
                $null -eq $service -or
                $null -eq $interfaceType -or
                $null -eq $interface -or
                $null -eq $security
            ) {
                throw "Missing firewall filter for rule: $id"
            }

            # Combine the rule and its filters into one
            # structured object for Python correlation.
            [PSCustomObject]@{

                # Rule identification.
                Name = [string]$rule.Name
                DisplayName = [string]$rule.DisplayName

                # Rule action and profile restrictions.
                Action = [string]$rule.Action
                Profile = [string]$rule.Profile

                # Protocol and local port restrictions.
                Protocol = [string]$port.Protocol
                LocalPort = [string]$port.LocalPort

                # Source and destination restrictions.
                LocalAddress = [string]$address.LocalAddress
                RemoteAddress = [string]$address.RemoteAddress

                # Application and Windows service restrictions.
                Program = [string]$application.Program
                Service = [string]$service.Service

                # Network interface restrictions.
                InterfaceType = [string]$interfaceType.InterfaceType
                InterfaceAlias = [string]$interface.InterfaceAlias

                # Authentication and encryption requirements.
                Authentication = [string]$security.Authentication
                Encryption = [string]$security.Encryption

                # Authenticated bypass of ordinary Block rules.
                OverrideBlockRules = [string]$security.OverrideBlockRules

                # Identity-based firewall restrictions.
                LocalUser = [string]$security.LocalUser
                RemoteUser = [string]$security.RemoteUser
                RemoteMachine = [string]$security.RemoteMachine

                # Edge traversal behavior.
                EdgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy
            }
        }
    )

    # Preserve the JSON array even when only one rule exists.
    ConvertTo-Json -InputObject $results -Depth 5 -Compress
    """

    # --------------------------------------------------------
    # STEP 4: EXECUTE POWERSHELL AND VALIDATE EVIDENCE
    # --------------------------------------------------------

    try:
        # Execute read-only Windows Firewall queries.
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
            timeout=60
        )

        # A failed PowerShell command must produce ERROR.
        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
                or "Firewall rule collection failed."
            )

        # Parse the JSON returned by PowerShell.
        rules = json.loads(result.stdout)

        if not isinstance(rules, list):
            raise ValueError(
                "Expected a list of firewall rules."
            )

        # These fields are mandatory for later correlation.
        required_fields = (
            "Name",
            "DisplayName",
            "Action",
            "Profile",
            "Protocol",
            "LocalPort",
            "LocalAddress",
            "RemoteAddress",
            "Program",
            "Service",
            "InterfaceType",
            "InterfaceAlias",
            "Authentication",
            "Encryption",
            "OverrideBlockRules",
            "LocalUser",
            "RemoteUser",
            "RemoteMachine",
            "EdgeTraversalPolicy"
        )

        # Verify the structure of every collected rule.
        for index, rule in enumerate(rules):

            if not isinstance(rule, dict):
                raise ValueError(
                    f"Invalid firewall rule at index {index}."
                )

            for field in required_fields:

                if not isinstance(rule.get(field), str):
                    raise ValueError(
                        f"Invalid field '{field}' "
                        f"in firewall rule {index}."
                    )

            # Reject unexpected firewall actions.
            if rule["Action"].strip().lower() not in (
                "allow",
                "block"
            ):
                raise ValueError(
                    f"Unsupported firewall action in rule {index}."
                )

            # Empty advanced conditions must not be
            # interpreted as unrestricted permissions.
            for field in (
                "Authentication",
                "Encryption",
                "OverrideBlockRules",
                "InterfaceAlias"
            ):
                if not rule[field].strip():
                    raise ValueError(
                        f"Empty security condition '{field}' "
                        f"in firewall rule {index}."
                    )

    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError
    ) as error:

        # Collection failures must never become PASS.
        return Finding(
            check_id="NET-002",
            title="Inbound firewall rule analysis",
            status="ERROR",
            severity="INFO",
            description=(
                "Unable to collect or validate inbound "
                "Windows Firewall rules."
            ),
            evidence=str(error),
            recommendation=(
                "Verify PowerShell networking cmdlets, "
                "firewall query permissions and filter data."
            )
        )

    # --------------------------------------------------------
    # STEP 5: CLASSIFY FIREWALL RULES
    # --------------------------------------------------------

    # Separate rules by action for subsequent correlation.
    allow_rules = [
        rule
        for rule in rules
        if rule["Action"].strip().lower() == "allow"
    ]

    block_rules = [
        rule
        for rule in rules
        if rule["Action"].strip().lower() == "block"
    ]

    # Broad Allow rules have no restrictions on remote
    # addresses, application or service.
    #
    # Additional firewall conditions may still apply.
    broad_allow_rules = [
        rule
        for rule in allow_rules
        if rule["RemoteAddress"].strip().lower() in ("any", "*")
        and rule["Program"].strip().lower() in ("any", "*")
        and rule["Service"].strip().lower() in ("any", "*")
    ]

    # --------------------------------------------------------
    # STEP 6: RETURN STRUCTURED EVIDENCE
    # --------------------------------------------------------

    # WARN means broad Allow rules were identified.
    # It does not prove actual external reachability.
    return Finding(
        check_id="NET-002",
        title="Inbound firewall rule analysis",
        status="WARN" if broad_allow_rules else "PASS",
        severity="LOW" if broad_allow_rules else "INFO",
        description=(
            f"Inspected {len(rules)} enabled inbound firewall "
            f"rules: {len(allow_rules)} Allow and "
            f"{len(block_rules)} Block. "
            f"Identified {len(broad_allow_rules)} potentially "
            "broad Allow rules."
        ),
        evidence=json.dumps({
            "rule_count": len(rules),
            "allow_count": len(allow_rules),
            "block_count": len(block_rules),
            "broad_allow_count": len(broad_allow_rules),
            "rules": rules
        }),
        recommendation=(
            "Correlate firewall rules with listening services, "
            "active profiles, network interfaces and security "
            "requirements. Verify actual network reachability "
            "before confirming exposure."
        )
    )
