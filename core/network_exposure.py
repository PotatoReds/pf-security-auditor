
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Network Exposure Correlation
# Rule ID: COR-002
#
# Purpose:
# Correlate listening TCP sockets with inbound firewall
# Allow rules to identify potential network exposure.
#
# Security:
# READ-ONLY. No network connections or changes are made.
# ============================================================

import json
import ipaddress

from core.findings import Finding


def port_matches(port: int, specification: str) -> bool:
    """
    Determine whether a TCP port matches a firewall port rule.

    Supported examples:
        Any
        445
        80,443
        8000-8100

    Unknown or symbolic port expressions are not treated
    as matches, avoiding unsupported exposure conclusions.
    """

    for item in specification.split(","):
        item = item.strip()

        if item.lower() in ("any", "*"):
            return True

        # Match an individual numeric port.
        if item.isdigit() and int(item) == port:
            return True

        # Match an inclusive numeric port range.
        if "-" in item:
            parts = item.split("-")

            if len(parts) == 2 and all(
                part.strip().isdigit() for part in parts
            ):
                start, end = map(int, parts)

                if start <= port <= end:
                    return True

    return False


def is_non_loopback(address: str) -> bool:
    """
    Return True for listening addresses that are not
    restricted to the local loopback interface.

    Wildcard bindings (0.0.0.0 and ::) are included,
    because they may accept connections on network
    interfaces subject to operating system behavior.
    """

    try:
        return not ipaddress.ip_address(address).is_loopback
    except ValueError:
        # Unknown address formats cannot be assessed safely.
        return False


def is_unrestricted(value: str) -> bool:
    """
    Identify unrestricted firewall filter values.

    Application-specific and service-specific rules are
    excluded from this initial correlation to avoid
    incorrectly attributing permissions to other processes.
    """

    return value.strip().lower() in ("any", "*")


def correlate_network_exposure(
    findings: list[Finding]
) -> list[Finding]:
    """
    Correlate NET-001 listeners with NET-002 firewall rules.

    Returns:
        A list containing COR-002 when potential exposure
        is identified.

    Important:
        A matching Allow rule is not proof of actual
        network reachability. Blocking rules, active
        profiles and other conditions may override it.
    """

    # --------------------------------------------------------
    # STEP 1: LOCATE REQUIRED SECURITY FINDINGS
    # --------------------------------------------------------

    findings_by_id = {
        finding.check_id: finding
        for finding in findings
    }

    network = findings_by_id.get("NET-001")
    firewall = findings_by_id.get("NET-002")

    # Both checks must have usable evidence.
    if network is None or firewall is None:
        return []

    if network.status == "ERROR" or firewall.status == "ERROR":
        return []

    # --------------------------------------------------------
    # STEP 2: PARSE STRUCTURED EVIDENCE
    # --------------------------------------------------------

    try:
        network_data = json.loads(network.evidence)
        firewall_data = json.loads(firewall.evidence)

        listeners = network_data["connections"]
        rules = firewall_data["rules"]

        if not isinstance(listeners, list):
            return []

        if not isinstance(rules, list):
            return []

    except (ValueError, KeyError, TypeError):
        return []

    # --------------------------------------------------------
    # STEP 3: MATCH LISTENERS TO FIREWALL RULES
    # --------------------------------------------------------

    potential_exposures = []

    for listener in listeners:

        try:
            local_port = int(listener["LocalPort"])
            local_address = str(listener["LocalAddress"])
        except (KeyError, ValueError, TypeError):
            continue

        # A loopback-only service cannot be reached directly
        # through an ordinary external network connection.
        if not is_non_loopback(local_address):
            continue

        for rule in rules:

            # Only consider TCP and protocol-independent rules.
            protocol = str(rule.get("Protocol", "")).lower()

            if protocol not in ("tcp", "6", "any", "256"):
                continue

            # Check whether the rule includes this local port.
            if not port_matches(
                local_port,
                str(rule.get("LocalPort", ""))
            ):
                continue

            # Require unrestricted application and service
            # filters for this conservative first version.
            if not is_unrestricted(str(rule.get("Program", ""))):
                continue

            if not is_unrestricted(str(rule.get("Service", ""))):
                continue

            # Only consider rules permitting any remote source.
            if not is_unrestricted(
                str(rule.get("RemoteAddress", ""))
            ):
                continue

            # Do not assume that address-restricted firewall
            # rules apply to every local listening interface.
            if not is_unrestricted(
                str(rule.get("LocalAddress", ""))
            ):
                continue

            # Record the possible exposure and its evidence.
            potential_exposures.append({
                "port": local_port,
                "address": local_address,
                "process": listener.get("ProcessName", "Unknown"),
                "firewall_rule": rule.get("DisplayName", ""),
                "firewall_profile": rule.get("Profile", ""),
                "interface_type": rule.get("InterfaceType", "")
            })

    # --------------------------------------------------------
    # STEP 4: RETURN CORRELATED SECURITY FINDING
    # --------------------------------------------------------

    if not potential_exposures:
        return []

    # Avoid duplicates caused by multiple matching rules.
    unique_exposures = list({
        (
            item["port"],
            item["address"],
            item["firewall_rule"]
        ): item
        for item in potential_exposures
    }.values())

    return [
        Finding(
            check_id="COR-002",
            title="Potential inbound network exposure",
            status="WARN",
            severity="MEDIUM",
            description=(
                f"Identified {len(unique_exposures)} combinations "
                "of listening TCP sockets and broadly scoped "
                "inbound firewall Allow rules."
            ),
            evidence=json.dumps({
                "potential_exposures": unique_exposures
            }),
            recommendation=(
                "Review the matching firewall rules and "
                "listening services. Verify active firewall "
                "profiles, blocking rules and actual network "
                "reachability before classifying exposure "
                "as a confirmed vulnerability."
            )
        )
    ]
