
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Firewall Policy Correlation Engine
# Correlation ID: COR-002
# Version: 2.1
#
# Purpose:
# Correlate listening TCP sockets with Windows Firewall
# rules, executable paths, network profiles and interfaces.
#
# Security:
# READ-ONLY. No system configuration is modified.
#
# Limitations:
# Results describe potential firewall policy behavior.
# They do NOT prove external network reachability.
# ============================================================

import ipaddress
import json
import ntpath


# ============================================================
# STEP 1: NORMALIZATION HELPERS
# ============================================================

def _text(value):
    """Normalize a value for case-insensitive comparisons."""
    return str(value).strip().lower() if value is not None else ""


def _is_any(value):
    """Check whether a firewall condition is unrestricted."""
    return _text(value) in ("any", "*")


def _split_values(value):
    """Split comma-separated Windows Firewall values."""
    return [
        item.strip()
        for item in str(value or "").split(",")
        if item.strip()
    ]


# ============================================================
# STEP 2: FIREWALL RULE MATCHING
# ============================================================

def _protocol_matches(rule):
    """
    Determine whether a firewall rule applies to TCP.

    True:  TCP or unrestricted protocol.
    False: Known non-TCP protocol.
    None:  Unsupported or unknown protocol.
    """
    protocol = _text(rule.get("Protocol"))

    if protocol in ("tcp", "6", "any", "*"):
        return True

    if protocol in ("udp", "17", "icmpv4", "icmpv6"):
        return False

    return None


def _port_matches(rule, listener_port):
    """
    Match a listening TCP port against a firewall rule.

    Supports single ports, comma-separated ports,
    numeric ranges and unrestricted ports.

    Unsupported expressions remain uncertain.
    """
    parts = _split_values(rule.get("LocalPort"))

    if not parts:
        return None

    uncertain = False

    for part in parts:

        if _is_any(part):
            return True

        if part.isdigit():
            if int(part) == listener_port:
                return True
            continue

        if "-" in part:
            bounds = part.split("-", 1)

            if all(value.strip().isdigit() for value in bounds):
                start, end = map(int, bounds)

                if start <= listener_port <= end:
                    return True

                continue

        # Windows supports additional named port formats.
        # Unknown formats must not be assumed irrelevant.
        uncertain = True

    return None if uncertain else False


def _profile_matches(rule_profile, category):
    """
    Compare a firewall rule's profiles with a network
    connection's active category.
    """
    profiles = [_text(p) for p in _split_values(rule_profile)]
    category = _text(category)

    if not profiles:
        return None

    if any(_is_any(p) for p in profiles):
        return True

    if not category:
        return None

    if category == "domainauthenticated":
        category = "domain"

    if category not in ("domain", "private", "public"):
        return None

    return category in profiles


def _address_matches(expression, local_ip):
    """
    Match a firewall rule's LocalAddress condition
    against an endpoint's local IP address.

    Supports exact IP addresses and CIDR networks.
    Windows-specific address keywords remain unknown.
    """
    parts = _split_values(expression)

    if not parts:
        return None

    try:
        target = ipaddress.ip_address(local_ip)
    except ValueError:
        return None

    uncertain = False

    for part in parts:

        if _is_any(part):
            return True

        try:
            network = ipaddress.ip_network(
                part,
                strict=False
            )

            if target in network:
                return True

        except ValueError:
            uncertain = True

    return None if uncertain else False


def _program_matches(rule_program, executable_path):
    """
    Compare a firewall rule's Program condition with
    the executable path collected by NET-001.

    Returns:
        True:
            Rule applies to any program, or paths match.

        False:
            Both paths are known and definitely differ.

        None:
            The comparison cannot be completed reliably.

    Windows executable paths are case-insensitive.

    Environment variables, wildcard paths and special
    Windows application identifiers remain unresolved.
    """

    # A rule without an application restriction can
    # apply to any executable.
    if _is_any(rule_program):
        return True

    # NET-001 may not have access to protected process
    # paths. Missing information is not a mismatch.
    if not executable_path:
        return None

    rule_program = str(rule_program).strip()
    executable_path = str(executable_path).strip()

    # Environment variables such as %SystemRoot%
    # require expansion on the target Windows host.
    # Do not compare them as literal file paths.
    if "%" in rule_program:
        return None

    # Special Windows application identifiers and
    # non-executable expressions are not normal paths.
    if not rule_program.lower().endswith(".exe"):
        return None

    # Normalize Windows path separators, redundant
    # path components and capitalization.
    normalized_rule = ntpath.normcase(
        ntpath.normpath(rule_program)
    )

    normalized_process = ntpath.normcase(
        ntpath.normpath(executable_path)
    )

    # A definite path mismatch excludes this rule
    # from the listening process.
    return normalized_rule == normalized_process


# ============================================================
# STEP 3: NETWORK INTERFACE CLASSIFICATION
# ============================================================

def _classify_interface(address):
    """
    Classify the interface associated with a local IP.

    These classifications provide context, not proof
    of whether remote traffic can reach an endpoint.
    """
    alias = _text(address.get("InterfaceAlias"))
    ip_value = address.get("IPAddress", "")

    try:
        ip = ipaddress.ip_address(ip_value)

        # Loopback traffic remains on the local host.
        if ip.is_loopback:
            return "LOOPBACK"

    except ValueError:
        return "UNKNOWN"

    if "loopback" in alias:
        return "LOOPBACK"

    if "teredo" in alias:
        return "TUNNEL"

    if "vpn" in alias or "wireguard" in alias:
        return "VPN"

    if "vethernet" in alias or "hyper-v" in alias:
        return "VIRTUAL"

    return "NETWORK"


def _listener_addresses(listener, addresses):
    """
    Map a listening socket to compatible local addresses.

    A listener bound to 0.0.0.0 uses IPv4 addresses.
    A listener bound to :: uses IPv6 addresses.

    Dual-stack behavior is not inferred.
    """
    local = str(listener.get("LocalAddress", ""))

    if local in ("0.0.0.0", "::"):

        family = (
            "IPv4"
            if local == "0.0.0.0"
            else "IPv6"
        )

        return [
            address
            for address in addresses
            if address.get("AddressFamily") == family
            and address.get("AddressState") == "Preferred"
        ]

    return [
        address
        for address in addresses
        if address.get("IPAddress") == local
    ]


# ============================================================
# STEP 4: DETERMINE FIREWALL RULE APPLICABILITY
# ============================================================

def _evaluate_rule(
    rule,
    listener_port,
    local_ip,
    category,
    executable_path=None
):
    """
    Determine whether a firewall rule can apply to
    a specific TCP endpoint and owning process.

    False:
        At least one known condition excludes the rule.

    True:
        All evaluated conditions match and remaining
        restrictions are unrestricted.

    None:
        One or more conditions cannot be resolved.

    A definite mismatch always takes precedence
    over unresolved conditions.
    """

    # Evaluate the conditions for which we have evidence.
    conditions = (
        _protocol_matches(rule),
        _port_matches(rule, listener_port),
        _profile_matches(
            rule.get("Profile"),
            category
        ),
        _address_matches(
            rule.get("LocalAddress"),
            local_ip
        ),
        _program_matches(
            rule.get("Program"),
            executable_path
        ),
    )

    # If the rule targets a different program, port,
    # protocol, address or profile, exclude it.
    if False in conditions:
        return False

    # An unresolved condition prevents a confirmed match.
    uncertain = None in conditions

    # These conditions are not yet fully correlated.
    #
    # They may restrict a rule to specific services,
    # interfaces, remote sources or authenticated users.
    restricted_fields = (
        "Service",
        "InterfaceAlias",
        "InterfaceType",
        "RemoteAddress",
        "LocalUser",
        "RemoteUser",
        "RemoteMachine",
    )

    for field in restricted_fields:
        if not _is_any(rule.get(field)):
            uncertain = True

    # IPsec authentication and encryption requirements
    # cannot be confirmed using the current evidence.
    if _text(rule.get("Authentication")) != "notrequired":
        uncertain = True

    if _text(rule.get("Encryption")) != "notrequired":
        uncertain = True

    # Authenticated bypass rules have special precedence.
    # They must not be treated as ordinary Allow rules.
    if _text(rule.get("OverrideBlockRules")) != "false":
        uncertain = True

    return None if uncertain else True


# ============================================================
# STEP 5: EVALUATE A TCP ENDPOINT
# ============================================================

def _evaluate_endpoint(
    listener,
    address,
    rules,
    profiles,
    firewall_profiles
):
    """
    Evaluate potential firewall policy behavior for
    one TCP listener and one local IP address.

    Loopback endpoints are classified separately.
    Unknown profiles and restrictions remain uncertain.
    """

    interface_type = _classify_interface(address)

    # Loopback is not externally routable.
    if interface_type == "LOOPBACK":
        return {
            "status": "LOCAL_ONLY",
            "reason": (
                "Loopback address; not externally routable."
            ),
            "matching_allow_rules": [],
            "matching_block_rules": [],
            "uncertain_rule_count": 0,
        }

    # Determine the network profile for this interface.
    interface_index = address["InterfaceIndex"]
    network_profile = profiles.get(interface_index)

    if network_profile is None:
        return {
            "status": "INDETERMINATE",
            "reason": (
                "No network profile found for interface."
            ),
            "matching_allow_rules": [],
            "matching_block_rules": [],
            "uncertain_rule_count": 0,
        }

    category = _text(
        network_profile.get("NetworkCategory")
    )

    if category == "domainauthenticated":
        category = "domain"

    # Obtain the effective firewall profile configuration.
    firewall_profile = firewall_profiles.get(category)

    if firewall_profile is None:
        return {
            "status": "INDETERMINATE",
            "reason": (
                "Firewall profile configuration unavailable."
            ),
            "matching_allow_rules": [],
            "matching_block_rules": [],
            "uncertain_rule_count": 0,
        }

    # Do not assume Windows Firewall enforces rules
    # when its profile is disabled.
    if not firewall_profile.get("Enabled", False):
        return {
            "status": "INDETERMINATE",
            "reason": (
                "Windows Firewall profile is disabled."
            ),
            "matching_allow_rules": [],
            "matching_block_rules": [],
            "uncertain_rule_count": 0,
        }

    port = int(listener["LocalPort"])
    local_ip = address["IPAddress"]

    # NET-001 now supplies the executable path when
    # Windows permits process inspection.
    executable_path = listener.get("ExecutablePath")

    allows = []
    blocks = []
    uncertain = []

    # Evaluate every enabled inbound firewall rule.
    for rule in rules:

        match = _evaluate_rule(
            rule,
            port,
            local_ip,
            category,
            executable_path
        )

        # A definite mismatch means the rule is irrelevant.
        if match is False:
            continue

        action = _text(rule.get("Action"))

        # Keep unresolved rules separate from confirmed matches.
        if match is None:
            uncertain.append(
                rule.get("Name", "UNKNOWN")
            )
            continue

        if action == "allow":
            allows.append(
                rule.get("Name", "UNKNOWN")
            )

        elif action == "block":
            blocks.append(
                rule.get("Name", "UNKNOWN")
            )

    # Unknown potentially applicable rules may affect
    # the final policy decision.
    if uncertain:

        status = "INDETERMINATE"
        reason = (
            "Potentially applicable firewall rules have "
            "unresolved restrictions."
        )

    elif blocks:

        status = "POTENTIALLY_BLOCKED"
        reason = (
            "Matching inbound Block rule identified."
        )

    elif allows:

        status = "POTENTIALLY_ALLOWED"
        reason = (
            "Matching inbound Allow rule identified; "
            "network reachability is unverified."
        )

    else:

        # If no relevant rules remain, consider the
        # firewall profile's default inbound action.
        default_action = _text(
            firewall_profile.get("DefaultInboundAction")
        )

        if default_action == "block":

            status = "POTENTIALLY_BLOCKED"
            reason = (
                "Default inbound firewall action is Block."
            )

        else:

            status = "INDETERMINATE"
            reason = (
                "No matching rule; default inbound behavior "
                "cannot be established confidently."
            )

    return {
        "status": status,
        "reason": reason,
        "matching_allow_rules": allows,
        "matching_block_rules": blocks,
        "uncertain_rule_count": len(uncertain),
    }


# ============================================================
# STEP 6: CORRELATE ALL SOURCE FINDINGS
# ============================================================

def correlate_firewall_policy(findings):
    """
    Correlate NET-001, NET-002 and FW-002.

    NET-001:
        Listening TCP sockets and owning processes.

    NET-002:
        Enabled inbound Windows Firewall rules.

    FW-002:
        Firewall profiles, network interfaces and IPs.

    Returns:
        A structured correlation result.

    The engine does not execute commands or modify Windows.
    """

    # Index findings by check ID for reliable lookup.
    by_id = {
        finding.check_id: finding
        for finding in findings
    }

    required = (
        "NET-001",
        "NET-002",
        "FW-002"
    )

    # Correlation requires valid source evidence.
    for check_id in required:

        finding = by_id.get(check_id)

        if finding is None or finding.status == "ERROR":
            return {
                "check_id": "COR-002",
                "status": "ERROR",
                "description": (
                    f"Missing or failed source: {check_id}"
                ),
                "endpoints": [],
            }

    try:

        # Parse structured evidence from each source.
        network = json.loads(
            by_id["NET-001"].evidence
        )

        exposure = json.loads(
            by_id["NET-002"].evidence
        )

        policy = json.loads(
            by_id["FW-002"].evidence
        )

        listeners = network["connections"]
        rules = exposure["rules"]
        addresses = policy["IPAddresses"]

        # Map each network interface to its active profile.
        profiles = {
            item["InterfaceIndex"]: item
            for item in policy["NetworkProfiles"]
        }

        # Map firewall configuration by profile name.
        firewall_profiles = {
            _text(item["Name"]): item
            for item in policy["FirewallProfiles"]
        }

        endpoints = []

        # Evaluate every compatible listener/IP combination.
        for listener in listeners:

            candidates = _listener_addresses(
                listener,
                addresses
            )

            for address in candidates:

                assessment = _evaluate_endpoint(
                    listener,
                    address,
                    rules,
                    profiles,
                    firewall_profiles
                )

                # Preserve the underlying endpoint context.
                endpoints.append({
                    "local_ip": address["IPAddress"],
                    "local_port": listener["LocalPort"],
                    "process": listener.get(
                        "ProcessName",
                        "Unknown"
                    ),
                    "executable_path": listener.get(
                        "ExecutablePath"
                    ),
                    "interface": address["InterfaceAlias"],
                    "interface_type": _classify_interface(
                        address
                    ),
                    **assessment,
                })

        # Count endpoint classifications.
        counts = {
            "POTENTIALLY_ALLOWED": 0,
            "POTENTIALLY_BLOCKED": 0,
            "INDETERMINATE": 0,
            "LOCAL_ONLY": 0,
        }

        for endpoint in endpoints:
            counts[endpoint["status"]] += 1

        return {
            "check_id": "COR-002",
            "status": "COMPLETED",
            "description": (
                f"Evaluated {len(endpoints)} "
                "local TCP endpoints."
            ),
            "counts": counts,
            "endpoints": endpoints,
        }

    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError
    ) as error:

        # Correlation failures must be explicit.
        return {
            "check_id": "COR-002",
            "status": "ERROR",
            "description": str(error),
            "endpoints": [],
        }
