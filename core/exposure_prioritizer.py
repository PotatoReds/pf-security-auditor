
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: NET-004 - Network Exposure Prioritization
#
# Purpose:
# Prioritize TCP endpoints identified by COR-002 for
# subsequent manual security review.
#
# Method:
# Analyze existing correlation evidence using
# transparent, rule-based prioritization.
#
# Security:
# READ-ONLY. No network traffic is generated.
#
# Limitations:
# - Priority is not a vulnerability severity rating.
# - No external reachability is verified.
# - No exploitation or active scanning is performed.
# ============================================================

import json
from collections import Counter

from core.findings import Finding


# Ports associated with services worth reviewing.
# These are review indicators, not confirmed weaknesses.
REVIEW_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    135: "Windows RPC",
    139: "NetBIOS",
    445: "SMB file sharing",
    3389: "Remote Desktop",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}


def prioritize_endpoint(endpoint: dict) -> dict:
    """
    Assign a review priority to one COR-002 endpoint.

    The rules are deliberately simple so an examiner can
    reproduce and understand every classification.
    """

    status = endpoint.get("status", "INDETERMINATE")
    interface_type = endpoint.get("interface_type", "UNKNOWN")

    try:
        port = int(endpoint["local_port"])
    except (KeyError, TypeError, ValueError):
        port = None

    reasons = []

    # Loopback listeners do not need external exposure
    # verification because they are local to the host.
    if status == "LOCAL_ONLY":
        priority = "LOW"
        reasons.append("Endpoint is restricted to loopback.")

    else:
        score = 0

        # Review administrative and file-sharing services
        # before less recognizable application services.
        if port in REVIEW_PORTS:
            score += 2
            reasons.append(
                f"Port {port} is associated with "
                f"{REVIEW_PORTS[port]}."
            )

        # A normal network interface is a more relevant
        # exposure candidate than an isolated loopback.
        if interface_type == "NETWORK":
            score += 1
            reasons.append(
                "Listener is associated with a network interface."
            )

        # A potentially allowed firewall policy deserves
        # verification, but is not proof of reachability.
        if status == "POTENTIALLY_ALLOWED":
            score += 2
            reasons.append(
                "Firewall correlation found a potential Allow path."
            )

        # Missing evidence increases review urgency.
        if status == "INDETERMINATE":
            score += 1
            reasons.append(
                "Firewall exposure could not be determined."
            )

        if score >= 4:
            priority = "HIGH"
        elif score >= 2:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        if not reasons:
            reasons.append(
                "No additional prioritization indicators identified."
            )

    return {
        "local_ip": endpoint.get("local_ip"),
        "local_port": port,
        "process": endpoint.get("process", "Unknown"),
        "interface": endpoint.get("interface"),
        "interface_type": interface_type,
        "firewall_status": status,
        "firewall_reason": endpoint.get("reason"),
        "review_priority": priority,
        "priority_reasons": reasons,
    }


def prioritize_exposure(findings: list[Finding]) -> Finding:
    """
    Read COR-002 evidence and prioritize its endpoints.

    This function does not repeat firewall rule matching.
    It consumes the existing COR-002 assessment.
    """

    # Locate the previously generated correlation Finding.
    correlation = next(
        (
            finding
            for finding in findings
            if finding.check_id == "COR-002"
        ),
        None
    )

    # Missing or failed correlation evidence prevents
    # reliable prioritization.
    if correlation is None or correlation.status == "ERROR":
        raise ValueError(
            "NET-004 requires a successful COR-002 result."
        )

    # COR-002 stores structured JSON inside evidence.
    data = json.loads(correlation.evidence)

    if data.get("status") != "COMPLETED":
        raise ValueError(
            "COR-002 did not complete successfully."
        )

    endpoints = data.get("endpoints")

    if not isinstance(endpoints, list):
        raise ValueError(
            "COR-002 evidence does not contain an endpoint list."
        )

    # Prioritize each endpoint independently.
    prioritized = [
        prioritize_endpoint(endpoint)
        for endpoint in endpoints
    ]

    # Sort high-priority items first.
    priority_order = {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
    }

    prioritized.sort(
        key=lambda item: (
            priority_order[item["review_priority"]],
            item["local_port"] or 0,
            str(item["local_ip"] or ""),
        )
    )

    # Count the results for the report summary.
    counts = Counter(
        item["review_priority"]
        for item in prioritized
    )

    evidence = {
        "source": "COR-002",
        "method": "Rule-based review prioritization",
        "total_endpoints": len(prioritized),
        "priority_counts": {
            "HIGH": counts["HIGH"],
            "MEDIUM": counts["MEDIUM"],
            "LOW": counts["LOW"],
        },
        "review_ports": REVIEW_PORTS,
        "endpoints": prioritized,
        "limitations": [
            "Priority does not represent confirmed risk.",
            "No external network reachability was tested.",
            "Port numbers alone do not identify actual services.",
            "Priorities are project-defined review heuristics.",
        ],
    }

    # WARN indicates that manual review is recommended.
    # It does not mean a vulnerability was confirmed.
    return Finding(
        check_id="NET-004",
        title="Network exposure review prioritization",
        status="WARN",
        severity="INFO",
        description=(
            f"Prioritized {len(prioritized)} TCP endpoints: "
            f"{counts['HIGH']} high, "
            f"{counts['MEDIUM']} medium, "
            f"{counts['LOW']} low review priority."
        ),
        evidence=json.dumps(evidence, ensure_ascii=False),
        recommendation=(
            "Review high-priority endpoints first. "
            "Use controlled network verification before "
            "concluding that a service is reachable or vulnerable."
        )
    )
