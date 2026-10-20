
"""
Pathfinder Security Auditor - Security posture scoring.

This is a project-defined heuristic, not a certified security
rating or a probability that the system is secure.

The score is based on findings, not confirmed exploitability.
"""

PENALTIES = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

# Findings that overlap with more specific checks, or describe
# inventory/uncertainty rather than a confirmed weakness.
#
# These still appear in the report but do not lower the score.
EXCLUDED_CHECKS = {
    "NET-001",   # Listening services inventory
    "NET-002",   # Broad firewall rule inventory
    "NET-003",   # Passive neighbor discovery
    "NET-004",   # Exposure prioritization; firewall uncertain
    "NET-005",   # Software inventory
    "VULN-001",  # Keyword CVE matches, not validated
    "FW-002",    # Network interface/profile inventory
    "COR-002",   # Heuristic firewall correlation
}


def calculate_score(findings: list) -> dict:
    """
    Calculate an explainable score from Finding objects or dicts.

    WARN and FAIL findings may reduce the score.
    PASS, ERROR and informational findings do not.

    ERROR findings are counted separately because unknown
    security state must not be interpreted as safe.
    """
    deductions = []
    errors = 0

    for finding in findings:
        if isinstance(finding, dict):
            data = finding
        else:
            data = finding.to_dict()

        check_id = str(data.get("check_id", "UNKNOWN"))
        status = str(data.get("status", "")).upper()
        severity = str(data.get("severity", "INFO")).upper()

        if status == "ERROR":
            errors += 1
            continue

        if status not in ("WARN", "FAIL"):
            continue

        if check_id in EXCLUDED_CHECKS:
            continue

        penalty = PENALTIES.get(severity, 0)

        if penalty == 0:
            continue

        deductions.append({
            "check_id": check_id,
            "title": data.get("title", check_id),
            "severity": severity,
            "status": status,
            "points": penalty,
        })

    total_deduction = sum(item["points"] for item in deductions)
    score = max(0, 100 - total_deduction)

    if errors:
        rating = "INCOMPLETE"
    elif score >= 90:
        rating = "STRONG"
    elif score >= 75:
        rating = "GOOD"
    elif score >= 50:
        rating = "NEEDS IMPROVEMENT"
    else:
        rating = "HIGH CONCERN"

    return {
        "score": score,
        "max_score": 100,
        "rating": rating,
        "total_deduction": total_deduction,
        "deductions": deductions,
        "errors": errors,
        "method": "Project-defined severity-weighted heuristic",
        "limitations": (
            "Not a measure of exploitability or overall system security. "
            "Overlapping inventory/correlation findings are excluded. "
            "Unknown states and unverified vulnerabilities are not "
            "treated as confirmed weaknesses."
        ),
    }
