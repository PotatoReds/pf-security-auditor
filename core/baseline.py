
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Security Baseline Engine
#
# Purpose:
# Evaluate findings against project-defined security rules.
#
# Supports:
# - Finding status evaluation
# - Individual configuration values in JSON evidence
# - Missing and invalid evidence handling
#
# Security:
# Read-only. Does not modify Windows configuration.
# ============================================================

import json
from pathlib import Path

from core.findings import Finding


def extract_evidence_value(evidence, field_path: str):
    """
    Retrieve a value from nested JSON evidence.

    Example:
        field_path = "server.EnableSMB1Protocol"

    Returns:
        (value, True) when the field exists.
        (None, False) when the field cannot be verified.
    """

    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (ValueError, TypeError):
            return None, False

    current = evidence

    for field in field_path.split("."):
        if not isinstance(current, dict):
            return None, False

        if field not in current:
            return None, False

        current = current[field]

    return current, True


def evaluate_baseline(findings: list[Finding]) -> dict:
    """
    Evaluate findings against config/baseline.json.

    Rules can use either:
    - required_status: compare the overall finding status.
    - evidence_field + expected_value: compare a specific
      configuration value in the finding's evidence.

    Missing evidence must never count as compliance.
    """

    project_root = Path(__file__).resolve().parent.parent
    baseline_path = project_root / "config" / "baseline.json"

    with baseline_path.open("r", encoding="utf-8") as file:
        baseline = json.load(file)

    findings_by_id = {
        finding.check_id: finding
        for finding in findings
    }

    results = []

    for rule in baseline["rules"]:

        check_id = rule["check_id"]
        finding = findings_by_id.get(check_id)

        actual_status = finding.status if finding else None
        actual_value = None

        # Missing check: no basis for compliance.
        if finding is None:
            result = "NOT_ASSESSED"

        # Execution failure: security state is unknown.
        elif finding.status == "ERROR":
            result = "ERROR"

        # Evaluate a specific field from the finding's evidence.
        elif "evidence_field" in rule:

            actual_value, found = extract_evidence_value(
                finding.evidence,
                rule["evidence_field"]
            )

            if not found:
                result = "NOT_ASSESSED"

            elif (
                type(actual_value) is type(rule["expected_value"])
                and actual_value == rule["expected_value"]
            ):
                result = "COMPLIANT"

            else:
                result = "NON_COMPLIANT"

        # Existing rules continue to use status comparison.
        elif finding.status == rule["required_status"]:
            result = "COMPLIANT"

        else:
            result = "NON_COMPLIANT"

        results.append({
            "check_id": check_id,
            "description": rule["description"],
            "required_status": rule.get("required_status"),
            "evidence_field": rule.get("evidence_field"),
            "expected_value": rule.get("expected_value"),
            "actual_status": actual_status,
            "actual_value": actual_value,
            "result": result,
            "severity": rule["severity"]
        })

    assessed = [
        item for item in results
        if item["result"] in ("COMPLIANT", "NON_COMPLIANT")
    ]

    return {
        "baseline_name": baseline["baseline_name"],
        "baseline_version": baseline["baseline_version"],
        "compliant": sum(
            item["result"] == "COMPLIANT"
            for item in results
        ),
        "non_compliant": sum(
            item["result"] == "NON_COMPLIANT"
            for item in results
        ),
        "not_assessed": sum(
            item["result"] == "NOT_ASSESSED"
            for item in results
        ),
        "errors": sum(
            item["result"] == "ERROR"
            for item in results
        ),
        "assessed": len(assessed),
        "rules": results
    }
