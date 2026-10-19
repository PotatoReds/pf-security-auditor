# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Security Correlation Engine
#
# Purpose:
# Combine independent security findings to identify
# compound risks that individual checks cannot establish.
#
# This module is READ-ONLY.
# ============================================================

import json

from core.findings import Finding


def correlate(findings: list[Finding]) -> list[Finding]:

    # Store any new correlated findings.
    correlations = []

    # Index findings by their unique check ID.
    findings_by_id = {
        finding.check_id: finding
        for finding in findings
    }

    # Retrieve the SMB and network findings.
    smb = findings_by_id.get("SMB-001")
    network = findings_by_id.get("NET-001")

    # Both checks must have completed successfully.
    if (
        smb is not None
        and network is not None
        and smb.status in ("PASS", "FAIL")
        and network.status in ("PASS", "WARN")
    ):

        try:
            # Read the structured network evidence.
            network_data = json.loads(network.evidence)
            smb_data = json.loads(smb.evidence)

            # Check whether SMBv1 is explicitly enabled.
            smb1_enabled = (
                smb_data["EnableSMB1Protocol"] is True
            )

            # Check whether TCP port 445 is listening.
            smb_listeners = [
                connection
                for connection in network_data["connections"]
                if connection["LocalPort"] == 445
            ]

            # Only generate a correlated finding when
            # both conditions have been confirmed.
            if smb1_enabled and smb_listeners:

                correlations.append(
                    Finding(
                        check_id="COR-001",
                        title="Legacy SMB protocol and listening service",
                        status="FAIL",
                        severity="HIGH",
                        description=(
                            "SMBv1 server support is enabled "
                            "and TCP port 445 is listening. "
                            "This combination warrants urgent "
                            "security review."
                        ),
                        evidence=json.dumps({
                            "source_checks": [
                                "SMB-001",
                                "NET-001"
                            ],
                            "smb1_enabled": True,
                            "smb_listeners": smb_listeners
                        }),
                        recommendation=(
                            "Disable SMBv1 after assessing legacy "
                            "dependencies, and restrict SMB access "
                            "to trusted networks."
                        )
                    )
                )

        except (ValueError, KeyError, TypeError):
            # Malformed evidence must not produce
            # an unsupported security conclusion.
            pass

    return correlations