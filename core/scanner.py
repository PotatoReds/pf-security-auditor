# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Scanner
#
# Purpose:
# Register and execute security checks independently.
#
# Error handling:
# - One failed check must not stop the entire audit.
# - Preserve the original check ID when a check fails.
# - Record failures as Finding objects with status ERROR.
# - Validate that checks return the expected Finding type.
#
# This module does not modify the audited system.
# ============================================================

from typing import Callable

from core.findings import Finding


class Scanner:
    """
    Coordinates the execution of registered security checks.

    Each check must be a callable that returns a Finding object.
    """

    def __init__(self):

        # Store the registered check functions.
        self.checks: list[Callable[[], Finding]] = []

    def register(self, check: Callable[[], Finding]) -> None:
        """
        Register a security check for later execution.
        """

        self.checks.append(check)

    def run(self) -> list[Finding]:
        """
        Execute all registered checks.

        A failed check is converted into an ERROR Finding,
        allowing the remaining checks to continue.
        """

        findings: list[Finding] = []

        for check in self.checks:

            # Use the check function's name for diagnostics.
            check_name = getattr(check, "__name__", "unknown_check")

            # Our checks follow the naming convention:
            # check_firewall, check_network, etc.
            #
            # The actual check ID is normally defined inside
            # the Finding returned by each check.
            #
            # If the check crashes before returning, Python
            # cannot recover that ID automatically.
            #
            # We therefore maintain an explicit mapping.
            check_ids = {
                "check_system": "SYS-001",
                "check_firewall": "FW-001",
                "check_firewall_policy": "NET-002",
                "check_antivirus": "AV-001",
                "check_rdp": "RDP-001",
                "check_network": "NET-001",
                "check_exposure": "FW-002",
                "check_smb": "SMB-001",
                "check_users": "USR-001",
                "check_uac": "UAC-001",
                "check_shares": "SHARE-001",
                "check_bitlocker": "BL-001",
                "check_defender": "DEF-001",
            }

            # Resolve the expected ID before executing the check.
            expected_check_id = check_ids.get(
                check_name,
                "SYS-ERROR"
            )

            try:
                # Execute the security check.
                finding = check()

                # Reject invalid return values rather than
                # silently adding them to the report.
                if not isinstance(finding, Finding):
                    raise TypeError(
                        f"{check_name} returned "
                        f"{type(finding).__name__}, expected Finding."
                    )

                findings.append(finding)

            except Exception as error:

                # Preserve the original check ID so the baseline
                # can distinguish ERROR from NOT_ASSESSED.
                findings.append(
                    Finding(
                        check_id=expected_check_id,
                        title=f"Security check failed: {check_name}",
                        status="ERROR",
                        severity="INFO",
                        description=(
                            "The security check could not be completed. "
                            "Its security state remains unknown."
                        ),
                        evidence=(
                            f"Check: {check_name}\n"
                            f"Error type: {type(error).__name__}\n"
                            f"Error message: {error}"
                        ),
                        recommendation=(
                            "Investigate the execution error and "
                            "rerun the security check."
                        )
                    )
                )

        return findings