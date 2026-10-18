# Import Callable to describe functions that our scanner can execute.
from typing import Callable

# Import our Finding class from core/findings.py.
from core.findings import Finding


# The Scanner class coordinates the execution of security checks.
class Scanner:

    # This method runs automatically when we create a Scanner object.
    def __init__(self):

        # Store security-check functions in a list.
        # Each function must return a Finding object.
        self.checks: list[Callable[[], Finding]] = []


    # Register a new security-check function with the scanner.
    def register(self, check: Callable[[], Finding]) -> None:

        # Add the function to our list without executing it yet.
        self.checks.append(check)


    # Execute every registered security check.
    def run(self) -> list[Finding]:

        # Create an empty list for the results.
        findings = []

        # Loop through all registered check functions.
        for check in self.checks:

            try:
                # Execute the check and collect its result.
                finding = check()
                findings.append(finding)

            except Exception as error:
                # If one check crashes, record the error instead
                # of stopping the entire security audit.
                findings.append(
                    Finding(
                        check_id="SYS-ERROR",
                        title="Security check execution failed",
                        status="ERROR",
                        severity="INFO",
                        description="A security check could not be completed.",
                        evidence=f"{check.__name__}: {error}",
                        recommendation="Investigate the failed security check."
                    )
                )

        # Return all collected results to the caller.
        return findings