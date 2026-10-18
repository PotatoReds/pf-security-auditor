# Import tools for creating classes that primarily store data.
# dataclass automatically generates an __init__ method.
# asdict converts a dataclass instance into a dictionary.
from dataclasses import dataclass, asdict

# Literal restricts a type annotation to specific allowed values.
from typing import Literal


# Define the possible outcomes of a security check.
Status = Literal["PASS", "FAIL", "WARN", "ERROR"]

# Define how serious a detected security issue is.
Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


# Automatically generate the constructor and other useful methods.
@dataclass
class Finding:

    # Unique identifier for the security check.
    check_id: str

    # Human-readable name of the finding.
    title: str

    # Result of the check (PASS, FAIL, WARN or ERROR).
    status: Status

    # Risk level associated with the finding.
    severity: Severity

    # Explanation of what was checked or discovered.
    description: str

    # Evidence supporting the result.
    evidence: str

    # Suggested action to address the issue.
    recommendation: str

    # Convert the Finding object into a Python dictionary.
    def to_dict(self) -> dict:
        return asdict(self)