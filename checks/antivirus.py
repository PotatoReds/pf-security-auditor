# subprocess allows Python to execute PowerShell commands.
import subprocess

# json converts PowerShell output into Python objects.
import json

# Import Pathfinder's standardized security finding class.
from core.findings import Finding


# Check which antivirus products are registered with Windows.
# This function does not change any system settings.
def check_antivirus() -> Finding:

    # Query Windows Security Center for registered antivirus products.
    # Select only the product name and its reported state.
    # ConvertTo-Json makes the output machine-readable.
    command = (
        "Get-CimInstance -Namespace root/SecurityCenter2 "
        "-ClassName AntivirusProduct -ErrorAction Stop | "
        "Select-Object displayName, productState | "
        "ConvertTo-Json -Compress"
    )

    try:
        # Execute PowerShell and capture its output.
        # A timeout prevents the command from running indefinitely.
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
            timeout=15
        )

    # Handle missing PowerShell or commands that exceed the timeout.
    except (OSError, subprocess.TimeoutExpired) as error:
        return Finding(
            check_id="AV-001",
            title="Antivirus product detection",
            status="ERROR",
            severity="INFO",
            description="Could not execute the antivirus check.",
            evidence=str(error),
            recommendation="Verify PowerShell availability."
        )

    # A failed PowerShell command means the audit is incomplete.
    if result.returncode != 0:
        return Finding(
            check_id="AV-001",
            title="Antivirus product detection",
            status="ERROR",
            severity="INFO",
            description="Could not retrieve antivirus information.",
            evidence=result.stderr.strip(),
            recommendation="Verify access to Windows Security Center."
        )

    try:
        # Convert the returned JSON into Python data.
        products = json.loads(result.stdout)

    # Invalid JSON must not be interpreted as a valid security result.
    except json.JSONDecodeError as error:
        return Finding(
            check_id="AV-001",
            title="Antivirus product detection",
            status="ERROR",
            severity="INFO",
            description="Windows returned invalid antivirus data.",
            evidence=str(error),
            recommendation="Investigate the Security Center query output."
        )

    # PowerShell returns a dictionary for one product,
    # but a list when multiple products are found.
    # Convert both cases into a consistent list.
    if isinstance(products, dict):
        products = [products]

    # Reject unexpected data structures or missing product fields.
    if not isinstance(products, list) or not all(
        isinstance(product, dict)
        and isinstance(product.get("displayName"), str)
        and product["displayName"].strip()
        and type(product.get("productState")) is int
        for product in products
    ):
        return Finding(
            check_id="AV-001",
            title="Antivirus product detection",
            status="ERROR",
            severity="INFO",
            description="Windows returned unexpected antivirus data.",
            evidence=json.dumps(products),
            recommendation="Verify the antivirus query output."
        )

    # An empty list means no antivirus products were returned.
    # This is a potential concern, but not conclusive proof
    # that the system has no endpoint protection.
    if not products:
        return Finding(
            check_id="AV-001",
            title="Antivirus product detection",
            status="WARN",
            severity="MEDIUM",
            description="No antivirus products were reported by Windows Security Center.",
            evidence="No registered antivirus products found.",
            recommendation="Verify that endpoint protection is installed and active."
        )

    # Extract the names of the detected antivirus products.
    product_names = [
        product["displayName"]
        for product in products
    ]

    # Record the detected products without assuming their
    # registration proves that real-time protection is enabled.
    return Finding(
        check_id="AV-001",
        title="Antivirus product detection",
        status="WARN",
        severity="INFO",
        description=(
            "Antivirus products were detected, but their active "
            "protection status has not been independently verified."
        ),
        evidence=json.dumps(products),
        recommendation=(
            "Verify that at least one registered antivirus product "
            "provides active, up-to-date protection."
        )
    )