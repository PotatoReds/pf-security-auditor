# Import libraries for system information, JSON, and timestamps.
import platform
import json
from datetime import datetime, timezone

# Import our scanner engine and Windows Firewall check.
from core.scanner import Scanner
from checks.firewall import check_firewall

# Import our Windows antivirus detection check.
from checks.antivirus import check_antivirus

# Import our JSON report export function.
from core.reporter import save_report

# Import our new Remote Desktop security check.
from checks.rdp import check_rdp

# Import network reconnaissance functionality.
from checks.network import check_network

# Import the SMB security check for analysis.
from checks.smb import check_smb

# Import the user account security check.
from checks.users import check_users

# Import the User Account Control (UAC) security check.
from checks.uac import check_uac

# Import the shared folder security check.
from checks.shares import check_shares

# Import the BitLocker encryption check.
from checks.bitlocker import check_bitlocker

# Import the correlation engine to analyze findings.
from core.correlator import correlate

# Collect basic information about the operating system.
def get_system_info():
    return {
        "operating_system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
    }


# Main entry point for the Pathfinder application.
def main():
    print("=== Pathfinder Security Auditor v0.1 ===")

    # Create an instance of the scanner engine.
    scanner = Scanner()

    # Register the firewall check without executing it yet.
    scanner.register(check_firewall)

    # Register the antivirus check for execution.
    scanner.register(check_antivirus)

    # Register the RDP security check with the scanner.
    scanner.register(check_rdp)

    # Register the network reconnaissance check.
    scanner.register(check_network)

    # Register the SMB security check for execution.
    scanner.register(check_smb)

    # Register the user account security check.
    scanner.register(check_users)

    # Register the User Account Control (UAC) security check.
    scanner.register(check_uac)

    # Register the shared folder security check.
    scanner.register(check_shares)

    # Register the BitLocker encryption check.
    scanner.register(check_bitlocker)

    # Execute all registered checks and collect their findings.
    findings = scanner.run()

    # Analyze relationships between independent security checks.
    correlated_findings = correlate(findings)

    # Include correlated risks in the final report.
    findings.extend(correlated_findings)

    # Convert Finding objects into dictionaries for JSON serialization.
    finding_results = [finding.to_dict() for finding in findings]

    # Build the report using the collected security findings.
    report = {
        "scanner": "Pathfinder Internal Auditor",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": get_system_info(),
        "findings": finding_results,
    }

    # Convert the report to formatted JSON and display it.
    print(json.dumps(report, indent=4))

    # Save the same report to the reports directory.
    report_path = save_report(report)

    # Show the user where the report was saved.
    print(f"\nReport saved to: {report_path}")


# Only start Pathfinder when this file is executed directly.
# This prevents main() from running automatically if imported elsewhere.
if __name__ == "__main__":
    main()