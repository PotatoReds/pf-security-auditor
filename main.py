
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Module: Main Application
# Version: 0.2
#
# Purpose:
# Coordinate Pathfinder's security assessment workflow:
#
# 1. Collect basic operating system information.
# 2. Execute registered Windows security checks.
# 3. Correlate findings to identify compound security risks.
# 4. Evaluate findings against a configurable security baseline.
# 5. Generate and save a structured JSON security report.
#
# Security:
# This application performs read-only security assessments.
# It does not modify Windows security configurations.
# ============================================================


# ------------------------------------------------------------
# STANDARD PYTHON LIBRARIES
# ------------------------------------------------------------

# Retrieve basic operating system information.
import platform

# Convert Python dictionaries into formatted JSON.
import json

# Generate timestamps for security reports.
from datetime import datetime, timezone


# ------------------------------------------------------------
# PATHFINDER CORE COMPONENTS
# ------------------------------------------------------------

# Scanner manages and executes registered security checks.
from core.scanner import Scanner

# Reporter saves security assessments as JSON files.
from core.reporter import save_report

# Correlator combines independent findings to identify
# compound security risks.
from core.correlator import correlate

# Baseline engine evaluates findings against security policies
# defined in config/baseline.json.
from core.baseline import evaluate_baseline


# ------------------------------------------------------------
# WINDOWS SECURITY CHECKS
# ------------------------------------------------------------

# SYS-001: Identify whether the host is a desktop, laptop,
# virtual machine, server, or another device type.
from checks.system import check_system

# FW-001: Verify Windows Firewall profile configuration.
from checks.firewall import check_firewall

# FW-002: Collect firewall profiles and network context.
from checks.firewall_policy import check_firewall_policy

# AV-001: Identify registered antivirus products.
from checks.antivirus import check_antivirus

# RDP-001: Inspect Remote Desktop and NLA configuration.
from checks.rdp import check_rdp

# NET-001: Enumerate listening TCP services.
from checks.network import check_network

# NET-002: Inspect enabled inbound Windows Firewall rules.
from checks.exposure import check_exposure

# SMB-001: Determine whether SMBv1 server support is enabled.
from checks.smb import check_smb

# USR-001: Enumerate members of the local Administrators group.
from checks.users import check_users

# UAC-001: Inspect User Account Control security settings.
from checks.uac import check_uac

# SHARE-001: Inspect SMB shares and broad share permissions.
from checks.shares import check_shares

# BL-001: Assess BitLocker encryption and protection status.
from checks.bitlocker import check_bitlocker

# ============================================================
# FUNCTION: GET SYSTEM INFORMATION
# ============================================================

def get_system_info() -> dict:
    """
    Collect basic operating system information.

    This provides context for the security report and helps
    identify the platform on which Pathfinder was executed.

    Returns:
        Dictionary containing OS name, release and architecture.
    """

    return {
        "operating_system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine()
    }


# ============================================================
# FUNCTION: MAIN
# ============================================================

def main() -> None:
    """
    Execute the complete Pathfinder security assessment.

    The workflow is divided into five stages:
        1. Register and execute checks.
        2. Correlate findings.
        3. Evaluate baseline compliance.
        4. Construct the security report.
        5. Display and save the report.
    """

    print("=== Pathfinder Security Auditor v0.2 ===")

    # --------------------------------------------------------
    # STEP 1: INITIALIZE THE SCANNER
    # --------------------------------------------------------

    # Create the scanner object that manages security checks.
    scanner = Scanner()

    # Register each check with the scanner.
    #
    # Registration does not execute the checks immediately.
    # It adds them to the scanner's execution list.

    scanner.register(check_system)
    scanner.register(check_firewall)
    scanner.register(check_antivirus)
    scanner.register(check_rdp)
    scanner.register(check_network)
    scanner.register(check_exposure)
    scanner.register(check_firewall_policy)
    scanner.register(check_smb)
    scanner.register(check_users)
    scanner.register(check_uac)
    scanner.register(check_shares)
    scanner.register(check_bitlocker)
  
    # --------------------------------------------------------
    # STEP 2: EXECUTE SECURITY CHECKS
    # --------------------------------------------------------

    # Execute each registered check and collect its Finding.
    #
    # The scanner handles individual check exceptions so
    # a failed check does not stop the entire assessment.
    findings = scanner.run()

    # --------------------------------------------------------
    # STEP 3: CORRELATE SECURITY FINDINGS
    # --------------------------------------------------------

    # The correlation engine evaluates relationships between
    # findings that may indicate additional security risks.
    #
    # Example:
    # SYS-001 identifies a portable computer.
    # BL-001 identifies an unencrypted volume.
    # COR-006 identifies the combined physical security risk.
    correlated_findings = correlate(findings)

    # Add correlated risks to the original findings.
    # These become part of the final security report.
    findings.extend(correlated_findings)

    # --------------------------------------------------------
    # STEP 4: EVALUATE SECURITY BASELINE
    # --------------------------------------------------------

    # Compare findings against the project-defined baseline.
    #
    # The baseline engine determines whether each requirement
    # is COMPLIANT, NON_COMPLIANT, NOT_ASSESSED or ERROR.
    #
    # Baseline requirements are stored separately in:
    # config/baseline.json
    baseline_results = evaluate_baseline(findings)

    # --------------------------------------------------------
    # STEP 5: PREPARE THE SECURITY REPORT
    # --------------------------------------------------------

    # Convert Finding objects into standard dictionaries.
    #
    # Python's JSON serializer cannot directly serialize
    # our custom Finding objects.
    finding_results = [
        finding.to_dict()
        for finding in findings
    ]

    # Construct the complete machine-readable assessment.
    #
    # Keeping findings and baseline results separate allows
    # other applications to process them independently.
    report = {
        "scanner": "Pathfinder Internal Auditor",
        "version": "0.2",
        "timestamp": datetime.now(timezone.utc).isoformat(),

        # Basic operating system details.
        "system": get_system_info(),

        # Results of individual checks and correlation rules.
        "findings": finding_results,

        # Assessment against the configured security policy.
        "baseline": baseline_results
    }

    # --------------------------------------------------------
    # STEP 6: DISPLAY THE SECURITY REPORT
    # --------------------------------------------------------

    # Display the complete JSON assessment in the terminal.
    #
    # This is useful during development and debugging.
    # Later, we can replace it with a concise summary while
    # preserving the full JSON report on disk.
    print(json.dumps(report, indent=4))

    # --------------------------------------------------------
    # STEP 7: SAVE THE SECURITY REPORT
    # --------------------------------------------------------

    # Save the complete report to the reports/ directory.
    #
    # The reporter generates a timestamped filename so
    # previous assessments are not overwritten.
    report_path = save_report(report)

    # Confirm the output location to the user.
    print(f"\nReport saved to: {report_path}")


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

# Only execute main() when this file is run directly.
#
# This prevents Pathfinder from automatically starting when
# main.py is imported by another Python module or test.
if __name__ == "__main__":
    main()
