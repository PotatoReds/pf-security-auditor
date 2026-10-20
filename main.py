
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
from core.reporter import save_report, save_html_report

# Correlator combines independent findings to identify
# compound security risks.
from core.correlator import correlate

# COR-002: Correlate listening TCP services with inbound
# firewall rules, network addresses and active profiles.
from core.firewall_policy_engine import correlate_firewall_policy

# Baseline engine evaluates findings against security policies
# defined in config/baseline.json.
from core.baseline import evaluate_baseline

# Finding is Pathfinder's common format for security results.
from core.findings import Finding

# Prioritize TCP exposure based on firewall rules, network
from core.exposure_prioritizer import prioritize_exposure

# Calculate the overall security score based on findings and baseline results.
from core.scoring import calculate_score

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

# Microsoft Defender configuration assessment.
from checks.defender import check_defender

# Network discovery check to identify network interfaces and addresses.
from checks.network_discovery import check_network_discovery

# Software inventory check to enumerate installed applications and versions.
from checks.software_inventory import check_software_inventory

# Vulnerability assessment check to identify known vulnerabilities.
from checks.vulnerability import check_vulnerabilities

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
    scanner.register(check_defender)
    scanner.register(check_network_discovery)
    scanner.register(check_software_inventory)
    scanner.register(check_vulnerabilities)
  
    # --------------------------------------------------------
    # STEP 2: EXECUTE SECURITY CHECKS
    # --------------------------------------------------------

    # Execute each registered check and collect its Finding.
    #
    # The scanner handles individual check exceptions so
    # a failed check does not stop the entire assessment.
    findings = scanner.run()

 # --------------------------------------------------------
    # STEP 3A: GENERAL SECURITY CORRELATIONS
    # --------------------------------------------------------

    # Identify compound risks such as SMBv1 combined with
    # listening SMB services, or unencrypted portable devices.
    general_correlations = correlate(findings)

    # Add the new findings to the overall assessment.
    findings.extend(general_correlations)


    # --------------------------------------------------------
    # STEP 3B: FIREWALL POLICY CORRELATION (COR-002)
    # --------------------------------------------------------

    # Run the firewall correlation engine.
    # It returns a dictionary containing its analysis.
    firewall_result = correlate_firewall_policy(findings)

    # Preserve the complete correlation result as JSON evidence.
    # This includes endpoint classifications and supporting details.
    firewall_evidence = json.dumps(
        firewall_result,
        ensure_ascii=False
    )

    # The engine uses COMPLETED/ERROR, whereas Pathfinder uses
    # PASS/FAIL/WARN/ERROR. COMPLETED means analysis finished,
    # not necessarily that every endpoint is secure.
    engine_status = firewall_result.get("status")

    if engine_status == "ERROR":
        correlation_status = "ERROR"
        correlation_severity = "MEDIUM"
    else:
        # A completed correlation is informational until the
        # endpoint classifications have been evaluated.
        correlation_status = "WARN"
        correlation_severity = "INFO"

    # Convert the dictionary into Pathfinder's Finding format.
    firewall_finding = Finding(
        check_id="COR-002",
        title="Firewall policy and TCP exposure correlation",
        status=correlation_status,
        severity=correlation_severity,
        description=firewall_result.get(
            "description",
            "Firewall correlation completed."
        ),
        evidence=firewall_evidence,
        recommendation=(
            "Review potentially exposed and indeterminate TCP "
            "endpoints. Verify actual network reachability through "
            "controlled testing before concluding that a service "
            "is externally accessible."
        )
    )

    # Append exactly one Finding object.
    # Do not use extend() on the engine's dictionary.
    findings.append(firewall_finding)

    # NET-004 uses COR-002 evidence to prioritize endpoints
    # without performing additional network scans.
    try:
        exposure_priority = prioritize_exposure(findings)
        findings.append(exposure_priority)

    except Exception as error:
        # Keep the audit running if prioritization fails.
        findings.append(
            Finding(
                check_id="NET-004",
                title="Network exposure review prioritization",
                status="ERROR",
                severity="INFO",
                description="Exposure prioritization could not be completed.",
                evidence=f"{type(error).__name__}: {error}",
                recommendation="Inspect COR-002 evidence and retry."
            )
        )

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
        "baseline": baseline_results,

        # Calculate the security posture score from the findings.
        "security_score": calculate_score(findings)
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
    html_path = save_html_report(report, report_path)

    print(f"\nJSON report saved to: {report_path}")
    print(f"HTML report saved to: {html_path}")

# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

# Only execute main() when this file is run directly.
#
# This prevents Pathfinder from automatically starting when
# main.py is imported by another Python module or test.
if __name__ == "__main__":
    main()
