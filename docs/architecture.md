# Pathfinder Security Auditor – Architecture

Pathfinder Security Auditor is a modular, host-based security auditing tool designed to identify and document security misconfigurations on Linux systems.

## Components

- **Core:** Coordinates security checks and structures findings.
- **Checks:** Independent modules for system configuration, firewall, network services, SSH and user privileges.
- **Reports:** Stores structured JSON scan results locally.
- **Tests:** Contains automated tests for scanner functionality.

## Design principles

- Read-only security auditing
- Modular and extensible architecture
- Reproducible, rule-based security checks
- Structured reporting
- Separation of data collection and future AI-assisted analysis

## Future development

The architecture is intended to support external network scanning, Windows auditing and AI-assisted penetration testing in isolated environments.

These features are not implemented in the initial version.