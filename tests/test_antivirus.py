# Python's built-in testing framework.
import unittest

# Allows us to replace real PowerShell execution with fake results.
from unittest.mock import patch

# Creates an object that behaves like a subprocess result.
from types import SimpleNamespace

# Import Pathfinder's antivirus check.
from checks.antivirus import check_antivirus


class TestAntivirus(unittest.TestCase):

    # TEST 1: Antivirus software is registered in Windows.
    def test_antivirus_registered(self):

        # Simulate Windows Security Center detecting Bitdefender.
        fake_output = (
            '[{"displayName":"Bitdefender Antivirus",'
            '"productState":266240}]'
        )

        # Simulate a successful PowerShell command.
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=fake_output,
            stderr=""
        )

        # Replace PowerShell execution with our simulated response.
        with patch(
            "checks.antivirus.subprocess.run",
            return_value=fake_result
        ):
            finding = check_antivirus()

        # Registration alone cannot confirm active protection.
        self.assertEqual(finding.status, "WARN")

        # This should be an informational warning.
        self.assertEqual(finding.severity, "INFO")

        # Verify the finding belongs to the antivirus check.
        self.assertEqual(finding.check_id, "AV-001")

    # TEST 2: No antivirus products registered in Windows.
    def test_no_antivirus_registered(self):

        # Simulate Windows Security Center returning an empty list.
        # This means no antivirus products were found.
        fake_output = "[]"

        # Simulate a successful PowerShell command.
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=fake_output,
            stderr=""
        )

        # Replace the real PowerShell execution with our fake result.
        # This does not uninstall or disable any antivirus software.
        with patch(
            "checks.antivirus.subprocess.run",
            return_value=fake_result
        ):
            finding = check_antivirus()

        # Pathfinder should warn about the missing registration.
        self.assertEqual(finding.status, "WARN")

        # Missing antivirus registration deserves a higher severity
        # than simply detecting an installed product.
        self.assertEqual(finding.severity, "MEDIUM")

        # Confirm the finding comes from our antivirus module.
        self.assertEqual(finding.check_id, "AV-001")

            # TEST 3: Invalid JSON should produce ERROR.
    def test_invalid_antivirus_json(self):

        # Simulate malformed JSON from Windows Security Center.
        # The closing quotation mark and brace are missing.
        fake_output = '{"displayName": "Bitdefender Antivirus'

        # PowerShell succeeds, but returns unusable data.
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=fake_output,
            stderr=""
        )

        # Replace the real PowerShell command with simulated output.
        with patch(
            "checks.antivirus.subprocess.run",
            return_value=fake_result
        ):
            finding = check_antivirus()

        # Pathfinder must recognize that the data is invalid.
        self.assertEqual(finding.status, "ERROR")

        # Verify the error belongs to the antivirus check.
        self.assertEqual(finding.check_id, "AV-001")


if __name__ == "__main__":
    unittest.main()