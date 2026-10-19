# unittest is Python's built-in framework for automated testing.
import unittest

# patch lets us temporarily replace a real function with a fake one.
# This means we can test without executing actual PowerShell commands.
from unittest.mock import patch

# SimpleNamespace lets us create an object with custom attributes.
from types import SimpleNamespace

# Import the firewall check that we want to test.
from checks.firewall import check_firewall


# Group our firewall tests inside a unittest test class.
class TestFirewall(unittest.TestCase):

    # Test 1: That all enabled firewall profiles produce PASS.
    def test_all_profiles_enabled(self):

        # Simulate the JSON that PowerShell would return.
        # All three profiles are enabled (1 = enabled).
        fake_output = (
            '[{"Name":"Domain","Enabled":1},'
            '{"Name":"Private","Enabled":1},'
            '{"Name":"Public","Enabled":1}]'
        )

        # Create a fake result resembling subprocess.run().
        fake_result = SimpleNamespace(
            returncode=0,   # The command succeeded.
            stdout=fake_output,  # Simulated PowerShell output.
            stderr=""       # No error messages.
        )

        # Temporarily replace subprocess.run in our firewall module.
        # The real PowerShell command will NOT execute.
        with patch(
            "checks.firewall.subprocess.run",
            return_value=fake_result
        ):

            # Run Pathfinder's firewall check against fake data.
            finding = check_firewall()

        # Verify that the scanner reports PASS.
        self.assertEqual(finding.status, "PASS")

        # Verify that the correct security check was executed.
        self.assertEqual(finding.check_id, "FW-001")

    # Test 2: Whether Pathfinder detects a disabled firewall profile.
    def test_public_firewall_disabled(self):

        # Simulate Windows Firewall with the Public profile disabled.
        # Domain and Private remain enabled.
        fake_output = (
            '[{"Name":"Domain","Enabled":1},'
            '{"Name":"Private","Enabled":1},'
            '{"Name":"Public","Enabled":0}]'
        )

        # Simulate a successful PowerShell execution.
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=fake_output,
            stderr=""
        )

        # Replace the actual PowerShell command with our fake result.
        # No real firewall settings are changed.
        with patch(
            "checks.firewall.subprocess.run",
            return_value=fake_result
        ):
            finding = check_firewall()

        # Verify that Pathfinder identifies the insecure configuration.
        self.assertEqual(finding.status, "FAIL")

        # Verify that the finding has the expected severity.
        self.assertEqual(finding.severity, "MEDIUM")

    # TEST 3: Missing firewall profile should return ERROR.
    def test_missing_firewall_profile(self):

        # Simulate PowerShell returning only two firewall profiles.
        # The Public profile is deliberately missing.
        fake_output = (
            '[{"Name":"Domain","Enabled":1},'
            '{"Name":"Private","Enabled":1}]'
        )

        # Simulate a successful PowerShell command.
        # The command succeeds, but its data is incomplete.
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=fake_output,
            stderr=""
        )

        # Replace the actual PowerShell execution with fake data.
        # No Windows security settings are changed.
        with patch(
            "checks.firewall.subprocess.run",
            return_value=fake_result
        ):
            finding = check_firewall()

        # Verify that Pathfinder rejects incomplete evidence.
        self.assertEqual(finding.status, "ERROR")

        # Verify that the correct security check returned the error.
        self.assertEqual(finding.check_id, "FW-001")

    # TEST 4: Invalid PowerShell JSON output should return ERROR.
    def test_invalid_json(self):

        # Simulate malformed JSON returned by PowerShell.
        # This is deliberately not valid JSON.
        fake_output = '{"Name": "Domain", "Enabled":'

        # Simulate a command that succeeded but returned invalid data.
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=fake_output,
            stderr=""
        )

        # Replace the real PowerShell execution with our fake response.
        # This keeps the test independent of the actual Windows Firewall.
        with patch(
            "checks.firewall.subprocess.run",
            return_value=fake_result
        ):
            finding = check_firewall()

        # Verify that invalid JSON produces an ERROR finding.
        self.assertEqual(finding.status, "ERROR")

        # Verify that the result belongs to the correct security check.
        self.assertEqual(finding.check_id, "FW-001")

# Run the tests when this file is executed directly.
if __name__ == "__main__":
    unittest.main()