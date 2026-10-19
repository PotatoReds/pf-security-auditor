# Import Python's built-in testing framework.
import unittest

# patch allows us to simulate PowerShell output.
from unittest.mock import patch

# SimpleNamespace creates an object resembling subprocess.run().
from types import SimpleNamespace

# Import the RDP security check.
from checks.rdp import check_rdp


class TestRDP(unittest.TestCase):

    # TEST 1: RDP enabled without NLA should produce HIGH severity.
    def test_rdp_enabled_without_nla(self):

        # Simulate an insecure Windows RDP configuration.
        # RDP is enabled, but NLA authentication is not required.
        fake_output = (
            '{"RDPEnabled":true,"NLARequired":false}'
        )

        # Simulate successful PowerShell execution.
        fake_result = SimpleNamespace(
            returncode=0,
            stdout=fake_output,
            stderr=""
        )

        # Replace actual PowerShell execution with simulated data.
        # This does not change any Windows registry settings.
        with patch(
            "checks.rdp.subprocess.run",
            return_value=fake_result
        ):
            finding = check_rdp()

        # Verify that Pathfinder identifies the misconfiguration.
        self.assertEqual(finding.status, "FAIL")

        # Verify that Pathfinder assigns HIGH severity.
        self.assertEqual(finding.severity, "HIGH")

        # Verify that the correct security check was executed.
        self.assertEqual(finding.check_id, "RDP-001")


if __name__ == "__main__":
    unittest.main()