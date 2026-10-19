import json
import unittest

from core.findings import Finding
from core.correlator import correlate


class TestCorrelator(unittest.TestCase):

    def test_smb1_enabled_with_port_445(self):

        # Simulate a Windows machine with SMBv1 enabled.
        smb = Finding(
            check_id="SMB-001",
            title="SMBv1 configuration",
            status="FAIL",
            severity="HIGH",
            description="SMBv1 is enabled.",
            evidence=json.dumps({
                "EnableSMB1Protocol": True
            }),
            recommendation="Disable SMBv1."
        )

        # Simulate TCP port 445 listening.
        network = Finding(
            check_id="NET-001",
            title="Listening TCP services",
            status="WARN",
            severity="LOW",
            description="Port 445 is listening.",
            evidence=json.dumps({
                "connections": [
                    {
                        "LocalAddress": "0.0.0.0",
                        "LocalPort": 445,
                        "OwningProcess": 4,
                        "ProcessName": "System"
                    }
                ]
            }),
            recommendation="Review network exposure."
        )

        # Run the correlation engine using simulated evidence.
        results = correlate([smb, network])

        # Verify that the compound risk was detected.
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].check_id, "COR-001")
        self.assertEqual(results[0].status, "FAIL")
        self.assertEqual(results[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()