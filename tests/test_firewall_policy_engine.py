
# ============================================================
# PATHFINDER SECURITY AUDITOR
# Tests: Firewall Policy Correlation Engine
#
# Purpose:
# Verify firewall rule matching and endpoint decisions
# without changing real Windows Firewall settings.
# ============================================================

import unittest

from core.firewall_policy_engine import (
    _port_matches,
    _protocol_matches,
    _address_matches,
    _evaluate_rule,
    _classify_interface,
)


class TestFirewallPolicyEngine(unittest.TestCase):
    """Test the core firewall correlation helpers."""

    def test_tcp_protocol_matches(self):
        """TCP rules must match TCP listeners."""
        self.assertTrue(
            _protocol_matches({"Protocol": "TCP"})
        )

    def test_udp_protocol_does_not_match(self):
        """UDP rules must not match TCP listeners."""
        self.assertFalse(
            _protocol_matches({"Protocol": "UDP"})
        )

    def test_numeric_port_range(self):
        """A port inside a configured range must match."""
        self.assertTrue(
            _port_matches({"LocalPort": "8000-9000"}, 8080)
        )

    def test_unrelated_port_does_not_match(self):
        """An unrelated numeric port must be excluded."""
        self.assertFalse(
            _port_matches({"LocalPort": "3389"}, 445)
        )

    def test_local_address_matches_cidr(self):
        """A local IP inside a CIDR network must match."""
        self.assertTrue(
            _address_matches("192.168.1.0/24", "192.168.1.20")
        )

    def test_loopback_classification(self):
        """Loopback must be identified as local-only."""
        self.assertEqual(
            _classify_interface({
                "IPAddress": "127.0.0.1",
                "InterfaceAlias": "Loopback Pseudo-Interface 1"
            }),
            "LOOPBACK"
        )

    def test_irrelevant_rule_is_excluded(self):
        """
        A definite port mismatch must exclude a rule
        even when another condition is unresolved.
        """
        rule = {
            "Protocol": "TCP",
            "LocalPort": "3389",
            "Profile": "Any",
            "LocalAddress": "Any",
            "Program": "C:\\Unknown\\service.exe",
            "Service": "Any",
            "InterfaceAlias": "Any",
            "InterfaceType": "Any",
            "RemoteAddress": "Any",
            "LocalUser": "Any",
            "RemoteUser": "Any",
            "RemoteMachine": "Any",
            "Authentication": "NotRequired",
            "Encryption": "NotRequired",
            "OverrideBlockRules": "False",
        }

        self.assertIsNone(
            _evaluate_rule(rule, 3389, "192.168.1.20", "private")
        )

        self.assertFalse(
            _evaluate_rule(rule, 445, "192.168.1.20", "private")
        )


if __name__ == "__main__":
    unittest.main()
