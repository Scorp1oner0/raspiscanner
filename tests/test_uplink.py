import unittest
from unittest import mock

from scapy.all import ICMP, IP

from scanner import config
from scanner.discovery import uplink


def _reply(src, icmp_type):
    return IP(src=src, dst="192.168.1.5") / ICMP(type=icmp_type)


class TestHopParsing(unittest.TestCase):
    def test_time_exceeded_is_a_hop(self):
        self.assertEqual(uplink.parse_hop_reply(_reply("192.168.1.1", 11)), ("hop", "192.168.1.1"))

    def test_echo_reply_means_the_target_was_reached(self):
        self.assertEqual(uplink.parse_hop_reply(_reply("1.1.1.1", 0)), ("reached", "1.1.1.1"))

    def test_unreachable_is_blocked(self):
        self.assertEqual(uplink.parse_hop_reply(_reply("10.0.0.1", 3)), ("blocked", "10.0.0.1"))

    def test_nothing_or_other_icmp_is_ignored(self):
        self.assertEqual(uplink.parse_hop_reply(None), (None, None))
        self.assertEqual(uplink.parse_hop_reply(_reply("10.0.0.1", 8)), (None, None))

    def test_private_and_public(self):
        for ip in ("10.1.2.3", "192.168.0.1", "172.20.10.1", "169.254.1.1", "100.64.3.2"):
            self.assertTrue(uplink.is_private(ip), ip)
        for ip in ("1.1.1.1", "8.8.8.8", "151.5.0.1"):
            self.assertFalse(uplink.is_private(ip), ip)
        self.assertFalse(uplink.is_private("not-an-ip"))


class TestTrace(unittest.TestCase):
    def setUp(self):
        for target, value in (
            (uplink.platform_net, "has_raw_socket_access"),
        ):
            patcher = mock.patch.object(target, value, return_value=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(uplink.platform_net, "egress_ip_for", return_value="192.168.1.5")
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(uplink.scapy_conf.route, "resync")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _trace(self, replies):
        with mock.patch.object(uplink, "sr1", side_effect=replies):
            return uplink.trace_uplink(target="1.1.1.1", max_hops=8, hop_timeout=0.01)

    def test_stops_at_the_first_public_hop(self):
        result = self._trace([_reply("192.168.88.2", 11), _reply("192.168.1.1", 11), _reply("151.5.0.1", 11),
                              _reply("151.5.0.2", 11)])
        self.assertEqual([h["ip"] for h in result["hops"]], ["192.168.88.2", "192.168.1.1", "151.5.0.1"])
        self.assertEqual([h["private"] for h in result["hops"]], [True, True, False])
        self.assertTrue(result["internet"])
        self.assertFalse(result["reached"])

    def test_reaching_the_target(self):
        result = self._trace([_reply("192.168.1.1", 11), _reply("1.1.1.1", 0)])
        self.assertTrue(result["reached"])
        self.assertTrue(result["internet"])

    def test_private_path_that_never_goes_public(self):
        result = self._trace([_reply("10.0.0.1", 11), _reply("10.0.1.1", 11), None, None, None])
        self.assertEqual([h["ip"] for h in result["hops"]], ["10.0.0.1", "10.0.1.1"])
        self.assertFalse(result["internet"])

    def test_silent_hop_in_the_middle_is_kept(self):
        result = self._trace([_reply("192.168.1.1", 11), None, _reply("151.5.0.1", 11)])
        self.assertEqual([h["ip"] for h in result["hops"]], ["192.168.1.1", None, "151.5.0.1"])

    def test_no_answer_at_all_returns_none(self):
        self.assertIsNone(self._trace([None, None, None]))

    def test_switched_off_without_target(self):
        with mock.patch.object(config, "UPLINK_TRACE_TARGET", ""):
            self.assertIsNone(uplink.trace_uplink())

    def test_no_route_returns_none(self):
        with mock.patch.object(uplink.platform_net, "egress_ip_for", return_value=None):
            self.assertIsNone(uplink.trace_uplink(target="1.1.1.1"))

    def test_sending_failure_returns_none(self):
        with mock.patch.object(uplink, "sr1", side_effect=OSError("no socket")):
            self.assertIsNone(uplink.trace_uplink(target="1.1.1.1", hop_timeout=0.01))


if __name__ == "__main__":
    unittest.main()
