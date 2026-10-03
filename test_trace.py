import unittest
from pathlib import Path

from nettrace import analyze, load_calls, related_calls, search

CALLS = load_calls(Path(__file__).with_name("calls.csv"))


def alert_text(query):
    kind, seeds = search(CALLS, query)
    return " | ".join(m for _, m in analyze(related_calls(CALLS, kind, query, seeds)))


class TraceTests(unittest.TestCase):
    def test_search_kinds(self):
        self.assertEqual(search(CALLS, "call001")[0], "Call ID")
        self.assertEqual(search(CALLS, "192.168.1.20")[0], "IP")
        self.assertEqual(search(CALLS, "device-b")[0], "Device")
        self.assertEqual(search(CALLS, "nothing")[0], None)

    def test_device_as_destination_is_related(self):
        kind, seeds = search(CALLS, "Device-B")
        ids = {c.call_id for c in related_calls(CALLS, kind, "Device-B", seeds)}
        self.assertIn("CALL017", ids)  # Device-H called Device-B

    def test_burst_detected(self):
        self.assertIn("Multiple calls detected", alert_text("CALL001"))

    def test_location_jump_detected(self):
        self.assertIn("Location jump", alert_text("Device-G"))

    def test_shared_ip_detected(self):
        self.assertIn("Shared IP", alert_text("203.0.113.45"))

    def test_short_calls_detected(self):
        self.assertIn("very short", alert_text("Device-I"))

    def test_normal_device_clean(self):
        text = alert_text("Device-H")
        self.assertNotIn("Multiple calls", text)
        self.assertNotIn("Location jump", text)


if __name__ == "__main__":
    unittest.main()
