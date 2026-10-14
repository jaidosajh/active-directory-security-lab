from pathlib import Path
import unittest
from tools.triage_events import detect, load_events

ROOT = Path(__file__).resolve().parents[1]


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "samples/events.jsonl").read_text()

    def test_fixture_has_expected_findings(self):
        result = detect(self.text)
        self.assertEqual(result["events_parsed"], 8)
        self.assertEqual([f["rule"] for f in result["findings"]], [
            "SECURITY_GROUP_MEMBERSHIP_CHANGE", "POWERSHELL_SCRIPT_BLOCK_REVIEW", "FAILED_LOGON_BURST"])
        burst = result["findings"][2]
        self.assertEqual(burst["event_count"], 5)
        self.assertEqual(burst["source_ip"], "10.50.0.31")

    def test_login_burst_requires_five_events_within_five_minutes(self):
        five = '\n'.join(self.text.splitlines()[1:6])
        self.assertIn("FAILED_LOGON_BURST", {f["rule"] for f in detect(five)["findings"]})
        four = '\n'.join(self.text.splitlines()[1:5])
        self.assertNotIn("FAILED_LOGON_BURST", {f["rule"] for f in detect(four)["findings"]})

    def test_outside_window_does_not_trigger(self):
        rows = [self.text.splitlines()[1]]
        for minute in range(6, 10):
            rows.append('{"timestamp":"2026-01-15T12:%02d:00Z","event_id":4625,"source_ip":"10.50.0.31"}' % minute)
        self.assertNotIn("FAILED_LOGON_BURST", {f["rule"] for f in detect('\n'.join(rows))["findings"]})

    def test_failed_logons_without_source_are_not_correlated(self):
        rows = [line.replace('"source_ip":"10.50.0.31",', '') for line in self.text.splitlines()[1:6]]
        self.assertNotIn("FAILED_LOGON_BURST", {f["rule"] for f in detect('\n'.join(rows))["findings"]})

    def test_case_insensitive_power_shell_indicator(self):
        event = '{"event_id":4104,"script_block_text":"invoke-expression"}'
        self.assertEqual(detect(event)["findings"][0]["rule"], "POWERSHELL_SCRIPT_BLOCK_REVIEW")

    def test_group_membership_finding_requests_review(self):
        event = '{"event_id":4728,"group":"Domain Admins","target_user":"lab-user"}'
        finding = detect(event)["findings"][0]
        self.assertEqual(finding["rule"], "SECURITY_GROUP_MEMBERSHIP_CHANGE")
        self.assertIn("Confirm whether", finding["review"])

    def test_non_matching_events_do_not_alert(self):
        self.assertEqual(detect('{"event_id":4624}')['findings'], [])
        self.assertEqual(detect('{"event_id":4104,"script_block_text":"Write-Output hello"}')['findings'], [])

    def test_bad_json_and_event_ids_rejected(self):
        for bad in ['', '{', '[]', '{"event_id":"4625"}', '{"event_id":true}', '{"event_id":99999}']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                load_events(bad)

    def test_invalid_address_timestamp_and_field_types_rejected(self):
        for bad in ['{"event_id":1,"source_ip":"999.1.1.1"}',
                    '{"event_id":1,"timestamp":"2026-01-15T12:00:00"}',
                    '{"event_id":1,"timestamp":"not-a-date"}',
                    '{"event_id":1,"group":4}']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                load_events(bad)

    def test_missing_timestamp_is_allowed_for_non_correlated_events(self):
        self.assertEqual(detect('{"event_id":4624}')['events_parsed'], 1)


if __name__ == "__main__":
    unittest.main()
