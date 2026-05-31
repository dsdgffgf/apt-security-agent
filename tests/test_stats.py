import unittest

from security_log_analyzer.parser import parse_log
from security_log_analyzer.stats import count_failed_login, generate_summary_data


SAMPLE_LOG = """\
2026-05-13 08:00:00 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:05 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:10 sshd[123]: Accepted password for root from 1.2.3.4 port 22 ssh2
2026-05-13 09:00:00 10.0.0.1 - - [13/May/2026:09:00:00 +0800] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"
"""


class SummaryStatsTests(unittest.TestCase):
    def test_generate_summary_data_counts_events_and_top_items(self):
        records = parse_log(SAMPLE_LOG).records
        summary = generate_summary_data(records)

        self.assertEqual(summary.total_events, 4)
        self.assertEqual(summary.success_events, 2)
        self.assertEqual(summary.failure_events, 2)
        self.assertEqual(summary.ip_count, 2)
        self.assertEqual(summary.account_count, 1)
        self.assertEqual(summary.top_ips[0].key, "1.2.3.4")
        self.assertEqual(summary.top_ips[0].count, 3)
        self.assertEqual(summary.high_risk_accounts[0].key, "root")
        self.assertIsNotNone(summary.time_start)
        self.assertIsNotNone(summary.time_end)

    def test_count_failed_login_groups_by_ip_and_account(self):
        records = parse_log(SAMPLE_LOG).records
        failed = count_failed_login(records)

        self.assertEqual(failed.by_ip[0].key, "1.2.3.4")
        self.assertEqual(failed.by_ip[0].count, 2)
        self.assertEqual(failed.by_account[0].key, "root")
        self.assertEqual(failed.by_account[0].count, 2)
        self.assertEqual(len(failed.events), 2)

    def test_generate_summary_data_treats_database_accounts_as_high_risk(self):
        records = parse_log(
            "2026-05-13 10:00:00 sshd[123]: Failed password for postgres from 1.2.3.4 port 22 ssh2\n"
            "2026-05-13 10:01:00 sshd[123]: Failed password for mysql from 1.2.3.5 port 22 ssh2"
        ).records

        summary = generate_summary_data(records)

        self.assertEqual([item.key for item in summary.high_risk_accounts], ["postgres", "mysql"])


if __name__ == "__main__":
    unittest.main()
