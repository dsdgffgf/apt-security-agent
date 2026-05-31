import unittest

from security_log_analyzer import parse_log


class ParseLogTests(unittest.TestCase):
    def test_parse_log_extracts_basic_login_fields(self):
        result = parse_log(
            "2026-05-13 08:00:00 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
        )

        self.assertIn(result.log_type, {"ssh_login", "system_login", "unknown"})
        self.assertGreaterEqual(len(result.records), 1)

        record = result.records[0]
        self.assertEqual(record.ip, "1.2.3.4")
        self.assertEqual(record.username, "root")
        self.assertFalse(record.succeeded)

    def test_parse_log_preserves_web_request_path_with_spaces(self):
        result = parse_log(
            '2026-05-14 10:15:01 access.log: 203.0.113.80 - - '
            '[14/May/2026:10:15:01 +0800] "GET /user?id=1 UNION SELECT username,password FROM users HTTP/1.1" 404 312'
        )

        record = result.records[0]

        self.assertEqual(record.log_type, "web_access")
        self.assertEqual(record.request_method, "GET")
        self.assertIn("UNION SELECT", record.request_path)


if __name__ == "__main__":
    unittest.main()
