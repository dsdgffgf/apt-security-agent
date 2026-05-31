import unittest

from security_log_analyzer.detectors import (
    detect_abnormal_ip,
    detect_bruteforce,
    detect_success_after_failures,
    detect_web_attack,
    risk_score,
)
from security_log_analyzer.parser import parse_log
from security_log_analyzer.stats import generate_summary_data


SAMPLE_LOG = """\
2026-05-13 08:00:00 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:05 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:10 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:00:15 sshd[123]: Accepted password for root from 1.2.3.4 port 22 ssh2
2026-05-13 08:01:00 sshd[123]: Failed password for guest from 5.6.7.8 port 22 ssh2
2026-05-13 08:01:05 sshd[123]: Failed password for test from 5.6.7.8 port 22 ssh2
2026-05-13 08:01:10 sshd[123]: Failed password for admin from 5.6.7.8 port 22 ssh2
2026-05-13 08:02:00 8.8.8.8 - - [13/May/2026:08:02:00 +0800] "GET /?id=1%20union%20select%201,2 HTTP/1.1" 200 100 "-" "curl/8.0"
2026-05-13 08:02:05 8.8.8.8 - - [13/May/2026:08:02:05 +0800] "GET /../../etc/passwd HTTP/1.1" 404 50 "-" "curl/8.0"
2026-05-13 08:02:10 8.8.8.8 - - [13/May/2026:08:02:10 +0800] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 100 "-" "curl/8.0"
"""


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.records = parse_log(SAMPLE_LOG).records
        self.summary = generate_summary_data(self.records)

    def test_detect_bruteforce_and_success_after_failures(self):
        brute = detect_bruteforce(self.records)
        success = detect_success_after_failures(self.records)

        self.assertTrue(any(item.kind == "bruteforce" and item.ip == "1.2.3.4" for item in brute))
        self.assertTrue(any(item.kind == "bruteforce" and item.ip == "5.6.7.8" for item in brute))
        self.assertTrue(
            any(
                item.kind == "success_after_failures"
                and item.ip == "1.2.3.4"
                and item.account == "root"
                and item.details["prior_failures"] >= 3
                for item in success
            )
        )

    def test_detect_web_attack_and_abnormal_ip(self):
        web = detect_web_attack(self.records)
        abnormal = detect_abnormal_ip(self.records)

        self.assertTrue(any(item.kind == "sql_injection" for item in web))
        self.assertTrue(any(item.kind == "directory_traversal" for item in web))
        self.assertTrue(any(item.kind == "xss" for item in web))
        self.assertTrue(any(item.kind == "high_frequency_ip" and item.ip == "8.8.8.8" for item in abnormal))
        self.assertTrue(any(item.kind == "suspicious_external_ip" and item.ip == "8.8.8.8" for item in abnormal))

    def test_risk_score_uses_findings_and_summary(self):
        findings = []
        findings.extend(detect_bruteforce(self.records))
        findings.extend(detect_success_after_failures(self.records))
        findings.extend(detect_web_attack(self.records))
        findings.extend(detect_abnormal_ip(self.records))

        risk = risk_score(findings, self.summary)

        self.assertGreaterEqual(risk.score, 80)
        self.assertEqual(risk.level, "严重")
        self.assertTrue(any("高权限" in reason or "root" in reason for reason in risk.reasons))


if __name__ == "__main__":
    unittest.main()
