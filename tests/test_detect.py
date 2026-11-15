"""탐지 엔진 테스트 — v0.2에서 빠졌던 규칙과 오탐 방지."""
import unittest
from pathlib import Path

from incident_note import ingest
from incident_note.detect import detect

DATA = Path(__file__).resolve().parent.parent / "data"
SCN1 = DATA / "scenarios" / "s1_bec_account_change"
SCN2 = DATA / "scenarios" / "s2_lookalike_domain"
SCN3 = DATA / "scenarios" / "s3_selfhosted_root_out_of_scope"


def load(*paths):
    return [ingest.parse(p.read_text(encoding="utf-8")) for p in paths]


class TestS1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.det = detect(load(SCN1 / "entra_signin_log.csv", SCN1 / "audit_log.csv",
                              SCN1 / "message_trace.csv"))

    def test_core_rules_hit(self):
        rules = set(self.det.rules_hit())
        for r in ("LR_FOREIGN_LOGIN", "LR_IMPOSSIBLE_TRAVEL", "LR_HIDING_RULE", "LR_MAIL_ACCESS",
                  "LR_PERSISTENCE", "LR_SUSPICIOUS_SEND", "LR_COVER_TRACKS", "LR_APP_PASSWORD_AUTH",
                  "LR_SPRAY_SAME_IP"):
            self.assertIn(r, rules)

    def test_impossible_travel_minutes_variant(self):
        # 같은 CorrelationId가 아닌 두 국가 로그인(네덜란드→독일, 39분)을 60분 규칙으로 잡는다.
        details = [f.detail for f in self.det.findings if f.rule_id == "LR_IMPOSSIBLE_TRAVEL"]
        self.assertTrue(any(d.get("basis") == "60분 규칙" for d in details))

    def test_audit_send_detected(self):
        # v0.2는 메시지 추적만 보고 감사 로그의 Send는 놓쳤다.
        sends = [f for f in self.det.findings if f.rule_id == "LR_SUSPICIOUS_SEND"]
        self.assertGreaterEqual(len(sends), 4)
        self.assertTrue(any("계좌" in f.summary for f in sends))

    def test_suspect_ips_exclude_legit_office_ip(self):
        self.assertIn("198.51.100.23", self.det.suspect_ips)
        self.assertIn("198.51.100.88", self.det.suspect_ips)
        self.assertNotIn("203.0.113.10", self.det.suspect_ips)

    def test_no_duplicate_findings(self):
        keys = [(f.rule_id, f.ts) for f in self.det.findings if f.rule_id == "LR_SUSPICIOUS_SEND"]
        self.assertEqual(len(keys), len(set(keys)))

    def test_timeline_sorted(self):
        times = [f.ts for f in self.det.ordered() if f.ts]
        self.assertEqual(times, sorted(times))


class TestS2(unittest.TestCase):
    def test_no_false_positive_on_normal_send(self):
        # 우리 직원의 정상 발송(사내 IP, 평범한 제목)은 의심 발송이 아니다.
        det = detect(load(SCN2 / "entra_signin_log.csv", SCN2 / "audit_log.csv"))
        self.assertNotIn("LR_SUSPICIOUS_SEND", det.rules_hit())
        self.assertNotIn("LR_FOREIGN_LOGIN", det.rules_hit())
        self.assertNotIn("LR_PERSISTENCE", det.rules_hit())
        self.assertEqual(det.findings, [])

    def test_set_mailbox_without_forwarding_is_not_persistence(self):
        det = detect(load(SCN2 / "audit_log.csv"))
        self.assertNotIn("LR_PERSISTENCE", det.rules_hit())


class TestS3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.det = detect(load(SCN3 / "remote_syslog_secure.log", SCN3 / "firewall_alert.csv"))

    def test_server_rules(self):
        rules = set(self.det.rules_hit())
        for r in ("SR_BRUTEFORCE", "SR_ROOT_LOGIN", "SR_PERSIST_SERVICE", "SR_LOG_TAMPER",
                  "SR_OUTBOUND_RDP", "FW_OUTBOUND_RDP"):
            self.assertIn(r, rules)

    def test_root_login_critical(self):
        root = [f for f in self.det.findings if f.rule_id == "SR_ROOT_LOGIN"]
        self.assertTrue(all(f.severity == "critical" for f in root))
        self.assertTrue(any("10.20.1.9" in f.summary for f in root))

    def test_bruteforce_window(self):
        bf = [f for f in self.det.findings if f.rule_id == "SR_BRUTEFORCE"]
        self.assertTrue(bf)
        self.assertTrue(any(f.detail.get("count", 0) >= 5 for f in bf))

    def test_missing_log_kinds_noted(self):
        self.assertTrue(any("로그인 로그" in n for n in self.det.notes))


if __name__ == "__main__":
    unittest.main()
