"""PII 마스킹 테스트 — 기획서 핵심 원칙(밖으로 보내지 않는다)의 회귀 방지."""
import unittest

from incident_note.mask import Masker


class TestMask(unittest.TestCase):
    def setUp(self):
        self.m = Masker()

    def test_rrn(self):
        out = self.m.mask("주민번호 900101-1234567 확인")
        self.assertNotIn("900101-1234567", out)
        self.assertIn("[주민번호_1]", out)

    def test_phone_not_confused_with_account(self):
        out = self.m.mask("연락처 010-1234-5678")
        self.assertIn("[전화번호_1]", out)
        self.assertNotIn("010-1234-5678", out)

    def test_account(self):
        out = self.m.mask("계좌 999-000-123456 로 송금")
        self.assertIn("[계좌번호_1]", out)
        self.assertNotIn("999-000-123456", out)

    def test_email_keeps_domain(self):
        out = self.m.mask("sy.park@hanbit-logis.example 에게")
        self.assertIn("@hanbit-logis.example", out)
        self.assertNotIn("sy.park@", out)

    def test_same_value_same_token(self):
        out = self.m.mask("010-1111-2222 그리고 010-1111-2222")
        self.assertEqual(out.count("[전화번호_1]"), 2)

    def test_unmask_roundtrip(self):
        original = "박서연 010-1234-5678 sy.park@hanbit-logis.example 계좌 999-000-123456"
        masked = self.m.mask(original)
        self.assertEqual(self.m.unmask(masked), original)

    def test_ip_kept_when_requested(self):
        m = Masker(keep_ip=True)
        out = m.mask("198.51.100.23 에서 로그인")
        self.assertIn("198.51.100.23", out)

    def test_ip_masked_by_default(self):
        self.assertNotIn("198.51.100.23", self.m.mask("198.51.100.23 에서 로그인"))


if __name__ == "__main__":
    unittest.main()
