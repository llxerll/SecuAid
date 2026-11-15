"""로그 인제스트 · EML 헤더 판독 테스트."""
import json
import unittest
from pathlib import Path

from incident_note import eml, ingest

DATA = Path(__file__).resolve().parent.parent / "data"
SCN1 = DATA / "scenarios" / "s1_bec_account_change"
SCN2 = DATA / "scenarios" / "s2_lookalike_domain"
SCN3 = DATA / "scenarios" / "s3_selfhosted_root_out_of_scope"


class TestSniff(unittest.TestCase):
    def test_kinds(self):
        cases = {
            "entra_signin_log.csv": ingest.SIGNIN,
            "audit_log.csv": ingest.AUDIT,
            "message_trace.csv": ingest.TRACE,
            "firewall_alert.csv": ingest.FIREWALL,
            "remote_syslog_secure.log": ingest.SYSLOG,
            "account_change_sent.eml": ingest.EML,
        }
        for name, kind in cases.items():
            d = SCN1 if (SCN1 / name).exists() else SCN3
            self.assertEqual(ingest.sniff((d / name).read_text(encoding="utf-8")), kind, name)


class TestParse(unittest.TestCase):
    def test_signin_rows_and_utc(self):
        log = ingest.parse((SCN1 / "entra_signin_log.csv").read_text(encoding="utf-8"))
        self.assertEqual(len(log), len([l for l in (SCN1 / "entra_signin_log.csv").read_text(encoding="utf-8").splitlines() if l.strip()]) - 1)
        self.assertEqual(log.records[0].ts.isoformat(), "2026-11-13T00:02:41+00:00")

    def test_audit_params_kept(self):
        log = ingest.parse((SCN1 / "audit_log.csv").read_text(encoding="utf-8"))
        rule = [r for r in log.records if r.get("Operation") == "New-InboxRule"][0]
        self.assertIn("MoveToFolder=RSS 피드", rule.get("Parameters"))

    def test_syslog_local_time(self):
        log = ingest.parse((SCN3 / "remote_syslog_secure.log").read_text(encoding="utf-8"))
        self.assertEqual(len(log), len([l for l in (SCN3 / "remote_syslog_secure.log").read_text(encoding="utf-8").splitlines() if l.strip()]))
        root = [r for r in log.records if "Accepted password for root" in r.get("message")][0]
        # 11:31 KST → 02:31 UTC
        self.assertEqual(root.ts.isoformat(), "2026-11-16T02:31:02+00:00")

    def test_multi_paste(self):
        text = (SCN3 / "remote_syslog_secure.log").read_text(encoding="utf-8") + "\n" + \
               (SCN3 / "firewall_alert.csv").read_text(encoding="utf-8")
        logs = ingest.parse_multi(text)
        kinds = {l.kind: len(l) for l in logs}
        self.assertEqual(kinds.get(ingest.SYSLOG), len([l for l in (SCN3 / "remote_syslog_secure.log").read_text(encoding="utf-8").splitlines() if l.strip()]))
        self.assertEqual(kinds.get(ingest.FIREWALL), 5)

    def test_unknown_format_is_reported(self):
        log = ingest.parse("안녕하세요, 이상한 메일이 왔어요")
        self.assertEqual(log.kind, ingest.UNKNOWN)
        self.assertTrue(log.warnings)


class TestEml(unittest.TestCase):
    def test_ato(self):
        tri = eml.triage_eml((SCN1 / "account_change_sent.eml").read_text(encoding="utf-8"),
                             org_domains={"hanbit-logis.example"},
                             suspect_ips={"198.51.100.23"})
        self.assertEqual(tri.verdict, "ato")
        self.assertEqual(tri.from_domain, "hanbit-logis.example")
        self.assertEqual(tri.auth.get("spf"), "pass")
        self.assertEqual(tri.originating_ip, "198.51.100.23")
        self.assertTrue(any(f.code == "HDR_ORIGIN_IP_SUSPECT" for f in tri.flags))

    def test_lookalike(self):
        tri = eml.triage_eml((SCN2 / "lookalike_account_change.eml").read_text(encoding="utf-8"),
                             org_domains={"hanbit-logis.example"})
        self.assertEqual(tri.verdict, "lookalike")
        self.assertTrue(any(f.code == "HDR_LOOKALIKE" for f in tri.flags))
        self.assertEqual(tri.auth.get("dmarc"), "fail")

    def test_external_legit_domain(self):
        raw = ("From: someone@partner.example\nTo: a@b.example\nSubject: hi\n"
               "Authentication-Results: mx.b.example; spf=pass smtp.mailfrom=partner.example; dkim=pass\n"
               "Date: Mon, 16 Nov 2026 10:00:00 +0900\n\nbody")
        tri = eml.triage_eml(raw, org_domains={"b.example"})
        self.assertEqual(tri.verdict, "external")

    def test_levenshtein_and_homoglyph(self):
        self.assertTrue(eml.is_lookalike("hanbit-logistcs.example", {"hanbit-logis.example"})[0])
        self.assertTrue(eml.is_lookalike("hanb1t-logis.example", {"hanbit-logis.example"})[0])
        self.assertFalse(eml.is_lookalike("google.com", {"hanbit-logis.example"})[0])


if __name__ == "__main__":
    unittest.main()
