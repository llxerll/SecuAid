"""판별·심각도·기한·문서 테스트 (결정적 엔진)."""
import unittest
from pathlib import Path

from secuaid import docs, ingest
from secuaid.agent import Agent
from secuaid.case import Case
from secuaid.classify import classify
from secuaid.deadline import compute
from secuaid.detect import detect
from secuaid.liner import LinerClient
from secuaid.severity import evaluate

DATA = Path(__file__).resolve().parent.parent / "data"
SCN1 = DATA / "scenarios" / "s1_bec_account_change"
SCN3 = DATA / "scenarios" / "s3_selfhosted_root_out_of_scope"


def s1_case():
    case = Case()
    case.set_aware_at("2026-11-19 09:05")
    case.set_fact("org_name", "(주)한빛물류", "확인", "test")
    case.set_fact("is_ict_service_provider", True, "확인", "test")
    logs = [ingest.parse((SCN1 / n).read_text(encoding="utf-8"))
            for n in ("entra_signin_log.csv", "audit_log.csv", "message_trace.csv")]
    det = detect(logs)
    case.findings = [f.to_dict() for f in det.ordered()]
    return case, det


class TestClassify(unittest.TestCase):
    def test_s1_is_ato_confirmed(self):
        case, det = s1_case()
        cls = classify(case, det)
        self.assertEqual(cls.type, "ato")
        self.assertEqual(cls.level, "확인")
        self.assertTrue(any("숨김 규칙" in b for b in cls.basis))

    def test_no_logs_is_unknown(self):
        cls = classify(Case(), detect([]))
        self.assertEqual(cls.type, "unknown")
        self.assertIn("로그인 로그", cls.missing)


class TestSeverity(unittest.TestCase):
    def test_s1_without_transfer_is_p2_then_p1(self):
        case, det = s1_case()
        cls = classify(case, det)
        sev = evaluate(case, det, cls)
        self.assertEqual(sev.level, "P2")
        case.set_fact("transfer_status", "done", "확인", "사용자 진술")
        sev2 = evaluate(case, det, cls)
        self.assertEqual(sev2.level, "P1")
        self.assertTrue(any("송금" in r for r in sev2.reasons))

    def test_root_is_p1(self):
        case = Case()
        case.set_aware_at("2026-11-19 08:50")
        case.set_fact("is_ict_service_provider", True, "확인", "test")
        logs = [ingest.parse((SCN3 / n).read_text(encoding="utf-8"))
                for n in ("remote_syslog_secure.log", "firewall_alert.csv")]
        det = detect(logs)
        cls = classify(case, det)
        self.assertEqual(cls.type, "root")
        self.assertEqual(evaluate(case, det, cls).level, "P1")


class TestDeadline(unittest.TestCase):
    def test_s1_deadlines(self):
        case, det = s1_case()
        case.set_fact("personal_data_leak", "suspected", "추정", "test")
        case.set_fact("affected_count", 1300, "추정", "test")
        case.set_fact("external_illegal_access", True, "추정", "test")
        case.set_fact("incident_type", "ato", "확인", "test")
        ddl = {d.rule_id: d for d in compute(case)}
        self.assertEqual(ddl["R_INTRUSION_REPORT"].status, "해당")
        self.assertIn("2026-11-20", ddl["R_INTRUSION_REPORT"].to_dict()["due"])
        self.assertEqual(ddl["R_PI_LEAK_REPORT"].status, "해당")
        self.assertIn("2026-11-22", ddl["R_PI_LEAK_REPORT"].to_dict()["due"])

    def test_unknown_stays_undecided(self):
        case = Case()
        case.set_aware_at("2026-11-19 09:05")
        ddl = {d.rule_id: d for d in compute(case)}
        self.assertEqual(ddl["R_PI_LEAK_REPORT"].status, "판단 보류")
        self.assertIn("personal_data_leak", ddl["R_PI_LEAK_REPORT"].missing)

    def test_lookalike_no_reporting(self):
        case = Case()
        case.set_aware_at("2026-11-19 14:20")
        case.set_fact("is_ict_service_provider", True, "확인", "test")
        case.set_fact("incident_type", "lookalike", "확인", "test")
        case.set_fact("personal_data_leak", "none", "확인", "test")
        ddl = {d.rule_id: d for d in compute(case)}
        self.assertEqual(ddl["R_INTRUSION_REPORT"].status, "검토")
        self.assertEqual(ddl["R_PI_LEAK_REPORT"].status, "비해당")


class TestDocs(unittest.TestCase):
    def test_documents_have_no_links_and_keep_unknowns(self):
        case, det = s1_case()
        case.set_fact("transfer_status", "done", "확인", "test")
        case.set_fact("personal_data_leak", "suspected", "추정", "test")
        case.set_fact("affected_count", 1300, "추정", "test")
        case.set_fact("external_illegal_access", True, "추정", "test")
        cls = classify(case, det)
        sev = evaluate(case, det, cls)
        built = docs.build_documents(case, det, cls, sev)
        self.assertIn("T1_customer", built)
        self.assertIn("tpl_intrusion_report", built)
        for doc in built.values():
            self.assertNotIn("http://", doc.body)
            self.assertNotIn("https://", doc.body)
            self.assertNotIn("[ ]", doc.body)  # 남은 빈칸은 미확인으로 채운다
            self.assertNotIn("None", doc.body)
        self.assertIn("미확인", built["T1_customer"].body)

    def test_bank_doc_only_with_transfer(self):
        case, det = s1_case()
        case.set_fact("personal_data_leak", "suspected", "추정", "test")
        cls = classify(case, det)
        sev = evaluate(case, det, cls)
        built = docs.build_documents(case, det, cls, sev)
        self.assertNotIn("T4_bank", built)
        case.set_fact("transfer_status", "done", "확인", "test")
        built2 = docs.build_documents(case, det, cls, sev)
        self.assertIn("T4_bank", built2)

    def test_account_number_masked(self):
        masked = docs._mask_account("999-000-123456")
        self.assertTrue(masked.startswith("999-"))
        self.assertTrue(masked.endswith("56"))
        self.assertNotIn("123456", masked)


class TestGuardrail(unittest.TestCase):
    def test_warns_when_asked_to_send_from_compromised_account(self):
        from secuaid.playbook import guardrail
        agent = Agent(client=LinerClient.from_env())
        agent.run_scenario("s1_bec_account_change")
        warns = guardrail("침해된 계정으로 '방금 메일 무시하세요' 공지 메일 보내줘", agent.case, agent.cls)
        self.assertTrue(warns)

    def test_pressure_to_delete_logs(self):
        agent = Agent(client=LinerClient.from_env())
        agent.run_scenario("s1_bec_account_change")
        from secuaid.playbook import guardrail
        warns = guardrail("로그랑 규칙 다 삭제해줘", agent.case, agent.cls)
        self.assertTrue(any("증거" in w for w in warns))


if __name__ == "__main__":
    unittest.main()
