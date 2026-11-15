"""시나리오 E2E 테스트 — 데모 입력을 실제 사용자 흐름대로 흘려보낸다(오프라인 모드)."""
import os
import unittest

os.environ.setdefault("LINER_OFFLINE", "1")

from incident_note.agent import Agent  # noqa: E402
from incident_note.liner import LinerClient  # noqa: E402


def agent():
    return Agent(client=LinerClient.from_env())


class TestScenarioS1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.board = agent().run_scenario("s1_bec_account_change")

    def test_severity_p1(self):
        self.assertEqual(self.board["severity"]["level"], "P1")

    def test_classification_ato(self):
        self.assertEqual(self.board["classification"]["type"], "ato")

    def test_findings_cover_expected_signals(self):
        rules = set(self.board["counts"])
        for r in ("LR_IMPOSSIBLE_TRAVEL", "LR_HIDING_RULE", "LR_SUSPICIOUS_SEND", "LR_PERSISTENCE"):
            self.assertIn(r, rules)

    def test_deadlines_match_answer_key(self):
        ddl = {d["rule_id"]: d for d in self.board["deadlines"]["items"]}
        self.assertEqual(ddl["R_INTRUSION_REPORT"]["due"], "2026-11-20(금) 09:05 KST")
        self.assertEqual(ddl["R_PI_LEAK_REPORT"]["due"], "2026-11-22(일) 09:05 KST")
        self.assertEqual(ddl["R_PI_NOTICE"]["due"], "2026-11-22(일) 09:05 KST")

    def test_timezone_in_timeline(self):
        hits = [f for f in self.board["findings"] if f["rule_id"] == "LR_FOREIGN_LOGIN"]
        self.assertTrue(any("2026-11-16(월) 10:14" in h["ts_kst"] for h in hits))

    def test_first_action_is_bank(self):
        self.assertIn("지급정지", self.board["actions"][0]["action"])

    def test_documents(self):
        ids = {d["id"] for d in self.board["docs"]}
        self.assertTrue({"T1_customer", "T3_staff", "T6_exec5", "tpl_intrusion_report",
                         "tpl_pi_leak_report", "tpl_pi_notice"} <= ids)
        self.assertEqual(len(ids), 10)

    def test_no_absolute_claims(self):
        reply = self.board["reply"]
        self.assertNotIn("피해 없음", reply)


class TestScenarioS2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.board = agent().run_scenario("s2_lookalike_domain")

    def test_lookalike_not_ato(self):
        self.assertEqual(self.board["classification"]["type"], "lookalike")
        self.assertEqual(self.board["severity"]["level"], "P4")

    def test_no_reporting_duty(self):
        ddl = {d["rule_id"]: d for d in self.board["deadlines"]["items"]}
        self.assertEqual(ddl["R_PI_LEAK_REPORT"]["status"], "비해당")
        self.assertEqual(ddl["R_INTRUSION_REPORT"]["status"], "검토")


class TestScenarioS3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.board = agent().run_scenario("s3_selfhosted_root_out_of_scope")

    def test_root_p1(self):
        self.assertEqual(self.board["classification"]["type"], "root")
        self.assertEqual(self.board["severity"]["level"], "P1")

    def test_out_of_scope_escalation(self):
        text = " ".join(a["action"] for a in self.board["actions"])
        self.assertIn("전문", text)
        self.assertIn("재부팅", text)

    def test_intrusion_report_due(self):
        ddl = {d["rule_id"]: d for d in self.board["deadlines"]["items"]}
        self.assertEqual(ddl["R_INTRUSION_REPORT"]["status"], "해당")
        self.assertEqual(ddl["R_INTRUSION_REPORT"]["due"], "2026-11-20(금) 08:50 KST")

    def test_guardrail_on_reboot_request(self):
        a = agent()
        a.run_scenario("s3_selfhosted_root_out_of_scope")
        board = a.handle("서버를 재부팅해도 될까요?")
        # 재부팅 금지는 dont_do·행동에 남아 있어야 한다
        self.assertTrue(any("재부팅" in d for d in board["dont_do"]))


class TestChatFlow(unittest.TestCase):
    def test_first_message_records_aware_time_and_asks_for_missing(self):
        a = agent()
        board = a.handle("거래처에서 우리가 계좌를 바꿨냐고 전화가 왔어요. 우리는 바꾼 적이 없습니다. 방금 알았어요.")
        self.assertIsNotNone(board["case"]["aware_at"])
        self.assertTrue(board["missing"])
        self.assertEqual(board["severity"]["level"], "P3")  # 로그 없음 → 판별 전

    def test_kingfisher_log_without_org_domain(self):
        a = agent()
        a.handle("우리 회사 메일에서 이상한 메일이 나갔대요")
        board = a.handle("방금 알았어요")
        self.assertIn("회사 메일 도메인", " ".join(board["missing"]))


if __name__ == "__main__":
    unittest.main()
