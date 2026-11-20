"""S4 랜섬웨어 시나리오 — 암호화 확산 차단·백업 보호·몸값 지불 금지·법정 기한."""
import os
import unittest

os.environ.setdefault("LINER_OFFLINE", "1")

from incident_note.agent import Agent  # noqa: E402
from incident_note.liner import LinerClient  # noqa: E402


def agent():
    return Agent(client=LinerClient.from_env())


class TestRansomwareScenario(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = agent()
        cls.board = cls.a.run_scenario("s4_ransomware")

    def test_p1_ransom_confirmed(self):
        self.assertEqual(self.board["severity"]["level"], "P1")
        self.assertEqual(self.board["classification"]["type"], "ransom")
        self.assertEqual(self.board["classification"]["level"], "확인")

    def test_edr_rules_all_fire(self):
        rules = set(self.board["counts"])
        for r in ("RW_EXTENSION_MASS", "RW_RANSOM_NOTE", "RW_SHADOW_DELETE",
                  "RW_SECURITY_DISABLED", "RW_LATERAL", "RW_BACKUP_TARGETED"):
            self.assertIn(r, rules)

    def test_facts_from_edr_and_backup(self):
        raw = {f["key"]: f["raw"] for f in self.board["facts"]}
        self.assertTrue(raw["ransomware_confirmed"])
        self.assertEqual(raw["encrypted_hosts"], 3)
        self.assertEqual(raw["encrypted_files"], 4877)
        self.assertEqual(raw["encrypted_ext"], ".locked")
        self.assertTrue(raw["shadow_copies_deleted"])
        self.assertEqual(raw["backup_status"], "at_risk")
        self.assertIn("README_RESTORE", str(raw["ransom_note"]))

    def test_deadlines_24h_and_72h(self):
        ddl = {d["rule_id"]: d for d in self.board["deadlines"]["items"]}
        self.assertEqual(ddl["R_INTRUSION_REPORT"]["status"], "해당")
        self.assertEqual(ddl["R_INTRUSION_REPORT"]["due"], "2026-11-21(토) 07:40 KST")
        self.assertEqual(ddl["R_PI_LEAK_REPORT"]["status"], "해당")
        self.assertEqual(ddl["R_PI_LEAK_REPORT"]["due"], "2026-11-23(월) 07:40 KST")

    def test_ransom_specific_operational_contacts(self):
        ops = {o["id"] for o in self.board["deadlines"]["operational"] if o["triggered"]}
        self.assertIn("O_RANSOM_KISA", ops)
        self.assertIn("O_BACKUP", ops)

    def test_actions_start_with_isolation_and_backup(self):
        acts = [a["action"] for a in self.board["actions"]]
        self.assertIn("네트워크에서 분리", acts[0])
        self.assertIn("백업", acts[1])
        self.assertTrue(any("몸값 지불 금지" in a for a in acts))
        self.assertTrue(any("백업" in a and "무결성" in a for a in acts))

    def test_dont_do_forbids_ransom_and_reboot(self):
        text = " ".join(self.board["dont_do"])
        self.assertIn("몸값 지불 금지", text)
        self.assertIn("재부팅", text)
        self.assertIn("백업이 연결된 상태", text)
        # 메일 전용 금기는 랜섬웨어 화면에서 빠진다
        self.assertNotIn("받은편지함", text)

    def test_documents_include_ransom_report(self):
        ids = {d["id"] for d in self.board["docs"]}
        self.assertTrue({"T7_staff_ransom", "T6_exec5", "tpl_ransom_report",
                         "tpl_intrusion_report", "tpl_exec_report", "tpl_timeline"} <= ids)
        body = self.a.case.docs["tpl_ransom_report"]["body"]
        for token in ("몸값 지불 금지", "24시간", "72시간", "백업", "재감염"):
            self.assertIn(token, body)

    def test_ransom_phase_and_first_five(self):
        self.assertEqual(self.board["phase"]["type"], "ransom")
        self.assertEqual(len(self.board["first_five"]), 5)
        self.assertIn("분리", self.board["first_five"][0]["action"])

    def test_no_absolute_claim(self):
        self.assertNotIn("피해 없음", self.board["reply"])
        self.assertNotIn("복구 보장", self.board["reply"])


class TestRansomwareDialog(unittest.TestCase):
    def test_guardrail_warns_against_paying(self):
        a = agent()
        a.run_scenario("s4_ransomware")
        board = a.handle("몸값을 지불하면 복구가 될까요?")
        self.assertTrue(any("몸값 지불은 권고하지 않습니다" in w for w in board["warnings"]))
        self.assertIn("몸값 지불은 권고하지 않습니다", board["reply"])

    def test_guardrail_on_reboot(self):
        a = agent()
        a.run_scenario("s4_ransomware")
        board = a.handle("일단 서버를 재부팅해 볼까요?")
        self.assertTrue(any("재부팅" in d for d in board["dont_do"]))

    def test_backup_statement_overrides_at_risk(self):
        a = agent()
        a.handle("파일 서버 파일이 .locked로 바뀌었고 랜섬노트가 있어요. 방금 알았어요.")
        board = a.handle("백업은 오프라인 테이프로 따로 보관 중입니다.")
        raw = {f["key"]: f["raw"] for f in board["facts"]}
        self.assertEqual(raw["backup_status"], "offline_safe")
        self.assertTrue(raw["backup_isolated"])

    def test_replay_steps_are_played_like_a_user(self):
        a = agent()
        steps = a.start_replay("s4_ransomware")
        self.assertEqual(len(steps), 5)
        self.assertTrue(steps[1]["label"].startswith("📎 edr_events.csv"))
        self.assertIn("event_type", steps[1]["text"])
        board = None
        for st in steps:
            board = a.handle(st["text"])
        self.assertEqual(board["severity"]["level"], "P1")
        self.assertEqual(board["classification"]["type"], "ransom")


class TestRansomwareLinerFallback(unittest.TestCase):
    def test_visualization_offline_is_clean(self):
        a = agent()
        a.run_scenario("s4_ransomware")
        viz = a.visualize()
        self.assertFalse(viz["ok"])
        self.assertTrue(viz["reason"])
        self.assertEqual(viz["html"], "")
        self.assertFalse(a.board()["viz"]["ok"])

    def test_quick_guide_offline_answers(self):
        a = agent()
        board = a.apply_category("CAT04_RANSOMWARE")
        guide = board["guide"]
        self.assertEqual(guide["status"], "offline")
        self.assertIn("몸값", guide["answer"])
        self.assertEqual(guide["source"], "규칙 기반 안내")

    def test_viz_query_mentions_case(self):
        a = agent()
        a.run_scenario("s4_ransomware")
        q = a.viz_query()
        self.assertIn("한빛물류", q)
        self.assertIn("72시간", q)


if __name__ == "__main__":
    unittest.main()
