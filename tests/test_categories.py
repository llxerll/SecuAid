"""10대 침해 사고 유형 카탈로그 테스트 — 선택만으로 공통 초동조치·기한·가이드가 작동하는가."""
import os
import unittest

os.environ.setdefault("LINER_OFFLINE", "1")

from secuaid import categories as cat_mod  # noqa: E402
from secuaid.agent import Agent, SCENARIO_DIR  # noqa: E402
from secuaid.liner import LinerClient  # noqa: E402


def agent():
    return Agent(client=LinerClient.from_env())


class TestCatalog(unittest.TestCase):
    def test_ten_categories_in_order(self):
        cats = cat_mod.CATEGORIES
        self.assertEqual(len(cats), 10)
        self.assertEqual([c.no for c in cats], list(range(1, 11)))
        self.assertEqual(len({c.id for c in cats}), 10)
        for c in cats:
            self.assertTrue(c.name and c.first_15min and c.dont_do, c.id)
            self.assertIn(c.base_severity, ("P1", "P2", "P3", "P4"))

    def test_deep_four_and_scenarios_exist(self):
        # 핵심 4종(시나리오 S1~S4) — BEC와 ATO는 같은 S1 시나리오를 공유하는 별도 유형이다.
        deep = [c for c in cat_mod.CATEGORIES if c.deep]
        self.assertEqual({c.scenario for c in deep},
                         {"s1_bec_account_change", "s2_lookalike_domain",
                          "s3_selfhosted_root_out_of_scope", "s4_ransomware"})
        self.assertEqual(len(deep), 5)
        self.assertEqual({c.incident_type for c in deep}, {"ato", "lookalike", "root", "ransom"})
        for c in deep:
            self.assertTrue(c.scenario, c.id)
            self.assertTrue((SCENARIO_DIR / c.scenario / "scenario.json").exists(), c.scenario)

    def test_lookup_by_id_number_and_alias(self):
        self.assertEqual(cat_mod.get("CAT04_RANSOMWARE").no, 4)
        self.assertEqual(cat_mod.get(4).id, "CAT04_RANSOMWARE")
        self.assertEqual(cat_mod.get("ransom").id, "CAT04_RANSOMWARE")
        self.assertEqual(cat_mod.get("s4_ransomware").id, "CAT04_RANSOMWARE")
        self.assertIsNone(cat_mod.get("없는유형"))

    def test_guess_from_text(self):
        self.assertEqual(cat_mod.guess("파일이 .locked로 바뀌었어요").id, "CAT04_RANSOMWARE")
        self.assertEqual(cat_mod.guess("거래처에서 계좌를 바꿨냐고 전화가 왔어요").id, "CAT01_BEC_ACCOUNT_CHANGE")
        self.assertEqual(cat_mod.guess("우리 도메인과 비슷한 주소로 사칭 메일이 왔대요").id, "CAT03_LOOKALIKE_SPOOF")
        self.assertEqual(cat_mod.guess("AWS API 키가 깃허브에 올라갔어요").id, "CAT06_CLOUD_KEY_LEAK")


class TestCategoryFlow(unittest.TestCase):
    def test_every_category_produces_actions_and_deadlines_offline(self):
        for cat in cat_mod.CATEGORIES:
            a = agent()
            board = a.apply_category(cat.id)
            self.assertTrue(board["actions"], cat.id)
            self.assertTrue(board["first_five"], cat.id)
            self.assertTrue(board["dont_do"], cat.id)
            self.assertTrue(board["deadlines"]["items"], cat.id)
            self.assertEqual(board["category"]["id"], cat.id)
            self.assertEqual(board["severity"]["level"], cat.base_severity, (cat.id, board["severity"]))
            # 키 없이도 규칙 기반 가이드가 즉시 나온다
            self.assertEqual(board["guide"]["status"], "offline")
            self.assertTrue(board["guide"]["answer"])

    def test_generic_category_uses_its_own_playbook(self):
        board = agent().apply_category("CAT07_WEB_DB_LEAK")
        text = " ".join(a["action"] for a in board["actions"])
        self.assertIn("웹서버", text)
        self.assertEqual(board["classification"]["type"], "webdb")
        ddl = {d["rule_id"]: d for d in board["deadlines"]["items"]}
        self.assertEqual(ddl["R_PI_LEAK_REPORT"]["status"], "판단 보류")  # 유출 사실 미확인

    def test_ransomware_category_is_p1_and_forbids_ransom(self):
        a = agent()
        board = a.apply_category("CAT04_RANSOMWARE")
        self.assertEqual(board["severity"]["level"], "P1")
        self.assertEqual(board["classification"]["type"], "ransom")
        self.assertTrue(any("네트워크에서 분리" in x["action"] for x in board["actions"]))
        self.assertTrue(any("몸값" in d for d in board["dont_do"]))
        ddl = {d["rule_id"]: d for d in board["deadlines"]["items"]}
        self.assertIn(ddl["R_INTRUSION_REPORT"]["status"], ("해당", "판단 보류"))

    def test_category_guessed_from_chat_message(self):
        a = agent()
        board = a.handle("출근하니 파일 이름 뒤에 .locked가 붙어 있고 랜섬노트가 생겼어요. 방금 알았어요.")
        self.assertEqual((board["category"] or {}).get("id"), "CAT04_RANSOMWARE")
        self.assertEqual(board["category"]["level"], "추정")
        self.assertEqual(board["severity"]["level"], "P1")

    def test_suggested_categories_from_detection(self):
        board = agent().run_scenario("s4_ransomware")
        ids = {s["id"] for s in board["suggested_categories"]}
        self.assertIn("CAT04_RANSOMWARE", ids)


if __name__ == "__main__":
    unittest.main()
