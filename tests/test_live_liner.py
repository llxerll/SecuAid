"""Liner API 라이브 테스트 — 키가 있을 때만 실행한다.

실행: LINER_LIVE=1 python -m unittest tests.test_live_liner -v
비용: chat 1회 + web search 1회 + search agent 1회(약 30초) + quick answer 1회 + visualization 1회(20~40초).
"""
import os
import unittest

from incident_note.liner import LinerClient, LinerError

LIVE = os.environ.get("LINER_LIVE") == "1"


@unittest.skipUnless(LIVE, "LINER_LIVE=1 일 때만 실제 API를 호출합니다")
class TestLiveLiner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = LinerClient.from_env()

    def setUp(self):
        if not self.client.available:
            self.skipTest(".env에 LINER_API_KEY가 없습니다")

    def test_models(self):
        status = self.client.status()
        self.assertTrue(status["ok"], status)

    def test_chat_json(self):
        out = self.client.chat_json(
            "너는 JSON만 출력하는 테스트다.",
            '{"ok": true, "lang": "ko"} 형태로만 답하세요.',
        )
        self.assertIsInstance(out, dict)

    def test_search_web(self):
        results = self.client.search_web("KISA 침해사고 신고 118", max_results=3)
        self.assertTrue(results)
        self.assertTrue(any(r["url"] for r in results))

    def test_search_agent_citations(self):
        res = self.client.search_agent("정보통신망법 제48조의3 침해사고 신고 기한은 몇 시간인가요?")
        self.assertIn("24", res["answer"])
        self.assertGreater(len(res["references"]), 0)

    def test_quick_answer(self):
        """Quick Answer Agent API — 짧은 답변 + 출처 3개(stream=false)."""
        res = self.client.quick_answer("정보통신망법 제48조의3 침해사고 신고 기한은 몇 시간인가요? 한 문장으로.")
        self.assertTrue(res["answer"])
        self.assertIn("24", res["answer"])
        self.assertGreater(len(res["references"]), 0)
        self.assertLessEqual(len(res["references"]), 3)
        self.assertTrue(all(r["url"] for r in res["references"]))

    def test_visualization_returns_html(self):
        """Visualization API — iframe srcdoc 로 렌더 가능한 완전한 HTML 문서."""
        res = self.client.visualize("랜섬웨어 사고 대응 0~72시간 타임라인")
        self.assertTrue(res["ok"])
        self.assertTrue(res["html"].lstrip().lower().startswith("<!doctype html"))
        self.assertIn("<html", res["html"][:200].lower())
        self.assertTrue(res["theme"])

    def test_agent_guide_and_viz_live(self):
        """에이전트 경로에서 Quick Answer 와 Visualization 가 실제로 붙는지."""
        from incident_note.agent import Agent

        a = Agent(client=self.client)
        board = a.apply_category("CAT04_RANSOMWARE")
        self.assertEqual(board["guide"]["status"], "live")
        self.assertTrue(board["guide"]["references"])
        viz = a.visualize()
        self.assertTrue(viz["ok"], viz.get("reason"))
        self.assertIn("<html", viz["html"][:400].lower())

    def test_s1_scenario_live(self):
        """S1 전체(5단계 + 문서)를 실제 Liner 로 — 판정·기한·브리핑·문서가 살아 있는지."""
        from incident_note.agent import Agent
        from incident_note.docs import Document, to_docx

        a = Agent(client=self.client)
        board = a.run_scenario("s1_bec_account_change")
        self.assertEqual(board["api"]["mode"], "liner")
        self.assertEqual(board["severity"]["level"], "P1")
        self.assertTrue(board["reply"])
        self.assertGreaterEqual(len(board["deadlines"]["items"]), 2)
        docs = a.compose_docs()
        self.assertGreaterEqual(len(docs), 10)
        doc = a.case.docs["tpl_intrusion_report"]
        data = to_docx(Document(doc["id"], doc["title"], doc["kind"], doc["body"]))
        self.assertTrue(data.startswith(b"PK"))

    def test_s4_ransom_scenario_live(self):
        """S4 랜섬웨어 전체 — P1 고정·몸값 지불 금지·문서 구성."""
        from incident_note.agent import Agent

        a = Agent(client=self.client)
        board = a.run_scenario("s4_ransomware")
        self.assertEqual(board["classification"]["type"], "ransom")
        self.assertEqual(board["severity"]["level"], "P1")
        self.assertTrue(any("몸값" in d for d in board["dont_do"]))
        ids = {d["id"] for d in board["docs"]}
        self.assertIn("tpl_ransom_report", ids)
        self.assertIn("T7_staff_ransom", ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
