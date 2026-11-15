"""Liner API 라이브 테스트 — 키가 있을 때만 실행한다.

실행: LINER_LIVE=1 python -m unittest tests.test_live_liner -v
비용: chat 1회 + web search 1회 + search agent 1회(약 30초).
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
