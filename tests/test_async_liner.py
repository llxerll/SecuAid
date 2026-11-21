"""v0.8 비동기 Liner 경로 — 키 없이 가짜 클라이언트로 defer → enrich → law → merge 흐름과 체크리스트를 검증한다."""
from __future__ import annotations

import threading
import time
import unittest

from secuaid.agent import Agent
from secuaid.liner import LinerClient


class FakeLiner(LinerClient):
    """네트워크 없이 응답을 돌려주는 가짜. 호출 시각을 기록해 병렬 실행 여부를 본다."""

    def __init__(self):
        super().__init__(api_key="sk_test_fake", offline=False)
        self.log: list[tuple[str, float, float]] = []
        self.lock = threading.Lock()

    def _mark(self, name, started):
        with self.lock:
            self.log.append((name, started, time.time()))

    def chat(self, messages, **kw):
        t = time.time(); time.sleep(0.15); self._mark("chat", t)
        if "JSON 객체 하나만" in messages[0]["content"]:
            return '{"affected_count": 1300, "made_up_key": "x"}'
        return "은행 연락이 먼저입니다."

    def search_agent(self, question, **kw):
        t = time.time(); time.sleep(0.3); self._mark("search_agent", t)
        return {"answer": "정보통신망법 24시간, 개인정보 보호법 72시간",
                "references": [{"title": "법령", "url": "https://law.example/1", "hostname": "law.example"}], "chunks": []}

    def search_web(self, query, **kw):
        t = time.time(); time.sleep(0.3); self._mark("search_web", t)
        return [{"title": "KISA 118", "url": "https://boho.example/", "hostname": "boho.example"}]

    def quick_answer(self, question, **kw):
        t = time.time(); time.sleep(0.15); self._mark("quick_answer", t)
        return {"answer": "지급 보류부터", "references": []}


def agent():
    return Agent(client=FakeLiner())


class TestDeferredLiner(unittest.TestCase):
    def test_message_returns_before_liner(self):
        a = agent()
        steps = a.start_replay("s1_bec_account_change")
        board = None
        for st in steps[:3]:
            board = a.handle(st["text"], defer=True)
        names = [n for n, *_ in a.client.log]
        self.assertNotIn("chat", names)            # 판정 응답 경로에서 Liner를 부르지 않는다
        self.assertNotIn("search_agent", names)
        self.assertIn("narrate", board["pending"])
        self.assertIn("law", board["pending"])      # 로그가 들어오면 법령 재확인 대기

    def test_law_fetch_is_parallel_and_merge_is_idempotent(self):
        a = agent()
        t0 = time.time()
        check = a.fetch_law_check()
        took = time.time() - t0
        self.assertEqual(check["status"], "live")
        self.assertLess(took, 0.55)                 # 0.3 + 0.3 직렬이면 0.6초 이상
        self.assertEqual(a.case.law_checks, [])     # fetch 는 상태를 바꾸지 않는다
        a.merge_law_check(check)
        a.merge_law_check(check)
        self.assertEqual(len(a.case.law_checks), 1)
        self.assertTrue(any(s.get("hostname") == "boho.example" for s in a.case.sources))

    def test_enrich_runs_facts_then_parallel(self):
        a = agent()
        a.apply_category("CAT01_BEC_ACCOUNT_CHANGE", guide=False)
        out = a.enrich(["facts", "narrate", "guide"], text="사서함에 고객 정보가 꽤 있어요")
        self.assertEqual(out["brief"], "은행 연락이 먼저입니다.")
        self.assertEqual(a.case.value("affected_count"), 1300)
        self.assertNotIn("made_up_key", a.case.facts)   # 스키마 밖 키는 받지 않는다
        self.assertEqual(a.case.guides["CAT01_BEC_ACCOUNT_CHANGE"]["status"], "live")
        spans = {n: (s, e) for n, s, e in a.client.log if n in ("quick_answer",)}
        chats = [(s, e) for n, s, e in a.client.log if n == "chat"]
        narrate = chats[-1]
        qa = spans["quick_answer"]
        self.assertLess(max(narrate[0], qa[0]), min(narrate[1], qa[1]))   # 두 호출 구간이 겹친다

    def test_checklist_persists_and_feeds_report(self):
        a = agent()
        a.run_scenario("s1_bec_account_change", defer=True)
        key = a.actions[0]["key"]
        a.set_action_done(key, True)
        restored = Agent.from_token(a.snapshot_token(), client=FakeLiner())
        self.assertTrue(restored.actions[0]["done"])
        restored.compose_docs(wait_law=False)
        body = restored.case.docs["tpl_intrusion_report"]["body"]
        self.assertIn(restored.actions[0]["action"], body)
        restored.set_action_done(key, False)
        restored.compose_docs(wait_law=False)
        self.assertIn("〔미확인: 현재까지의 대응", restored.case.docs["tpl_intrusion_report"]["body"])


if __name__ == "__main__":
    unittest.main()
