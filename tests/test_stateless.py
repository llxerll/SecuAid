"""Stateless 세션 테스트 — Vercel 서버리스에서 인스턴스가 바뀌어도 사건이 이어지는가."""
import base64
import json
import os
import unittest
import zlib

os.environ.setdefault("LINER_OFFLINE", "1")

import app as app_module  # noqa: E402
from secuaid.agent import Agent  # noqa: E402
from secuaid.liner import LinerClient  # noqa: E402


def agent():
    return Agent(client=LinerClient.from_env())


class TestSnapshotRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = agent()
        cls.board = cls.agent.run_scenario("s4_ransomware")
        cls.token = cls.agent.snapshot_token()
        cls.restored = Agent.from_token(cls.token, client=LinerClient.from_env())

    def test_board_survives_restore(self):
        b = self.restored.board()
        self.assertEqual(b["case"]["id"], self.board["case"]["id"])
        self.assertEqual(b["severity"]["level"], "P1")
        self.assertEqual(b["classification"]["type"], "ransom")
        self.assertEqual(len(b["findings"]), len(self.board["findings"]))
        self.assertEqual(len(b["docs"]), len(self.board["docs"]))
        self.assertEqual(len(b["actions"]), len(self.board["actions"]))
        self.assertEqual(b["deadlines"]["items"][0]["due"], self.board["deadlines"]["items"][0]["due"])

    def test_docs_and_guides_survive(self):
        self.assertIn("tpl_ransom_report", self.restored.case.docs)
        self.assertIn("몸값 지불 금지", self.restored.case.docs["tpl_ransom_report"]["body"])
        self.restored.apply_category("CAT04_RANSOMWARE")
        self.assertIn("CAT04_RANSOMWARE", self.restored.case.guides)

    def test_continues_after_restore(self):
        before = len(self.restored.det.findings)
        board = self.restored.handle("파일 서버 외에 다른 서버도 확인해야 하나요?")
        self.assertGreaterEqual(len(board["findings"]), before)
        self.assertEqual(board["severity"]["level"], "P1")

    def test_token_is_compressed_and_has_no_secret(self):
        raw = zlib.decompress(base64.urlsafe_b64decode(self.token.encode())).decode("utf-8")
        key = os.environ.get("LINER_API_KEY", "")
        if key:
            self.assertNotIn(key, raw)          # 실제 키 값은 토큰에 절대 들어가지 않는다
        self.assertNotIn("sk_live_", raw)
        self.assertLess(len(self.token), len(raw))
        self.assertEqual(json.loads(raw)["v"], 1)

    def test_bad_token_raises(self):
        with self.assertRaises(Exception):
            Agent.from_token("not-a-token")

    def test_token_bomb_is_bounded(self):
        bomb = base64.urlsafe_b64encode(zlib.compress(b"{\"x\":\"" + b"A" * 9_000_000 + b"\"}")).decode()
        with self.assertRaises(Exception):
            Agent.from_token(bomb)


class TestHttpStateless(unittest.TestCase):
    """서버 메모리(SESSIONS)를 비워도 state 토큰만으로 이어지는지 HTTP로 확인한다."""

    def setUp(self):
        self.client = app_module.app.test_client()
        app_module.SESSIONS.clear()

    def _session(self):
        data = self.client.post("/api/session", json={}).get_json()
        return data["session"], data["state"]

    def test_lost_session_recovers_from_state(self):
        sid, _ = self._session()
        data = self.client.post(f"/api/{sid}/scenario/s4_ransomware", json={}).get_json()
        self.assertEqual(data["board"]["severity"]["level"], "P1")
        state = data["state"]

        app_module.SESSIONS.clear()          # 다른 인스턴스로 요청이 간 상황
        res = self.client.post(f"/api/{sid}/message", json={"text": "지금 몸값을 지불해야 하나요?", "state": state})
        self.assertEqual(res.status_code, 200, res.get_data(as_text=True)[:200])
        body = res.get_json()
        self.assertIn("몸값", body["board"]["reply"])
        self.assertTrue(any("몸값 지불" in d for d in body["board"]["dont_do"]))
        self.assertGreaterEqual(len(body["board"]["findings"]), 6)

    def test_board_and_docs_with_state_query(self):
        sid, _ = self._session()
        data = self.client.post(f"/api/{sid}/scenario/s1_bec_account_change", json={}).get_json()
        state = data["state"]
        app_module.SESSIONS.clear()

        res = self.client.get(f"/api/{sid}/board?state={state}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["board"]["severity"]["level"], "P1")

        app_module.SESSIONS.clear()
        res = self.client.get(f"/api/{sid}/doc/T1_customer?state={state}")
        self.assertEqual(res.status_code, 200)
        self.assertIn("제목", res.get_data(as_text=True))

        app_module.SESSIONS.clear()
        res = self.client.get(f"/api/{sid}/docs.zip?state={state}")
        self.assertEqual(res.status_code, 200)

    def test_without_state_still_404(self):
        res = self.client.post("/api/nope/message", json={"text": "hi"})
        self.assertEqual(res.status_code, 404)

    def test_new_session_with_category(self):
        res = self.client.post("/api/session", json={"category": "CAT04_RANSOMWARE"})
        body = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(body["board"]["category"]["id"], "CAT04_RANSOMWARE")
        self.assertEqual(body["board"]["severity"]["level"], "P1")
        self.assertEqual(body["guide"]["status"], "offline")

    def test_category_endpoint_and_guide(self):
        data = self.client.post("/api/session", json={}).get_json()
        sid = data["session"]
        res = self.client.post(f"/api/{sid}/category/CAT09_DDOS_OUTAGE", json={})
        body = res.get_json()
        self.assertEqual(body["board"]["category"]["no"], 9)
        self.assertTrue(body["board"]["actions"])
        res = self.client.post(f"/api/{sid}/guide", json={"force": True})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["guide"]["answer"])

    def test_viz_endpoint_offline_falls_back(self):
        data = self.client.post("/api/session", json={}).get_json()
        sid = data["session"]
        res = self.client.post(f"/api/{sid}/viz", json={})
        body = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertFalse(body["viz"]["ok"])
        self.assertEqual(body["html"], "")
        self.assertTrue(body["viz"]["reason"])

    def test_unknown_category_404(self):
        data = self.client.post("/api/session", json={}).get_json()
        sid = data["session"]
        res = self.client.post(f"/api/{sid}/category/NO_SUCH", json={})
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()


class TestStaleInstanceCache(unittest.TestCase):
    """서버리스의 다른 인스턴스에 옛 사건이 캐시돼 있어도 요청의 최신 state 토큰이 이긴다.

    재현: 단계별 재생 3단계에서 시작한 법령 재확인이 재생이 끝난 뒤 병합될 때, 옛 사건(P2)을 가진 인스턴스로 가면
    심각도가 P1→P2로 돌아가고 타임라인이 줄었다.
    """

    def test_late_law_merge_on_stale_instance_keeps_latest_case(self):
        from secuaid.liner import LinerClient
        c = app_module.app.test_client()
        sid = c.post("/api/session", json={}).get_json()["session"]
        r = c.post(f"/api/{sid}/replay/s1_bec_account_change", json={}).get_json()
        state, snap = r["state"], None
        for i, st in enumerate(r["steps"], 1):
            d = c.post(f"/api/{sid}/message", json={"text": st["text"], "defer": True, "state": state}).get_json()
            state = d["state"]
            if i == 2:
                snap = state
        latest = d["board"]
        self.assertEqual(latest["severity"]["level"], "P1")
        app_module.SESSIONS[sid] = Agent.from_token(snap, client=LinerClient.from_env())   # 다른 인스턴스의 옛 캐시
        merged = c.post(f"/api/{sid}/law/merge", json={"law_check": {"status": "offline"}, "state": state}).get_json()["board"]
        self.assertEqual(merged["severity"]["level"], "P1")
        self.assertEqual(len(merged["findings"]) + len(merged["events"]), len(latest["findings"]) + len(latest["events"]))

    def test_cache_used_when_token_matches(self):
        c = app_module.app.test_client()
        d = c.post("/api/session", json={}).get_json()
        sid = d["session"]
        cached = app_module.SESSIONS[sid]
        c.post(f"/api/{sid}/board", json={"state": d["state"]})
        self.assertIs(app_module.SESSIONS[sid], cached)          # 같은 토큰이면 다시 복원하지 않는다
