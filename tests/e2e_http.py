"""웹 UI·API E2E — 실제 HTTP 서버를 띄워 요청으로 검증하고 종료한다.

실행: python -m tests.e2e_http  (또는 python tests/e2e_http.py)
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

os.environ.setdefault("LINER_OFFLINE", "1")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as app_module  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

PORT = int(os.environ.get("E2E_PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"


def http(path: str, method: str = "GET", payload: dict | None = None, raw: bool = False):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        body = resp.read()
        return resp.status, (body if raw else body.decode("utf-8"))


def http_json(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    status, body = http(path, method, payload)
    assert status == 200, (status, body[:200])
    return json.loads(body)


class TestWebApp(unittest.TestCase):
    server = None
    thread = None

    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", PORT, app_module.app, threaded=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.6)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_index_page(self):
        status, body = http("/")
        self.assertEqual(status, 200)
        # 리브랜딩: 시큐에이드 / SecuAid
        self.assertIn("시큐에이드", body)
        self.assertIn("SecuAid", body)
        self.assertIn('href="/static/logo.png"', body)          # 파비콘
        self.assertIn('src="/static/logo.png"', body)           # 좌상단 로고
        self.assertIn("중소·소호 기업 보안사고 초동대응 파트너", body)
        # v0.8 관제 일지 디자인: 첫 화면(유형 고르기) → 사건 워크스페이스
        self.assertIn('data-stage="start"', body)
        self.assertIn('id="startView"', body)                    # 첫 화면
        self.assertIn('id="clock"', body)                        # 72시간 시계
        self.assertEqual(body.count('<button class="b-tab'), 5)   # 할 일 · 타임라인 · 증거 확보 · 문서 · 근거
        self.assertIn('id="chartNative"', body)                  # 앱이 그리는 72시간 대응 차트
        self.assertEqual(body.count('<button class="m-tab'), 4)         # 모바일 하단 4탭
        self.assertIn('data-tab="side"', body)
        self.assertIn('id="sidePane"', body)
        # Liner 차트는 격리된 창에서 — 고유 출처(allow-same-origin)를 주지 않는다
        self.assertIn('sandbox="allow-scripts"', body)
        self.assertNotIn("allow-same-origin", body)
        self.assertIn('href="/static/logo.svg?v=', body)
        self.assertIn('href="/favicon.ico?v=', body)

    def test_static_assets(self):
        for path in ("/static/app.js", "/static/style.css"):
            status, body = http(path)
            self.assertEqual(status, 200, path)
            self.assertGreater(len(body), 500)
        status, logo = http("/static/logo.png", raw=True)
        self.assertEqual(status, 200)
        self.assertTrue(logo.startswith(b"\x89PNG"))
        self.assertGreater(len(logo), 2000)

    def test_favicon_ico_served(self):
        status, body = http("/favicon.ico", raw=True)
        self.assertEqual(status, 200)
        self.assertEqual(body[:4], b"\x00\x00\x01\x00")       # ICO 헤더

    def test_html_ids_match_js(self):
        """JS가 참조하는 DOM id가 HTML에 모두 존재해야 화면이 깨지지 않는다."""
        _, html = http("/")
        _, js = http("/static/app.js")
        ids = set(re.findall(r'\$\("([A-Za-z0-9_]+)"\)', js))
        missing = [i for i in ids if f'id="{i}"' not in html]
        self.assertEqual(missing, [])

    def test_health_and_scenarios(self):
        data = http_json("/api/health")
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["scenarios"]), 4)
        self.assertIn("liner", data)
        self.assertEqual(len(data["categories"]), 10)
        self.assertTrue(data["features"]["stateless"])

    def test_categories_api(self):
        data = http_json("/api/categories")
        self.assertEqual([c["no"] for c in data["categories"]], list(range(1, 11)))
        self.assertEqual(len(data["deep"]), 5)  # BEC·ATO가 S1을 공유한다

    def test_mobile_css_unsticks_chat(self):
        """모바일에서 sticky 가 스크롤을 막지 않고, 한 화면씩 전환하는 규칙이 있는지."""
        _, css = http("/static/style.css")
        self.assertIn("@media (max-width: 900px)", css)
        self.assertIn(".chat-panel { position: static", css)
        self.assertIn('body[data-view="chat"] .board-panel { display: none; }', css)
        self.assertIn('body[data-view="board"] .chat-panel { display: none; }', css)
        for token in (".cat-chip", ".viz-frame", "max-width: 640px", "overflow-x: hidden"):
            self.assertIn(token, css)

    def test_category_chips_in_html(self):
        _, html = http("/")
        for el in ('id="catChips"', 'id="guide"', 'id="vizBtn"', 'id="vizFrame"', 'id="guideBtn"'):
            self.assertIn(el, html)

    def test_session_and_message(self):
        data = http_json("/api/session", "POST", {})
        sid = data["session"]
        board = http_json(f"/api/{sid}/message", "POST",
                          {"text": "거래처에서 우리가 계좌를 바꿨냐고 전화가 왔어요. 우리는 바꾼 적이 없습니다. 방금 알았어요."})["board"]
        self.assertIn("aware_at", board["case"])
        self.assertTrue(board["reply"])

    def test_scenario_run_and_docs_over_http(self):
        sid = http_json("/api/session", "POST", {})["session"]
        board = http_json(f"/api/{sid}/scenario/s1_bec_account_change", "POST", {})["board"]
        self.assertEqual(board["severity"]["level"], "P1")
        self.assertEqual(len(board["docs"]), 10)
        status, md = http(f"/api/{sid}/doc/T1_customer")
        self.assertEqual(status, 200)
        self.assertIn("제목", md)
        status, report = http(f"/api/{sid}/report")
        self.assertEqual(status, 200)
        self.assertIn("## 신고·통지 기한", report)

    def test_docx_export_over_http(self):
        sid = http_json("/api/session", "POST", {})["session"]
        http_json(f"/api/{sid}/scenario/s1_bec_account_change", "POST", {})
        try:
            import docx  # noqa: F401
        except Exception:
            self.skipTest("python-docx 없음")
        status, body = http(f"/api/{sid}/doc/T1_customer.docx", raw=True)
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"PK"))

    def test_replay_and_zip_over_http(self):
        sid = http_json("/api/session", "POST", {})["session"]
        data = http_json(f"/api/{sid}/replay/s1_bec_account_change", "POST", {})
        self.assertEqual(len(data["steps"]), 5)
        for st in data["steps"]:
            board = http_json(f"/api/{sid}/message", "POST", {"text": st["text"]})["board"]
        self.assertEqual(board["severity"]["level"], "P1")
        self.assertGreaterEqual(len(board["severity_history"]), 2)
        http_json(f"/api/{sid}/docs", "POST", {})
        status, body = http(f"/api/{sid}/docs.zip", raw=True)
        self.assertEqual(status, 200)
        import io
        import zipfile
        names = zipfile.ZipFile(io.BytesIO(body)).namelist()
        self.assertIn("00_사건_리포트.md", names)
        self.assertGreaterEqual(sum(n.endswith(".md") for n in names), 11)

    def test_post_download_endpoints(self):
        """버튼 다운로드 — state 를 본문에 실어 URL 길이 제한 없이 받는다."""
        sid = http_json("/api/session", "POST", {})["session"]
        http_json(f"/api/{sid}/scenario/s4_ransomware", "POST", {})
        status, md = http(f"/api/{sid}/download/tpl_ransom_report", "POST", {})
        self.assertEqual(status, 200)
        self.assertIn("몸값 지불 금지", md)
        status, body = http(f"/api/{sid}/download/tpl_ransom_report.docx", "POST", {}, raw=True)
        self.assertIn(status, (200, 501))
        if status == 200:
            self.assertTrue(body.startswith(b"PK"))
        status, body = http(f"/api/{sid}/download/zip", "POST", {}, raw=True)
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"PK"))

    def test_no_logs_path_over_http(self):
        """로그 없는 작은 회사: 진술 타임라인 · 증거 확보 상태 · 업체 요청 메일 · 공식 안내 검색(키 없음)."""
        d = http_json("/api/session", "POST", {})
        sid, state = d["session"], d["state"]
        d = http_json(f"/api/{sid}/message", "POST", {"text": "저희는 가비아 메일 써요. 오늘 오전 10시쯤 거래처 전화 받았어요", "defer": True, "state": state})
        state = d["state"]
        self.assertEqual(d["board"]["evidence"]["platforms"][0]["id"], "kr_mail")
        d = http_json(f"/api/{sid}/event", "POST", {"when": "어제 오후 4시 40분", "what": "거래처에 계좌 변경 메일이 나감", "state": state})
        state = d["state"]
        self.assertTrue(any(e["what"] == "거래처에 계좌 변경 메일이 나감" and e["ts"] for e in d["board"]["events"]))
        ev_id = next(e["id"] for e in d["board"]["events"] if e["what"].startswith("거래처에 계좌"))
        d = http_json(f"/api/{sid}/evidence", "POST", {"item": "KR_LOGIN", "status": "cannot", "state": state})
        state = d["state"]
        self.assertEqual(d["board"]["evidence"]["cannot"], 1)
        letter = http_json(f"/api/{sid}/evidence/request", "POST", {"platform": "kr_mail", "state": state})["letter"]
        self.assertIn("로그 보존", letter["subject"])
        res = http_json(f"/api/{sid}/evidence/search", "POST", {"platform": "kr_mail", "state": state})
        self.assertEqual(res["results"], [])          # 키 없음 → 빈 결과 + 안내
        d = http_json(f"/api/{sid}/event/delete", "POST", {"id": ev_id, "state": state})
        self.assertFalse(any(e["id"] == ev_id for e in d["board"]["events"]))

    def test_aware_edit_and_skip_over_http(self):
        d = http_json("/api/session", "POST", {})
        sid, state = d["session"], d["state"]
        d = http_json(f"/api/{sid}/category/CAT04_RANSOMWARE", "POST", {"defer": True, "state": state})
        state = d["state"]
        self.assertTrue(d["board"]["case"]["aware_iso"])                 # 유형만 골라도 시계가 돈다
        self.assertTrue(d["board"]["asks"][0]["options"])
        d = http_json(f"/api/{sid}/aware", "POST", {"when": "30분 전", "state": state})
        state = d["state"]
        self.assertNotIn("aware", [x["id"] for x in d["board"]["asks"]])
        d = http_json(f"/api/{sid}/ask/skip", "POST", {"id": "backup", "state": state})
        self.assertNotIn("backup", [x["id"] for x in d["board"]["asks"]])
        try:
            http_json(f"/api/{sid}/aware", "POST", {"when": "언젠가", "state": d["state"]})
            self.fail("읽을 수 없는 시각은 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)

    def test_help_and_cta_in_html(self):
        _, html = http("/")
        for el in ('id="helpBtn"', 'id="helpModal"', 'id="howtoMore"', 'id="askCard"', 'id="nextCta"', 'id="awareEdit"'):
            self.assertIn(el, html)

    def test_howto_share_and_resume_ui_in_html(self):
        """v0.12 — 어떻게 하나요? · 저장·공유 · 진행 중인 사건 · 사건 파일 열기."""
        _, html = http("/")
        for el in ('id="howtoModal"', 'id="shareModal"', 'id="shareBtn"', 'id="recentCases"', 'id="caseFileInput"',
                   'id="shareIcs"', 'id="shareSave"', 'id="shareForget"'):
            self.assertIn(el, html)
        _, js = http("/static/app.js")
        for fn in ("function openHowto", "function buildIcs", "function shareSummary", "function importCase", "BEGIN:VALARM"):
            self.assertIn(fn, js)

    def test_howto_endpoint_offline(self):
        d = http_json("/api/session", "POST", {})
        sid, state = d["session"], d["state"]
        d = http_json(f"/api/{sid}/category/CAT04_RANSOMWARE", "POST", {"defer": True, "state": state})
        state = d["state"]
        a = d["board"]["actions"][0]
        self.assertEqual(a["howto"], "H_ISOLATE")
        self.assertIn("H_ISOLATE", d["board"]["howto"])
        res = http_json(f"/api/{sid}/howto", "POST", {"action": "암호화 범위 확인", "state": state})
        self.assertEqual(res["answer"], "")              # 키 없음 → 빈 답 + 118 안내
        self.assertIn("118", res["error"])
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            http(f"/api/{sid}/howto", "POST", {"action": "", "state": state})
        self.assertEqual(ctx.exception.code, 400)

    def test_case_file_import_with_new_sid(self):
        """사건 파일(state)만 있으면 새 sid로 그대로 다시 연다 — 다른 PC·다른 인스턴스."""
        sid = http_json("/api/session", "POST", {})["session"]
        d = http_json(f"/api/{sid}/scenario/s1_bec_account_change", "POST", {})
        key = d["board"]["actions"][0]["key"]
        d = http_json(f"/api/{sid}/action", "POST", {"key": key, "done": True, "state": d["state"]})
        app_module.SESSIONS.clear()
        b = http_json("/api/fabcdef0123456789/board", "POST", {"state": d["state"]})["board"]
        self.assertEqual(b["case"]["id"], d["board"]["case"]["id"])
        self.assertTrue(b["actions"][0]["done"])

    def test_unknown_session_returns_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            http("/api/nope/message", "POST", {"text": "hi"})
        self.assertEqual(ctx.exception.code, 404)

    def test_ransomware_scenario_over_http(self):
        sid = http_json("/api/session", "POST", {})["session"]
        board = http_json(f"/api/{sid}/scenario/s4_ransomware", "POST", {})["board"]
        self.assertEqual(board["severity"]["level"], "P1")
        self.assertEqual(board["classification"]["type"], "ransom")
        ids = {d["id"] for d in board["docs"]}
        self.assertIn("tpl_ransom_report", ids)
        self.assertIn("T7_staff_ransom", ids)
        status, md = http(f"/api/{sid}/doc/tpl_ransom_report")
        self.assertEqual(status, 200)
        self.assertIn("몸값 지불 금지", md)

    def test_category_selection_and_guide_over_http(self):
        sid = http_json("/api/session", "POST", {})["session"]
        data = http_json(f"/api/{sid}/category/CAT09_DDOS_OUTAGE", "POST", {})
        self.assertEqual(data["board"]["category"]["no"], 9)
        self.assertTrue(data["board"]["actions"])
        self.assertEqual(data["guide"]["status"], "offline")  # LINER_OFFLINE=1
        self.assertTrue(data["guide"]["answer"])

    def test_viz_offline_fallback_over_http(self):
        sid = http_json("/api/session", "POST", {})["session"]
        body = http_json(f"/api/{sid}/viz", "POST", {})
        self.assertFalse(body["viz"]["ok"])
        self.assertEqual(body["html"], "")
        self.assertTrue(body["viz"]["reason"])

    def test_stateless_resume_over_http(self):
        """서버 메모리를 비워도(다른 인스턴스) state 토큰으로 이어지는지 실제 HTTP로 확인."""
        sid = http_json("/api/session", "POST", {})["session"]
        data = http_json(f"/api/{sid}/replay/s1_bec_account_change", "POST", {})
        for st in data["steps"][:3]:
            data = http_json(f"/api/{sid}/message", "POST", {"text": st["text"]})
        state = data["state"]
        self.assertTrue(state)

        app_module.SESSIONS.clear()
        with self.assertRaises(urllib.error.HTTPError):
            http(f"/api/{sid}/board")

        board = http_json(f"/api/{sid}/board?state={state}")["board"]
        self.assertGreaterEqual(len(board["findings"]), 1)
        resumed = http_json(f"/api/{sid}/message", "POST", {"text": "방금 미래상사에서 1,870만 원을 이미 송금했다고 합니다.",
                                                             "state": state})
        self.assertEqual(resumed["board"]["severity"]["level"], "P1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
