"""시큐에이드 (SecuAid) 웹 앱 — 보안사고 초동대응 사건 보드 + 대화형 에이전트.

실행: python app.py  (기본 http://127.0.0.1:8000, PORT 환경변수로 변경)
Vercel: api/index.py 가 이 모듈의 `app` 을 노출한다(서버리스).

세션(v0.5)
- 서버 메모리(SESSIONS)는 캐시일 뿐이다. Vercel 같은 서버리스에서는 인스턴스가 바뀌면 사라진다.
- 그래서 모든 응답이 `state` 토큰(사건 상태의 zlib+base64 스냅샷)을 함께 주고,
  요청에 그 토큰이 실려 오면 서버가 즉시 `Agent` 를 복원한다(없으면 404).
- 기존 경로(`/api/session`, `/api/<sid>/message`)는 그대로라 예전 테스트·클라이언트도 깨지지 않는다.
"""
from __future__ import annotations

import os
import re
import threading
import uuid
from pathlib import Path
from urllib.parse import quote

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from incident_note import categories as category_mod
from incident_note.agent import SCENARIO_DIR, Agent
from incident_note.docs import to_docx
from incident_note.liner import LinerClient

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(ROOT / "static"), template_folder=str(ROOT / "templates"))
app.config["JSON_AS_ASCII"] = False
app.json.ensure_ascii = False

SESSIONS: dict[str, Agent] = {}
DATA_DIR = ROOT / "data"
LOCK = threading.Lock()
MAX_STATE_CHARS = 4_000_000          # 토큰 폭주 방지(약 4MB)

BRAND_KO = "시큐에이드"
BRAND_EN = "SecuAid"


# --------------------------------------------------------------------------- 세션·상태
def _body() -> dict:
    return request.get_json(silent=True) or {}


def _token(body: dict | None = None) -> str:
    token = (body or {}).get("state") or request.args.get("state") or request.headers.get("X-Case-State") or ""
    return token if isinstance(token, str) and len(token) <= MAX_STATE_CHARS else ""


def _agent(sid: str, body: dict | None = None) -> Agent | None:
    agent = SESSIONS.get(sid)
    if agent is not None:
        return agent
    token = _token(body)
    if not token:
        return None
    try:
        agent = Agent.from_token(token, client=LinerClient.from_env())
    except Exception:  # noqa: BLE001 - 잘못된 토큰은 '세션 없음'과 같이 처리한다
        return None
    with LOCK:
        SESSIONS[sid] = agent
    return agent


def _ok(agent: Agent | None = None, payload: dict | None = None):
    data = dict(payload or {})
    if agent is not None:
        try:
            data["state"] = agent.snapshot_token()
        except Exception:  # noqa: BLE001 - 직렬화 실패가 응답을 막지 않게
            pass
    return jsonify(data)


def _missing():
    return jsonify({"error": "세션이 없습니다. 새로 시작해 주세요."}), 404


# --------------------------------------------------------------------------- 화면
@app.errorhandler(Exception)
def _on_error(exc):
    """서버리스에서 번들 누락(data/ 등)으로 500이 나면 원인을 바로 알 수 있게 한다."""
    if isinstance(exc, HTTPException):
        return exc
    return jsonify({
        "error": f"서버 오류: {exc.__class__.__name__}: {str(exc)[:200]}",
        "hint": "Vercel이면 vercel.json 의 functions.includeFiles 에 data/ templates/ static/ incident_note/ 가 포함됐는지 확인하세요.",
    }), 500


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/favicon.ico")
def favicon():
    """브라우저 탭은 /favicon.ico 를 따로 요청하고 오래 캐시한다 — 404면 예전·기본 아이콘이 남는다."""
    return app.send_static_file("favicon.ico")


@app.get("/api/health")
def health():
    client = LinerClient.from_env()
    status = client.status(probe=request.args.get("probe") == "1")
    return _ok(payload={
        "ok": True,
        "region": os.environ.get("VERCEL_REGION", "local"),
        "brand": {"name": BRAND_KO, "en": BRAND_EN,
                  "subtitle": "중소·소호 기업 보안사고 초동대응 파트너"},
        "liner": status,
        "files_ok": DATA_DIR.exists() and (DATA_DIR / "playbook_tree.json").exists(),
        "features": {"quick_answer": status.get("available", False),
                     "visualization": status.get("available", False),
                     "stateless": True, "categories": 10},
        "categories": category_mod.all_categories(),
        "scenarios": Agent.scenarios(),
    })


@app.get("/api/scenarios")
def scenarios():
    return _ok(payload={"scenarios": Agent.scenarios()})


@app.get("/api/categories")
def categories():
    return _ok(payload={"categories": category_mod.all_categories(),
                        "deep": [c["id"] for c in category_mod.all_categories() if c["deep"]]})


# --------------------------------------------------------------------------- 사건 시작·대화
@app.post("/api/session")
def new_session():
    body = _body()
    agent = Agent(client=LinerClient.from_env())
    sid = uuid.uuid4().hex[:12]
    with LOCK:
        SESSIONS[sid] = agent
    category = body.get("category")
    scenario = body.get("scenario")
    if category:
        board = agent.apply_category(category, guide=bool(body.get("guide", True)))
        board["reply"] = (board.get("reply") or "") + "\n시나리오를 함께 보려면 [▶ 단계별 재생]을 누르세요."
    elif scenario:
        board = _run(agent, scenario_id=scenario, aware_at=body.get("aware_at"))
    else:
        board = agent.board(reply="사건을 알려주세요. 예: '거래처에서 우리가 계좌를 바꿨냐고 전화가 왔어요.' "
                                  "로그(CSV)나 메일 원본(.eml)을 붙여넣어도 됩니다. "
                                  "위의 10대 사고 유형에서 고르면 공통 초동조치와 기한이 바로 계산됩니다.")
    return _ok(agent, {"session": sid, "board": board, "guide": board.get("guide")})


@app.post("/api/<sid>/message")
def message(sid: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    text = (body or {}).get("text", "")
    board = agent.handle(text, defer=bool(body.get("defer")))
    return _ok(agent, {"board": board})


@app.post("/api/<sid>/enrich")
def enrich(sid: str):
    """Liner 보강(사실 보조 추출 → 브리핑·즉답 가이드 동시 호출). 판정은 /message 가 이미 돌려줬다."""
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    tasks = body.get("tasks") or ["narrate"]
    out = agent.enrich([str(t) for t in tasks][:4], text=str(body.get("text") or "")[:4000])
    return _ok(agent, {**out, "board": agent.board()})


@app.post("/api/<sid>/law")
def law_check(sid: str):
    """법령 재확인(Search Agent ∥ Search)만 수행하고 결과를 돌려준다 — 사건 상태는 바꾸지 않는다.

    20~30초 걸리므로 화면은 이 요청을 다른 요청과 동시에 보내고, 끝나면 /law/merge 로 붙인다.
    """
    agent = _agent(sid, _body())
    if not agent:
        return _missing()
    return jsonify({"law_check": agent.fetch_law_check()})


@app.post("/api/<sid>/law/merge")
def law_merge(sid: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    agent.merge_law_check(body.get("law_check") or {})
    agent._recompute()
    return _ok(agent, {"board": agent.board()})


# --------------------------------------------------------------------------- 로그 없이도: 진술 타임라인 · 증거 확보 도우미
@app.post("/api/<sid>/event")
def add_event(sid: str):
    """'기억나는 일' 한 줄을 타임라인에 — 시각은 '2026-11-20 08:30' 또는 '오늘 아침 8시 반' 모두 받는다."""
    from incident_note import nlu
    from incident_note.timeutil import parse_kst_local

    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    what = str(body.get("what") or "").strip()[:200]
    if not what:
        return jsonify({"error": "무슨 일이 있었는지 적어 주세요."}), 400
    raw = str(body.get("when") or "").strip()
    when = None
    if raw:
        try:
            when = parse_kst_local(raw.replace("T", " "))
        except Exception:  # noqa: BLE001 - 구어체 시각
            when = nlu.parse_time(raw)
    level = body.get("level") if body.get("level") in ("확인", "추정") else "확인"
    agent.add_event(when, what, level, "사용자 기록")
    if body.get("discovery") and when:
        agent.case.set_aware_at(when, source="사용자 기록(발견 시각)", level=level)
    agent._recompute()
    return _ok(agent, {"board": agent.board()})


@app.post("/api/<sid>/event/delete")
def delete_event(sid: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    agent.remove_event(str(body.get("id") or ""))
    agent._recompute()
    return _ok(agent, {"board": agent.board()})


@app.post("/api/<sid>/evidence")
def set_evidence(sid: str):
    from incident_note import evidence as evidence_mod

    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    if not evidence_mod.set_status(agent.case, str(body.get("item") or ""), str(body.get("status") or "")):
        return jsonify({"error": "알 수 없는 항목입니다."}), 400
    agent._recompute()
    return _ok(agent, {"board": agent.board()})


@app.post("/api/<sid>/evidence/request")
def evidence_request(sid: str):
    """호스팅·IT 업체에 보낼 '로그 보존·제공 요청' 초안 — 상태를 바꾸지 않는다."""
    from incident_note import evidence as evidence_mod

    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    try:
        return jsonify({"letter": evidence_mod.request_letter(agent.case, str(body.get("platform") or ""))})
    except KeyError:
        return jsonify({"error": "알 수 없는 사용 환경입니다."}), 400


@app.post("/api/<sid>/evidence/search")
def evidence_search(sid: str):
    """Liner Search로 해당 업체의 공식 안내(로그 확인 방법)를 찾는다 — 상태를 바꾸지 않는다."""
    from incident_note import evidence as evidence_mod
    from incident_note.liner import LinerError

    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    g = evidence_mod.load_guide()["platforms"].get(str(body.get("platform") or ""))
    if not g:
        return jsonify({"error": "알 수 없는 사용 환경입니다."}), 400
    item = str(body.get("item") or "")
    item_title = next((i["title"] for i in g["items"] if i["id"] == item), "로그인 기록·접속 기록")
    query = f"{g['name'].split('(')[0]} {item_title} 확인 방법"
    if not agent.client.available:
        return jsonify({"results": [], "query": query, "error": "Liner 키가 없어 검색할 수 없습니다."})
    try:
        results = agent.client.search_web(query, max_results=5)
    except LinerError as exc:
        return jsonify({"results": [], "query": query, "error": str(exc)[:160]})
    return jsonify({"results": results, "query": query})


@app.post("/api/<sid>/action")
def toggle_action(sid: str):
    """지금 할 일 체크/해제 — 완료 시각이 신고서 '현재까지의 대응'에 들어간다."""
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    mark = agent.set_action_done(str(body.get("key") or ""), bool(body.get("done")))
    if mark is None:
        return jsonify({"error": "해당 항목이 없습니다."}), 404
    return _ok(agent, {"mark": mark, "board": agent.board()})


@app.post("/api/<sid>/category/<category_id>")
def apply_category(sid: str, category_id: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    defer = bool(body.get("defer"))
    try:
        board = agent.apply_category(category_id, guide=False if defer else body.get("guide", True))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    if defer and agent.client.available:
        board["pending"] = ["guide"]
    return _ok(agent, {"board": board, "category": board.get("category"),
                       "guide": board.get("guide")})


@app.post("/api/<sid>/guide")
def refresh_guide(sid: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    guide = agent.quick_guide(force=bool(body.get("force", True)))
    return _ok(agent, {"guide": guide, "board": agent.board()})


@app.post("/api/<sid>/scenario/<scenario_id>")
def run_scenario(sid: str, scenario_id: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    try:
        board = _run(agent, scenario_id=scenario_id, aware_at=body.get("aware_at"),
                     defer=bool(body.get("defer")))
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    return _ok(agent, {"board": board})


@app.post("/api/<sid>/replay/<scenario_id>")
def start_replay(sid: str, scenario_id: str):
    """단계별 재생: 사건을 비우고 데모 입력 목록을 돌려준다. 화면이 /message 로 하나씩 보낸다."""
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    try:
        steps = agent.start_replay(scenario_id, aware_at=body.get("aware_at"))
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    return _ok(agent, {"steps": steps, "board": agent.board()})


@app.route("/api/<sid>/board", methods=["GET", "POST"])
def get_board(sid: str):
    agent = _agent(sid, _body())
    if not agent:
        return _missing()
    return _ok(agent, {"board": agent.board()})


# --------------------------------------------------------------------------- 시각화 (v0.5)
@app.post("/api/<sid>/viz")
def make_viz(sid: str):
    """Visualization API — 성공하면 iframe srcdoc 용 HTML, 실패하면 폴백 사유."""
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    viz = agent.visualize(force=bool(body.get("force", False)))
    return _ok(agent, {"viz": agent.viz_public(), "board": agent.board(),
                       "html": viz.get("html", "") if viz.get("ok") else "",
                       "references": viz.get("references", [])})


# --------------------------------------------------------------------------- 문서
@app.post("/api/<sid>/docs")
def make_docs(sid: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    docs = agent.compose_docs(wait_law=not body.get("defer"))
    agent._recompute()
    return _ok(agent, {"docs": docs, "board": agent.board()})


def _safe_name(text: str) -> str:
    """파일명에 쓸 수 없는 문자만 바꾼다 — 한글 제목을 그대로 살린다."""
    return re.sub(r'[\\/:*?"<>|\r\n\t]+', "_", text or "").strip(" ._") or "document"


def _attachment(korean_name: str, fallback: str) -> dict:
    """한글 파일명은 filename*=UTF-8'' 로, 옛 클라이언트용 ASCII 이름은 filename= 으로."""
    ascii_name = re.sub(r"[^A-Za-z0-9._-]+", "_", fallback) or "download"
    return {
        "Content-Disposition":
            f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(korean_name, safe="")}',
        "Cache-Control": "no-store",
    }


def _doc_filename(doc_id: str, doc: dict, ext: str) -> str:
    title = _safe_name(doc.get("title") or doc_id)
    return f"시큐에이드_{title}_{doc_id}.{ext}"


@app.get("/api/<sid>/doc/<doc_id>")
def get_doc(sid: str, doc_id: str):
    agent = _agent(sid, _body())
    if not agent:
        return "세션이 없습니다.", 404
    doc = agent.case.docs.get(doc_id)
    if not doc:
        return "문서가 없습니다. 먼저 문서를 생성해 주세요.", 404
    return Response(doc["body"], mimetype="text/markdown; charset=utf-8",
                    headers=_attachment(_doc_filename(doc_id, doc, "md"), f"SecuAid_{doc_id}.md"))


@app.post("/api/<sid>/download/zip")
def download_zip(sid: str):
    """POST 다운로드 — state 토큰을 본문에 실을 수 있어 서버리스에서 URL 길이 제한을 피한다."""
    return get_docs_zip(sid)


@app.post("/api/<sid>/download/<doc_id>")
def download_doc(sid: str, doc_id: str):
    """POST 다운로드(.md / .docx) — 화면의 [MD]·[DOCX] 버튼이 사용한다."""
    if doc_id.endswith(".docx"):
        return get_docx(sid, doc_id[:-5])
    return get_doc(sid, doc_id)


@app.get("/api/<sid>/doc/<doc_id>.docx")
def get_docx(sid: str, doc_id: str):
    from incident_note.docs import Document

    agent = _agent(sid, _body())
    if not agent:
        return "세션이 없습니다.", 404
    doc = agent.case.docs.get(doc_id)
    if not doc:
        return "문서가 없습니다. 먼저 문서를 생성해 주세요.", 404
    data = to_docx(Document(doc["id"], doc["title"], doc["kind"], doc["body"]))
    if data is None:
        return "python-docx가 설치되어 있지 않습니다. Markdown으로 받아 주세요.", 501
    return Response(data, mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers=_attachment(_doc_filename(doc_id, doc, "docx"), f"SecuAid_{doc_id}.docx"))


@app.get("/api/<sid>/docs.zip")
def get_docs_zip(sid: str):
    """생성된 문서 전체를 한 번에 — Markdown + (가능하면) DOCX + 사건 리포트."""
    import io
    import zipfile

    from incident_note.docs import Document

    agent = _agent(sid, _body())
    if not agent:
        return "세션이 없습니다.", 404
    if not agent.case.docs:
        return "문서가 없습니다. 먼저 문서를 생성해 주세요.", 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("00_사건_리포트.md", _report_text(agent))
        for i, (doc_id, doc) in enumerate(agent.case.docs.items(), 1):
            base = f"{i:02d}_{doc_id}"
            zf.writestr(f"{base}.md", doc["body"])
            data = to_docx(Document(doc["id"], doc["title"], doc["kind"], doc["body"]))
            if data:
                zf.writestr(f"{base}.docx", data)
    name = f"시큐에이드_사건문서_{agent.case.id}.zip"
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers=_attachment(name, f"SecuAid_documents_{agent.case.id}.zip"))


@app.get("/api/<sid>/report")
def report(sid: str):
    """테스트·데모 검증용 평문 리포트(마크다운)."""
    agent = _agent(sid, _body())
    if not agent:
        return "세션이 없습니다.", 404
    return Response(_report_text(agent), mimetype="text/markdown; charset=utf-8")


def _report_text(agent: Agent) -> str:
    board = agent.board()
    lines = [f"# {BRAND_KO} ({BRAND_EN}) — 사건 리포트",
             f"> {board['case']['title']} ({board['case']['id']})",
             f"- 인지: {board['case']['aware_at']} / 모드: {board['case']['mode']}",
             f"- 유형: {(board.get('category') or {}).get('name', '미선택')}",
             f"- 심각도: {board['severity']['level']} {board['severity']['name']} ({board['severity']['evidence_level']})",
             f"- 판별: {board['classification']['label']} ({board['classification']['level']})",
             "", "## 지금 할 일"]
    lines += [f"{a['priority']}. {a['action']} — {a['who']} (플레이북 {a['ref']})" for a in board["actions"]]
    lines += ["", "## 신고·통지 기한"]
    lines += [f"- [{d['status']}] {d['title']} → {d['to']} / {d['due'] or '미확인'}"
              f"{(' (' + d['remaining'] + ')') if d.get('remaining') else ''} — {d['why']}"
              for d in board["deadlines"]["items"]]
    lines += ["", "## 확인/추정/미확인"]
    lines += [f"- {f['label']}: {f['value']} [{f['level']}]" for f in board["facts"]]
    lines += ["", "## 타임라인(발췌)"]
    lines += [f"- {f['ts_kst']} (UTC {f['ts'][:16] if f['ts'] else '-'}) {f['rule_id']} {f['summary']}"
              for f in board["findings"][:25]]
    if board.get("severity_history"):
        lines += ["", "## 심각도 변화"]
        lines += [f"- {h['at']} {h['level']} {h['name']} — {h['reason']}" for h in board["severity_history"]]
    if board.get("guide"):
        g = board["guide"]
        lines += ["", f"## 유형 즉답 가이드 ({'Liner Quick Answer' if g.get('status') == 'live' else '규칙 기반'})",
                  g.get("answer", "")]
    return "\n".join(lines)


def _run(agent: Agent, *, scenario_id: str, aware_at: str | None = None, defer: bool = False) -> dict:
    """시나리오 한 번에 실행 — 데모·E2E 테스트 공용."""
    return agent.run_scenario(scenario_id, aware_at=aware_at, defer=defer)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    # 같은 Wi-Fi의 휴대폰에서 열어 보려면 HOST=0.0.0.0 (기본은 로컬만)
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=False, threaded=True)
