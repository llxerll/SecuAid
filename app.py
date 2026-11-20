"""인시던트 노트 웹 앱 — 사건 보드 + 대화형 에이전트.

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
import threading
import uuid
from pathlib import Path

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


@app.get("/api/health")
def health():
    client = LinerClient.from_env()
    status = client.status()
    return _ok(payload={
        "ok": True,
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
    board = agent.handle(text)
    return _ok(agent, {"board": board})


@app.post("/api/<sid>/category/<category_id>")
def apply_category(sid: str, category_id: str):
    body = _body()
    agent = _agent(sid, body)
    if not agent:
        return _missing()
    try:
        board = agent.apply_category(category_id, guide=body.get("guide", True))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
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
        board = _run(agent, scenario_id=scenario_id, aware_at=body.get("aware_at"))
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


@app.get("/api/<sid>/board")
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
    docs = agent.compose_docs()
    agent._recompute()
    return _ok(agent, {"docs": docs, "board": agent.board()})


@app.get("/api/<sid>/doc/<doc_id>")
def get_doc(sid: str, doc_id: str):
    agent = _agent(sid, _body())
    if not agent:
        return "세션이 없습니다.", 404
    doc = agent.case.docs.get(doc_id)
    if not doc:
        return "문서가 없습니다. 먼저 문서를 생성해 주세요.", 404
    return Response(doc["body"], mimetype="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{doc_id}.md"'})


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
                    headers={"Content-Disposition": f'attachment; filename="{doc_id}.docx"'})


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
    name = f"{agent.case.id}_documents.zip"
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/<sid>/report")
def report(sid: str):
    """테스트·데모 검증용 평문 리포트(마크다운)."""
    agent = _agent(sid, _body())
    if not agent:
        return "세션이 없습니다.", 404
    return Response(_report_text(agent), mimetype="text/markdown; charset=utf-8")


def _report_text(agent: Agent) -> str:
    board = agent.board()
    lines = [f"# {board['case']['title']} ({board['case']['id']})",
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


def _run(agent: Agent, *, scenario_id: str, aware_at: str | None = None) -> dict:
    """시나리오 한 번에 실행 — 데모·E2E 테스트 공용."""
    return agent.run_scenario(scenario_id, aware_at=aware_at)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    # 같은 Wi-Fi의 휴대폰에서 열어 보려면 HOST=0.0.0.0 (기본은 로컬만)
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=False, threaded=True)
