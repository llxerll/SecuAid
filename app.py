"""인시던트 노트 웹 앱 — 사건 보드 + 대화형 에이전트.

실행: python app.py  (기본 http://127.0.0.1:8000, PORT 환경변수로 변경)
의존성: Flask 1개. Liner API는 표준 라이브러리(urllib)로 직접 호출한다.
"""
from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from incident_note.agent import SCENARIO_DIR, Agent
from incident_note.docs import to_docx
from incident_note.liner import LinerClient

ROOT = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=str(ROOT / "static"), template_folder=str(ROOT / "templates"))
app.config["JSON_AS_ASCII"] = False
app.json.ensure_ascii = False

SESSIONS: dict[str, Agent] = {}
LOCK = threading.Lock()


def _agent(sid: str) -> Agent | None:
    return SESSIONS.get(sid)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    client = LinerClient.from_env()
    status = client.status()
    return jsonify({"ok": True, "liner": status, "scenarios": Agent.scenarios()})


@app.get("/api/scenarios")
def scenarios():
    return jsonify({"scenarios": Agent.scenarios()})


@app.post("/api/session")
def new_session():
    body = request.get_json(silent=True) or {}
    agent = Agent(client=LinerClient.from_env())
    sid = uuid.uuid4().hex[:12]
    with LOCK:
        SESSIONS[sid] = agent
    scenario = body.get("scenario")
    if scenario:
        board = _run(agent, scenario_id=scenario, aware_at=body.get("aware_at"))
    else:
        board = agent.board(reply="사건을 알려주세요. 예: '거래처에서 우리가 계좌를 바꿨냐고 전화가 왔어요.' "
                                  "로그(CSV)나 메일 원본(.eml)을 붙여넣어도 됩니다.")
    return jsonify({"session": sid, "board": board})


@app.post("/api/<sid>/message")
def message(sid: str):
    agent = _agent(sid)
    if not agent:
        return jsonify({"error": "세션이 없습니다. 새로 시작해 주세요."}), 404
    text = (request.get_json(silent=True) or {}).get("text", "")
    board = agent.handle(text)
    return jsonify({"board": board})


@app.post("/api/<sid>/scenario/<scenario_id>")
def run_scenario(sid: str, scenario_id: str):
    agent = _agent(sid)
    if not agent:
        return jsonify({"error": "세션이 없습니다."}), 404
    body = request.get_json(silent=True) or {}
    try:
        board = _run(agent, scenario_id=scenario_id, aware_at=body.get("aware_at"))
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"board": board})


@app.get("/api/<sid>/board")
def get_board(sid: str):
    agent = _agent(sid)
    if not agent:
        return jsonify({"error": "세션이 없습니다."}), 404
    return jsonify({"board": agent.board()})


@app.post("/api/<sid>/docs")
def make_docs(sid: str):
    agent = _agent(sid)
    if not agent:
        return jsonify({"error": "세션이 없습니다."}), 404
    docs = agent.compose_docs()
    agent._recompute()
    return jsonify({"docs": docs, "board": agent.board()})


@app.get("/api/<sid>/doc/<doc_id>")
def get_doc(sid: str, doc_id: str):
    agent = _agent(sid)
    if not agent:
        return "세션이 없습니다.", 404
    doc = agent.case.docs.get(doc_id)
    if not doc:
        return "문서가 없습니다. 먼저 문서를 생성해 주세요.", 404
    return Response(doc["body"], mimetype="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{doc_id}.md"'})


@app.get("/api/<sid>/doc/<doc_id>.docx")
def get_docx(sid: str, doc_id: str):
    from incident_note.docs import Document

    agent = _agent(sid)
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


@app.get("/api/<sid>/report")
def report(sid: str):
    """테스트·데모 검증용 평문 리포트(마크다운)."""
    agent = _agent(sid)
    if not agent:
        return "세션이 없습니다.", 404
    board = agent.board()
    lines = [f"# {board['case']['title']} ({board['case']['id']})",
             f"- 인지: {board['case']['aware_at']} / 모드: {board['case']['mode']}",
             f"- 심각도: {board['severity']['level']} {board['severity']['name']} ({board['severity']['evidence_level']})",
             f"- 판별: {board['classification']['label']} ({board['classification']['level']})",
             "", "## 지금 할 일"]
    lines += [f"{a['priority']}. {a['action']} — {a['who']} (플레이북 {a['ref']})" for a in board["actions"]]
    lines += ["", "## 신고·통지 기한"]
    lines += [f"- [{d['status']}] {d['title']} → {d['to']} / {d['due']} ({d['remaining']}) — {d['why']}"
              for d in board["deadlines"]["items"]]
    lines += ["", "## 확인/추정/미확인"]
    lines += [f"- {f['label']}: {f['value']} [{f['level']}]" for f in board["facts"]]
    lines += ["", "## 타임라인(발췌)"]
    lines += [f"- {f['ts_kst']} (UTC {f['ts'][:16] if f['ts'] else '-'}) {f['rule_id']} {f['summary']}"
              for f in board["findings"][:25]]
    return Response("\n".join(lines), mimetype="text/markdown; charset=utf-8")


def _run(agent: Agent, *, scenario_id: str, aware_at: str | None = None) -> dict:
    """시나리오 한 번에 실행 — 데모·E2E 테스트 공용."""
    return agent.run_scenario(scenario_id, aware_at=aware_at)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
