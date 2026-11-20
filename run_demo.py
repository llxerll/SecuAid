"""시큐에이드 (SecuAid) — CLI 데모 실행기.

웹 UI 없이도 한 사건을 끝까지 돌려 보고 결과를 마크다운으로 남긴다.
Liner 키가 없으면 자동으로 규칙 기반 모드로 실행된다.

예)
  python run_demo.py                          # S1 메인 데모
  python run_demo.py --scenario s4_ransomware     # 랜섬웨어(v0.5)
  python run_demo.py --category CAT04_RANSOMWARE  # 10대 유형만 골라 공통 흐름(v0.5)
  python run_demo.py --scenario s2_lookalike_domain
  python run_demo.py --out out/s1            # 리포트 + 문서 초안 저장
  python run_demo.py --json                  # 보드 전체 JSON 출력
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from incident_note.agent import Agent
from incident_note.liner import LinerClient
from incident_note.timeutil import now_utc


def render_markdown(board: dict) -> str:
    case = board["case"]
    sev = board["severity"]
    cls = board["classification"]
    lines = [
        f"# {case['title']} ({case['id']})",
        "",
        f"- 인지 시각: {case['aware_at']}",
        f"- 실행 모드: {case['mode']}",
        f"- 심각도: **{sev['level']} {sev['name']}** (근거 수준 {sev['evidence_level']})",
        f"- 판별: **{cls['label']}** ({cls['level']})",
        f"- 10대 유형: {((board.get('category') or {}).get('name') or '미선택')}",
        f"- 탐지: {len(board['findings'])}건 / 의심 IP {len(board['suspect_ips'])}개 / 로그 {', '.join(board['log_kinds']) or '없음'}",
        "",
        "## 판별 근거",
    ]
    lines += [f"- {b}" for b in cls["basis"]] or ["- 없음"]
    lines += ["", "## 지금 할 일"]
    lines += [f"{i}. {a['action']} — {a['who']} (플레이북 {a['ref']})"
              for i, a in enumerate(board["actions"], 1)]
    lines += ["", "## 신고·통지 기한"]
    for d in board["deadlines"]["items"]:
        lines.append(f"- **[{d['status']}] {d['title']}** → {d['to']} / 마감 {d['due'] or '미확인'}"
                     f"{(' (' + d['remaining'] + ')') if d.get('remaining') else ''}")
        lines.append(f"  - 판단 근거: {d['why']} · 근거 조항: {d['legal_ref']}")
    ops = [o for o in board["deadlines"]["operational"] if o["triggered"]]
    if ops:
        lines += ["", "### 운영상 연락(법정 신고 아님)"]
        lines += [f"- {o['title']}: {o['how']}" for o in ops]
    lines += ["", "## 확인 / 추정 / 미확인"]
    lines += [f"- {f['label']}: {f['value']} 〈{f['level']} / {f['source']}〉" for f in board["facts"]]
    if board["missing"]:
        lines += ["", "## 추가 확인 필요"]
        lines += [f"- {m}" for m in board["missing"]]
    lines += ["", "## 타임라인"]
    lines += [f"- {f['ts_kst']} (UTC {f['ts'][:16] if f['ts'] else '-'}) `{f['rule_id']}` {f['summary']}"
              for f in board["findings"][:40]]
    lines += ["", "## 하지 말 것"]
    lines += [f"- {d}" for d in board["dont_do"]]
    if board["law_checks"]:
        law = board["law_checks"][0]
        lines += ["", "## 법령 재확인 (Liner Search Agent)"]
        lines.append(f"- 상태: {law['status']} / 기한 추출: {law.get('hours')} / 차이: {law.get('drift') or '없음'}")
        if law.get("answer"):
            lines += ["", "> " + law["answer"].replace("\n", "\n> ")[:1500]]
    if board["sources"]:
        lines += ["", "## 출처 (Liner)"]
        lines += [f"- [{s['title'] or s['url']}]({s['url']})" for s in board["sources"][:10]]
    lines += ["", "## 문서 초안"]
    lines += [f"- {d['title']} (`{d['id']}`)" for d in board["docs"]]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="시큐에이드 CLI 데모")
    ap.add_argument("--scenario", default="s1_bec_account_change")
    ap.add_argument("--category", default=None,
                    help="10대 사고 유형 id/번호 (예: CAT04_RANSOMWARE 또는 4) — 시나리오 없이 공통 흐름 실행")
    ap.add_argument("--aware-at", default=None, help="인지 시각 재정의 (예: '2026-11-19 09:05')")
    ap.add_argument("--out", default=None, help="결과 저장 디렉터리")
    ap.add_argument("--json", action="store_true", help="보드 JSON을 표준출력으로")
    ap.add_argument("--offline", action="store_true", help="Liner 호출 없이 규칙 기반으로 실행")
    args = ap.parse_args()

    client = LinerClient.from_env()
    if args.offline:
        client.offline = True
    agent = Agent(client=client)
    if args.category:
        board = agent.apply_category(args.category)
    else:
        board = agent.run_scenario(args.scenario, aware_at=args.aware_at)

    if args.json:
        print(json.dumps(board, ensure_ascii=False, indent=2, default=str))
        return

    md = render_markdown(board)
    print(md)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.md").write_text(md, encoding="utf-8")
        for doc in agent.case.docs.values():
            (out / f"{doc['id']}.md").write_text(doc["body"], encoding="utf-8")
        (out / "board.json").write_text(json.dumps(board, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(f"\n저장: {out.resolve()} ({now_utc().isoformat()})")


if __name__ == "__main__":
    main()
