"""플레이북 → 지금 할 일. 카드 선택과 경고(하지 말 것)를 결정적으로 만든다.

플레이북 원문(저자 개인 저작물)은 배포물에 포함하지 않는다(기획서 방침).
여기서는 data/playbook_tree.json에 구조화한 판단 기준만 쓴다.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

from .case import Case
from .classify import Classification
from .detect import DetectionResult
from .severity import Severity
from .timeutil import now_utc

DATA = Path(__file__).resolve().parent.parent / "data"

PHASES = (
    ("PH_0_10M", 0, 10),
    ("PH_10_60M", 10, 60),
    ("PH_1_4H", 60, 240),
    ("PH_4_24H", 240, 1440),
    ("PH_24_72H", 1440, 4320),
)


def load_tree() -> dict:
    return json.loads((DATA / "playbook_tree.json").read_text(encoding="utf-8"))


def select_cards(case: Case, det: DetectionResult, cls: Classification) -> list[str]:
    rules = set(det.rules_hit())
    cards: list[str] = []
    if case.value("transfer_status") in ("done", "pending"):
        cards.append("C12_1")
    if cls.type == "root":
        cards.append("C12_4")
        if "LR_SUSPICIOUS_SEND" in rules:
            cards.append("C12_3")
    elif cls.type == "ato" or "LR_SUSPICIOUS_SEND" in rules:
        cards.append("C12_3")
    if cls.type != "root" and ("LR_HIDING_RULE" in rules or any("계좌" in f.summary for f in det.findings)):
        cards.append("C12_2")
    if cls.type in ("lookalike", "spoof"):
        cards.append("C12_7")
    if any("Consent" in f.summary or "OAuth" in f.summary for f in det.findings):
        cards.append("C12_8")
    seen, out = set(), []
    for c in cards:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def phase_now(case: Case) -> dict:
    tree = load_tree()
    aware = case.aware_at
    minutes = int((now_utc() - aware).total_seconds() // 60) if aware else 0
    pid = "PH_0_10M"
    for key, lo, hi in PHASES:
        if lo <= minutes < hi:
            pid = key
            break
    if minutes >= PHASES[-1][2]:
        pid = PHASES[-1][0]
    for p in tree.get("phases", []):
        if p.get("id") == pid:
            return {"id": pid, "window": p.get("window"), "goal": p.get("goal", ""),
                    "tasks": p.get("tasks", []), "exit": p.get("exit", ""),
                    "elapsed_minutes": minutes}
    return {"id": pid, "window": "", "goal": "", "tasks": [], "exit": "", "elapsed_minutes": minutes}


def first_five(case: Case, det: DetectionResult) -> list[dict]:
    tree = load_tree()
    items = []
    transfer = case.value("transfer_status") in ("done", "pending")
    for it in tree["first_five"]["items"]:
        status = "대기"
        action = it["action"]
        if it["n"] == 1 and transfer:
            status = "최우선"
        if it["n"] == 2 and case.value("incident_type") in ("ato", "root"):
            status = "최우선"
        items.append({"n": it["n"], "action": action, "who": it["who"],
                      "done_when": it["done_when"], "status": status})
    return items


def urgent_branches(case: Case, det: DetectionResult) -> list[dict]:
    tree = load_tree()
    out = []
    rules = set(det.rules_hit())
    transfer = case.value("transfer_status")
    for b in tree["first_five"]["urgent_branches"]:
        cond = b["if"]
        hit = False
        if "송금" in cond:
            hit = transfer in ("done", "pending")
        if "로그인" in cond:
            hit = bool(rules & {"LR_HIDING_RULE", "LR_SUSPICIOUS_SEND", "LR_MAIL_ACCESS"})
        if hit:
            out.append({"if": cond, "do": b["do"], "ref_part": b.get("ref_part")})
    return out


def next_actions(case: Case, det: DetectionResult, cls: Classification, sev: Severity) -> list[dict]:
    tree = load_tree()
    cards = select_cards(case, det, cls)
    actions: list[dict] = []

    def push(text: str, who: str, ref: str, kind: str = "지금", priority: int = 5) -> None:
        if any(a["action"] == text for a in actions):
            return
        actions.append({"action": text, "who": who, "ref": ref, "kind": kind, "priority": priority})

    # 사실 기반 최우선 행동
    if case.value("transfer_status") in ("done", "pending"):
        push("송금 은행 공식 대표번호로 지급정지·회수(리콜) 요청 — 의심 메일 속 번호는 쓰지 않는다", "재무·대표", "12.1", "0~10분", 1)
        push("거래처(송금한 곳)에 원장 번호로 전화 — 거래처가 자기 은행에 지급정지 요청하도록 안내", "영업·재무", "7.4 ①", "0~10분", 2)
        push("경찰 사이버범죄 신고(ecrm.police.go.kr) 접수 — 은행 접수와 병행", "사건 책임자", "14.1", "0~10분", 3)
    if case.value("incident_type") == "ato":
        push("관리자 콘솔에서 의심 계정 일시 중지 + 모든 세션·토큰 철회(암호 변경만으로는 부족)", "IT/관리자", "2.1", "0~10분", 1)
        push("업무 메일 밖의 안전한 대응 채널 개설(전화·메신저) 후 참여자 명단 고정", "사건 책임자", "2.1", "0~10분", 2)
    if cls.type == "root":
        push("서버를 재부팅·재설치하거나 의심 프로세스·파일을 지우지 말고 그대로 보존(메모리·흔적 소실)", "IT/관리자", "2.7", "0~10분", 1)
        push("전문 사고대응 조직/CSP·메일 서비스 지원에 즉시 호출 — 서버 포렌식은 이 문서 범위 밖", "대표", "2.7", "0~10분", 1)
        push("메일 게이트웨이를 내부망에서 분리할지 결정(서비스 중단 영향 포함), 결정자·시각 기록", "대표·IT/관리자", "2.7", "15분", 3)
        push("업무 메일 밖의 안전한 대응 채널 개설(전화·메신저) 후 참여자 명단 고정", "사건 책임자", "2.1", "0~10분", 2)
    for cid in cards:
        card = tree["play_cards"].get(cid, {})
        for i, a in enumerate(card.get("first_15min", [])):
            push(a, _who_for(a), card.get("ref", {}).get("s", [""])[0], "15분", 4 + i // 3)
        for a in card.get("investigate", []):
            push(a, "IT/관리자", card.get("ref", {}).get("s", [""])[0], "조사", 8)
        # 통지·종결 항목은 문서 초안과 통과표에서 다루므로 '지금 할 일'에는 넣지 않는다.

    # 개인정보 판단
    if case.value("personal_data_leak") in ("suspected", "confirmed"):
        push("사서함에 보관된 개인정보 항목·규모 확인(이름·연락처·주소 등) — 확인된 범위로 신고", "개인정보 담당", "7.1", "조사", 6)

    # 플레이북 범위 밖
    if cls.type == "root":
        push("초동 조치(차단·보존·보고) 후 전문 대응 조직 즉시 호출 — 서버 자체 장악은 이 플레이북 범위 밖", "대표", "2.7", "지금", 1)

    actions.sort(key=lambda a: a["priority"])
    return actions[:12]


def _who_for(action: str) -> str:
    if any(k in action for k in ("은행", "지급", "송금")):
        return "재무·대표"
    if any(k in action for k in ("공지", "경고", "통보", "안내")):
        return "사건 책임자"
    if any(k in action for k in ("차단", "격리", "검색", "콘솔", "로그", "세션")):
        return "IT/관리자"
    return "사건 책임자"


def _similar(a: str, b: str) -> bool:
    """같은 행동을 다른 문장으로 두 번 나열하지 않기 위한 간이 유사도."""
    def toks(s: str) -> set[str]:
        return {w for w in re.split(r"[\s,/·—()]+", s) if len(w) >= 2}

    ta, tb = toks(a), toks(b)
    if not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= 0.45


def dont_do(case: Case, det: DetectionResult, cls: Classification) -> list[str]:
    tree = load_tree()
    out = list(tree.get("dont_do", []))
    if cls.type in ("ato", "root"):
        msg = "침해 계정(또는 그 계정이 포함된 스레드)으로 사고 공지·경고 메일 발송 금지 — 침해되지 않은 채널을 쓴다"
        out = [x for x in out if "침해 계정" not in x]
        out.insert(0, msg)
    if case.value("personal_data_leak") in ("suspected", "confirmed"):
        out.append("통지문에 주민번호·계좌번호 등 민감정보를 다시 적지 않는다(원문 노출)")
    if case.value("transfer_status") in ("done", "pending"):
        out.append("송금 회수 전에 원인 분석을 이유로 은행 연락을 미루지 않는다")
    if cls.type == "root":
        out = [x for x in out if "재부팅" not in x]
        out.append("재부팅·재설치·프로세스 즉시 삭제 금지 — 메모리·흔적이 사라진다")
    return out


def persistence_items(case: Case, det: DetectionResult) -> list[dict]:
    tree = load_tree()
    rules = set(det.rules_hit())
    found = []
    if "LR_HIDING_RULE" in rules:
        found.append("받은편지함 규칙")
    if "LR_PERSISTENCE" in rules:
        found.append("앱 비밀번호")
    if any("Consent" in f.summary for f in det.findings):
        found.append("OAuth 앱")
    out = []
    for item in tree.get("persistence_checklist", []):
        hit = any(f == item["cat"] or f in item["cat"] for f in found)
        out.append({"cat": item["cat"], "pattern": item["pattern"], "where": item["where"],
                    "action": item["action"], "status": "발견" if hit else "확인 필요"})
    return out


def recovery(case: Case, det: DetectionResult) -> list[dict]:
    tree = load_tree()
    out = []
    for i, item in enumerate(tree.get("recovery_gate", []), 1):
        out.append({"n": i, "item": item, "status": "미완료"})
    return out


def guardrail(text: str, case: Case, cls: Classification | None = None) -> list[str]:
    """사용자의 요청이 플레이북 금지 항목과 부딪히면 경고를 돌려준다.

    데모의 "하지 말 것 준수 시험"용. 실행을 대신하지 않고, 이유와 대안을 함께 준다.
    """
    t = (text or "").lower()
    warn: list[str] = []
    compromised = (cls and cls.type in ("ato", "root")) or case.value("incident_type") in ("ato", "root")
    sending = any(k in t for k in ("보내", "발송", "공지", "알려", "회신", "답장", "메일 보"))
    if compromised and sending and any(k in t for k in ("침해 계정", "그 계정", "해당 계정", "박서연", "피해 계정", "계정으로")):
        warn.append("침해된 계정으로는 발송하지 않습니다. 공격자가 그 메일을 보고 학습하며, 수신자는 진짜 공지인지 구분할 수 없습니다. "
                    "침해되지 않은 채널(대표 메일·전화·문자)과 별도 계정으로 보내야 합니다.")
    if sending and any(k in t for k in ("방금 메일 무시", "무시하세요", "잘못 보냄", "해킹당한")):
        warn.append("침해 가능성이 있는 계정에서 '방금 메일 무시하세요'를 보내는 것은 금지입니다(위험 신호를 오히려 키웁니다). "
                    "같은 수신자에게 안전한 채널로 경고문을 보내세요.")
    if any(k in t for k in ("삭제", "지워", "정리")) and any(k in t for k in ("로그", "규칙", "메일 원본", "증거")):
        warn.append("증거 보존 전 삭제는 금지입니다. 규칙은 '기록 후 비활성화', 메일은 원본(헤더 포함) 보존 후 격리하세요.")
    if any(k in t for k in ("암호만", "비밀번호만", "암호 바꾸")):
        warn.append("암호 변경만으로는 부족합니다. 세션·토큰 철회, 앱 비밀번호, OAuth 동의, 전달 규칙, 위임을 함께 제거해야 합니다.")
    if any(k in t for k in ("답장", "회신")) and any(k in t for k in ("공격자", "의심 메일", "피싱")):
        warn.append("공격자 메일에 답장해 확인하지 마세요. 원장에 있는 별도 번호로 확인합니다.")
    if any(k in t for k in ("피해 없", "괜찮", "문제 없")) and case.value("personal_data_leak") == "unknown":
        warn.append("'피해 없음'이라고 단정할 수 없습니다. 결과가 없다는 것은 '피해 없음'의 증거가 아닙니다(보존 기간·수집 범위 한계).")
    return warn
