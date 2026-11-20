"""증거 확보 도우미 — 로그를 직접 못 다루는 작은 회사를 위한 '무엇을·어디서·언제까지' 안내.

- 사용 환경(플랫폼)별 확보 항목·경로·보관 기간·못 구할 때 대안
- 확보 상태(have/cannot) 기록 → 신고서의 '파악된 범위'와 〔미확인〕을 가르는 근거
- 호스팅·IT 업체에 보낼 '로그 보존·제공 요청' 메일 초안(사건 기록으로 채움)
"""
from __future__ import annotations

import json
from datetime import timedelta
from functools import lru_cache
from pathlib import Path

from .case import PLATFORM_LABEL, Case
from .timeutil import kst_label

DATA = Path(__file__).resolve().parent.parent / "data" / "evidence_guide.json"

# 대화에서 사용 환경을 알아보는 단어
PLATFORM_WORDS = {
    "m365": ("m365", "오피스365", "office 365", "office365", "마이크로소프트 365", "아웃룩", "outlook", "exchange", "엑셀 온라인", " ms에서", "ms 계정", "microsoft"),
    "google": ("지메일", "gmail", "구글 워크스페이스", "google workspace", "g suite", "구글 메일"),
    "kr_mail": ("가비아", "하이웍스", "다우오피스", "네이버웍스", "네이버 웍스", "카페24 메일", "후이즈", "닷네임", "아이네임즈", "웹메일", "그룹웨어"),
    "windows": ("컴퓨터", " pc", "pc가", "pc에", "노트북", "윈도우", "바탕화면", "확장자"),
    "nas": ("nas", "나스", "시놀로지", "synology", "큐냅", "qnap", "파일 서버", "공유 폴더"),
    "web_hosting": ("쇼핑몰", "카페24", "고도몰", "메이크샵", "홈페이지", "웹호스팅", "웹 호스팅", "아임웹", "식스샵"),
}


@lru_cache(maxsize=1)
def load_guide() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def detect_platforms(text: str) -> list[str]:
    t = " " + (text or "").lower()
    return [pid for pid, words in PLATFORM_WORDS.items() if any(w in t for w in words)]


def recommended(case: Case) -> list[str]:
    """사건에 맞는 사용 환경 — 사용자가 말한 것이 먼저, 없으면 유형 기본값."""
    said = list(case.value("platform") or [])
    by_cat = load_guide()["category_platforms"].get(case.value("category") or "", [])
    out = said + [p for p in by_cat if p not in said]
    return out or ["kr_mail", "windows"]


def item_index() -> dict[str, dict]:
    g = load_guide()
    idx = {i["id"]: {**i, "platform": "always"} for i in g["always"]}
    for pid, p in g["platforms"].items():
        for i in p["items"]:
            idx[i["id"]] = {**i, "platform": pid}
    return idx


def view(case: Case) -> dict:
    """화면용 — 추천 환경 순서, 항목별 확보 상태."""
    g = load_guide()
    status = case.evidence or {}
    platforms = []
    for pid in recommended(case) + [p for p in g["platforms"] if p not in recommended(case)]:
        p = g["platforms"][pid]
        platforms.append({"id": pid, "name": p["name"], "who": p["who"], "recommended": pid in recommended(case),
                          "items": [{**i, "status": status.get(i["id"], "")} for i in p["items"]]})
    always = [{**i, "status": status.get(i["id"], "")} for i in g["always"]]
    have = sum(1 for v in status.values() if v == "have")
    cannot = sum(1 for v in status.values() if v == "cannot")
    return {"always": always, "platforms": platforms, "have": have, "cannot": cannot,
            "caveat": g["meta"]["caveat"], "principle": g["meta"]["principle"]}


def set_status(case: Case, item_id: str, status: str) -> bool:
    idx = item_index()
    if item_id not in idx or status not in ("have", "cannot", ""):
        return False
    if status:
        case.evidence[item_id] = status
    else:
        case.evidence.pop(item_id, None)
    case.log("evidence", f"{idx[item_id]['title']}: {status or '해제'}")
    return True


def status_lines(case: Case) -> tuple[list[str], list[str]]:
    """(확보한 증거, 못 구한 증거) 제목 목록 — 문서·브리핑용."""
    idx = item_index()
    have = [idx[k]["title"] for k, v in (case.evidence or {}).items() if v == "have" and k in idx]
    cannot = [idx[k]["title"] for k, v in (case.evidence or {}).items() if v == "cannot" and k in idx]
    return have, cannot


def request_letter(case: Case, platform: str) -> dict:
    """호스팅·IT 업체에 보낼 '로그 보존·제공 요청' 초안. 모르는 칸은 〔미확인〕."""
    g = load_guide()
    p = g["platforms"].get(platform)
    if not p:
        raise KeyError(platform)
    org = case.value("org_name") or "〔미확인: 회사명〕"
    account = case.value("account") or "〔미확인: 의심 계정(메일 주소)〕"
    aware = case.aware_at
    start = kst_label(aware - timedelta(days=14)) if aware else "〔미확인: 시작 일시〕"
    end = "현재" if aware else "〔미확인: 종료 일시〕"
    wants = "\n".join(f"  {n}. {i['title']}" + (f" — {i['retention']}" if i.get("retention") else "")
                      for n, i in enumerate(p["items"], 1))
    who = PLATFORM_LABEL.get(platform, p["name"])
    subject = f"[긴급] {org} 보안사고 관련 로그 보존 및 제공 요청"
    body = (
        f"{who} 담당자님께,\n\n"
        f"{org}입니다. {kst_label(aware) if aware else '〔미확인: 인지 일시〕'}에 보안사고(의심)를 인지하여 대응 중입니다. "
        "사고 경위 확인과 법정 신고(정보통신망법·개인정보 보호법)에 필요하여 아래 기록의 보존과 제공을 요청드립니다.\n\n"
        f"■ 대상 계정: {account}\n"
        f"■ 대상 기간: {start} ~ {end}\n"
        f"■ 요청 기록:\n{wants}\n\n"
        "■ 가장 먼저 부탁드릴 것: 보관 기간이 지나 삭제되지 않도록 위 기록을 지금 시점으로 '보존'해 주십시오. "
        "제공이 늦어지더라도 보존은 먼저 처리해 주시면 됩니다.\n"
        "■ 제공 형식: CSV·엑셀·화면 캡처 등 가능한 형식 모두 괜찮습니다.\n\n"
        "공격자가 이 메일 계정에 접근했을 가능성이 있어, 회신은 아래 별도 연락처로 부탁드립니다.\n"
        "■ 회신 연락처: 〔미확인: 담당자 이름·전화번호(침해되지 않은 채널)〕\n\n"
        f"감사합니다.\n{org} 드림\n"
    )
    return {"platform": platform, "to": p["who"], "subject": subject, "body": body,
            "note": "침해 의심 계정으로 보내지 마세요. 다른 계정·업체 고객센터 게시판·전화로 전달하세요."}
