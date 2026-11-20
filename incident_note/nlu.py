"""구어체 한국어에서 시각·사건을 뽑는 결정적 파서.

작은 회사 담당자는 로그 대신 "오늘 아침 8시 반에 발견했어요", "어제 저녁 7시 퇴근할 땐 괜찮았어요"처럼 말한다.
이 모듈은 그런 문장을 절대 시각(KST)과 타임라인 사건으로 바꾼다. 모르는 표현은 None 으로 남기고 추측하지 않는다.
Liner Mark 가 이 결과를 보강할 수 있지만, 여기서 잡힌 값이 기준이다.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))

_DAY = {"오늘": 0, "금일": 0, "어제": -1, "어저께": -1, "전날": -1, "그저께": -2, "그제": -2, "엊그제": -2}
_PART_PM = ("오후", "저녁", "밤")
_PART_AM = ("오전", "아침", "새벽")

# "오늘 아침 8시 반", "어제 저녁 7시", "오후 3시 20분", "10시쯤", "08:30"
_TIME_RE = re.compile(
    r"(?P<day>오늘|금일|어제|어저께|전날|그저께|그제|엊그제)?\s*"
    r"(?P<part>오전|오후|아침|저녁|밤|새벽|낮)?\s*"
    r"(?:(?P<h>\d{1,2})\s*시\s*(?:(?P<half>반)|(?P<m>\d{1,2})\s*분)?|(?P<hh>\d{1,2}):(?P<mm>\d{2}))"
)
_AGO_RE = re.compile(r"(?P<n>\d{1,3})\s*(?P<u>분|시간|일)\s*(?:전|쯤 전|정도 전)")
_DISCOVER = ("발견", "알았", "알게", "전화 받", "전화를 받", "전화가 왔", "연락 받", "연락이 왔", "확인했", "인지", "봤어", "보니")


def _now_kst(now: datetime | None) -> datetime:
    return (now or datetime.now(timezone.utc)).astimezone(KST)


def parse_time(text: str, now: datetime | None = None) -> datetime | None:
    """문장 속 첫 시각 표현을 KST datetime(UTC 변환 전)으로. 없으면 None."""
    base = _now_kst(now)
    m = _AGO_RE.search(text or "")
    if m:
        n = int(m.group("n"))
        delta = {"분": timedelta(minutes=n), "시간": timedelta(hours=n), "일": timedelta(days=n)}[m.group("u")]
        return (base - delta).replace(second=0, microsecond=0)
    if re.search(r"(방금|조금 전|아까 막)", text or ""):
        return base.replace(second=0, microsecond=0)
    for m in _TIME_RE.finditer(text or ""):
        if m.group("hh"):
            h, mi = int(m.group("hh")), int(m.group("mm"))
        else:
            h = int(m.group("h"))
            mi = 30 if m.group("half") else int(m.group("m") or 0)
        if not (0 <= h <= 24 and 0 <= mi < 60):
            continue
        part = m.group("part") or ""
        if part in _PART_PM and h < 12:
            h += 12
        elif part == "낮" and h < 7:
            h += 12
        elif part in _PART_AM and h == 12:
            h = 0
        day = _DAY.get(m.group("day") or "", None)
        cand = base.replace(hour=h % 24, minute=mi, second=0, microsecond=0)
        if day is not None:
            cand = cand + timedelta(days=day)
        elif cand > base + timedelta(minutes=5):
            # 날짜 없이 "10시쯤"이 지금보다 뒤면 어제로 본다(미래 시각으로 사건을 기록하지 않는다).
            if not part and h < 12 and (h + 12) * 60 + mi <= base.hour * 60 + base.minute:
                cand = cand.replace(hour=h + 12)
            else:
                cand = cand - timedelta(days=1)
        return cand
    return None


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?。])\s+|(?<=요)\s+|(?<=다)\s+|\n+", (text or "").strip())
    return [p.strip() for p in parts if p and p.strip()]


def extract_events(text: str, now: datetime | None = None) -> list[dict]:
    """시각 표현이 있는 문장을 사건으로. {when: KST datetime, what: 문장, discovery: 발견 문장인지}."""
    out = []
    for s in split_sentences(text):
        when = parse_time(s, now)
        if when is None:
            continue
        out.append({"when": when, "what": s[:160], "discovery": any(k in s for k in _DISCOVER)})
    return out


def negated(text: str, word_pattern: str) -> bool:
    """'안 보냈대요', '보내지 않았', '송금 안 했' 처럼 부정된 진술인지."""
    t = text or ""
    return bool(re.search(rf"(안|않|못|아직)\s*\S{{0,3}}\s*(?:{word_pattern})", t)
                or re.search(rf"(?:{word_pattern})\S{{0,4}}\s*(않|안\s|없|아니)", t)
                or re.search(r"(돈|송금|입금|이체).{0,8}(안\s*(보냈|했|함)|안했|하지 않|않았|없었|아직)", t))
