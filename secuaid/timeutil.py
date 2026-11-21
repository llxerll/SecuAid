"""시간대 처리 — 모든 기록은 UTC로 보관하고 화면·문서에는 KST를 병기한다.

설계 원칙(플레이북 5.3):
- 원본 값을 절대 잃지 않는다. UTC 원본과 KST 변환값을 함께 남긴다.
- 시간대가 없는 값은 임의로 현지 시간으로 해석하지 않는다.
  M365 계열 로그는 UTC가 기본이므로 `assume_utc=True`를 명시적으로 넘긴다.
- 표기에는 항상 시간대를 붙인다.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
UTC = timezone.utc
WEEKDAYS_KR = ("월", "화", "수", "목", "금", "토", "일")

ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",
)


class TimeParseError(ValueError):
    """해석할 수 없는 시각 형식."""


def parse_ts(value: str | datetime | None, *, assume_utc: bool = True,
             default_year: int | None = None) -> datetime | None:
    """문자열 시각을 aware datetime(UTC)으로 변환한다.

    - 'Z' / '+09:00' 표기는 그대로 존중한다.
    - 시간대 없는 값은 assume_utc(기본 True)에 따라 UTC로 해석한다.
      (v0.2는 astimezone()을 써서 서버 로컬 시간으로 해석하는 버그가 있었다.)
    - syslog 형식 'Nov 16 11:22:03'은 연도가 없으므로 default_year를 쓴다.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC if assume_utc else KST)
        return dt.astimezone(UTC)

    s = str(value).strip().replace("\u00a0", " ")
    if not s:
        return None

    # ISO8601 (파이썬 3.11+는 대부분의 변형을 처리한다)
    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC if assume_utc else KST)
        return dt.astimezone(UTC)
    except ValueError:
        pass

    for fmt in ISO_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC if assume_utc else KST)
            return dt.astimezone(UTC)
        except ValueError:
            continue

    # syslog: 'Nov 16 11:22:03' — 연도가 없으므로 연도를 붙여 해석한다(1900년으로 먼저 읽으면 2월 29일이 실패한다).
    year = default_year or datetime.now(KST).year
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            dt = datetime.strptime(f"{year} {s}", "%Y " + fmt)
            return dt.replace(tzinfo=UTC if assume_utc else KST).astimezone(UTC)
        except ValueError:
            continue

    raise TimeParseError(f"시각 형식을 해석할 수 없습니다: {value!r}")


def to_kst(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(KST)


def kst_label(dt: datetime | None, *, with_year: bool = True, with_tz: bool = True) -> str:
    """'2026-11-16(월) 10:14 KST' 형태의 표기."""
    if dt is None:
        return "미확인"
    k = to_kst(dt)
    base = k.strftime("%Y-%m-%d") if with_year else k.strftime("%m/%d")
    out = f"{base}({WEEKDAYS_KR[k.weekday()]}) {k.strftime('%H:%M')}"
    return f"{out} KST" if with_tz else out


def utc_label(dt: datetime | None) -> str:
    if dt is None:
        return "미확인"
    u = dt.astimezone(UTC)
    return u.strftime("%Y-%m-%dT%H:%M:%SZ")


def kst_short(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    k = to_kst(dt)
    return f"{k.strftime('%m/%d %H:%M')} KST"


def human_delta(target: datetime, now: datetime | None = None) -> str:
    """마감까지 남은/지난 시간을 사람이 읽는 형태로. (음수면 경과)"""
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    delta = target - now
    total_min = int(round(delta.total_seconds() / 60))
    late = total_min < 0
    total_min = abs(total_min)
    days, rem = divmod(total_min, 60 * 24)
    hours, minutes = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}일")
    if hours:
        parts.append(f"{hours}시간")
    if minutes or not parts:
        parts.append(f"{minutes}분")
    return ("경과 " if late else "") + " ".join(parts) + (" 지남" if late else " 남음")


def parse_kst_local(value: str) -> datetime:
    """사용자가 입력한 'YYYY-MM-DD HH:MM'을 KST로 해석한다(인지 시각 입력용)."""
    dt = parse_ts(value, assume_utc=False)
    if dt is None:
        raise TimeParseError(f"시각을 읽을 수 없습니다: {value!r}")
    return dt


def now_utc() -> datetime:
    return datetime.now(UTC)
