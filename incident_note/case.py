"""사건 상태 모델 — 사실(fact)마다 '확인/추정/미확인' 수준과 출처를 붙여 보관한다.

기획서의 핵심 원칙: "확인/추정/미확인을 섞지 않는다", "모르는 건 모른다고 한다".
그래서 모든 판단 입력을 Fact로 만들고, 어떤 문장도 수준 없이 만들어지지 않게 한다.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .timeutil import kst_label, now_utc, parse_kst_local, parse_ts

LEVELS = ("확인", "추정", "미확인")

# 사건 판단에 쓰는 표준 사실 키와 초기값
DEFAULT_FACTS: dict[str, Any] = {
    "org_name": None,
    "org_domains": [],
    "org_country": "KR",
    "org_size": None,
    "is_ict_service_provider": None,
    "incident_type": "unknown",       # ato | spoof | lookalike | root | unknown
    "account": None,
    "transfer_status": "unknown",     # none | pending | done | unknown
    "transfer_amount": None,
    "transfer_counterparty": None,
    "personal_data_leak": "unknown",  # none | suspected | confirmed | unknown
    "affected_count": None,
    "sensitive_or_unique_id": None,
    "external_illegal_access": None,
    "admin_compromise": None,
    "adversary_active": None,
    "insurance": None,
    "pi_data_types": None,
    "aware_at": None,
    "report_channel": None,
}

FACT_LABEL = {
    "org_name": "조직명",
    "org_domains": "조직 도메인",
    "org_country": "기준 국가",
    "org_size": "직원 수",
    "is_ict_service_provider": "정보통신서비스 제공자 여부",
    "incident_type": "사고 유형",
    "account": "침해 의심 계정",
    "transfer_status": "송금 상태",
    "transfer_amount": "송금 금액",
    "transfer_counterparty": "송금 상대",
    "personal_data_leak": "개인정보 유출 여부",
    "affected_count": "정보주체 수",
    "sensitive_or_unique_id": "민감·고유식별정보 포함",
    "external_illegal_access": "외부 불법접근",
    "admin_compromise": "관리자 권한 침해",
    "adversary_active": "공격자 잔류 여부",
    "insurance": "사이버 보험 가입",
    "pi_data_types": "유출 가능 개인정보 항목",
    "aware_at": "인지 시각",
    "report_channel": "신고 창구",
}


# 내부 코드값 → 화면·문서에 쓰는 한국어 표기
VALUE_LABEL = {
    "incident_type": {"ato": "메일 계정 탈취(ATO)", "spoof": "발신자 위조(스푸핑)",
                      "lookalike": "유사 도메인 사칭", "root": "서버 관리자 권한 탈취", "unknown": "판별 전"},
    "transfer_status": {"none": "송금 없음", "pending": "송금 진행·예정", "done": "송금 완료", "unknown": "미확인"},
    "personal_data_leak": {"none": "유출 흔적 없음", "suspected": "유출 의심", "confirmed": "유출 확인",
                           "unknown": "미확인"},
}


def display_value(key: str, val: Any) -> Any:
    """사실 값을 사람이 읽는 문장으로 바꾼다(판단 로직은 원래 값을 그대로 쓴다)."""
    if isinstance(val, datetime):
        return kst_label(val)
    if isinstance(val, bool):
        return "예" if val else "아니오"
    if key in VALUE_LABEL and isinstance(val, str):
        return VALUE_LABEL[key].get(val, val)
    if isinstance(val, (list, tuple, set)):
        return ", ".join(str(v) for v in val)
    if key == "affected_count" and isinstance(val, int):
        return f"{val:,}명"
    if key == "org_size" and isinstance(val, int):
        return f"{val}명"
    if key == "transfer_amount" and isinstance(val, int):
        return f"{val:,}원"
    return val


@dataclass
class Fact:
    value: Any = None
    level: str = "미확인"
    source: str = "미상"
    note: str = ""

    def to_dict(self) -> dict:
        return {"value": self.value, "level": self.level, "source": self.source, "note": self.note}


@dataclass
class Case:
    id: str = field(default_factory=lambda: "IN-" + uuid.uuid4().hex[:8].upper())
    created_at: datetime = field(default_factory=now_utc)
    facts: dict[str, Fact] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    eml_triage: list[dict] = field(default_factory=list)
    log_kinds: list[str] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)   # Liner 인용 출처
    law_checks: list[dict] = field(default_factory=list)
    docs: dict[str, dict] = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for k, v in DEFAULT_FACTS.items():
            self.facts.setdefault(k, Fact(v, "미확인", "미상"))

    # ---------------------------------------------------------------- 사실
    def set_fact(self, key: str, value: Any, level: str = "추정", source: str = "사용자 진술",
                 note: str = "") -> Fact:
        if level not in LEVELS:
            level = "미확인"
        if value is None or value == "":
            value, level = None, "미확인"
        self.facts[key] = Fact(value, level, source, note)
        return self.facts[key]

    def fact(self, key: str) -> Fact:
        return self.facts.get(key, Fact(None, "미확인", "미상"))

    def value(self, key: str, default: Any = None) -> Any:
        f = self.facts.get(key)
        return default if f is None or f.value is None else f.value

    def level(self, key: str) -> str:
        return self.facts.get(key, Fact()).level

    def known(self, key: str) -> bool:
        return self.level(key) in ("확인", "추정") and self.value(key) not in (None, "", [], "unknown")

    # ---------------------------------------------------------------- 인지 시각
    def set_aware_at(self, value: str | datetime, source: str = "사용자 진술") -> None:
        if isinstance(value, datetime):
            dt = value
        else:
            dt = parse_kst_local(value)
        self.set_fact("aware_at", dt, "확인", source)

    @property
    def aware_at(self) -> datetime | None:
        v = self.value("aware_at")
        if isinstance(v, str):
            return parse_ts(v)
        return v

    def aware_label(self) -> str:
        return kst_label(self.aware_at)

    # ---------------------------------------------------------------- 기록
    def log(self, kind: str, text: str) -> None:
        self.history.append({"at": now_utc().isoformat(), "kind": kind, "text": text})

    def summary(self) -> dict:
        return {
            "id": self.id,
            "title": self.title(),
            "aware_at": kst_label(self.aware_at) if self.aware_at else "미확인",
            "log_kinds": self.log_kinds,
            "findings": len(self.findings),
            "docs": sorted(self.docs),
            "sources": len(self.sources),
        }

    def title(self) -> str:
        org = self.value("org_name") or "조직"
        kind = {
            "ato": "메일 계정 침해",
            "spoof": "도메인 스푸핑",
            "lookalike": "유사 도메인 사칭",
            "root": "메일 서버 관리자 권한 탈취",
            "unknown": "메일 침해 의심",
        }.get(self.value("incident_type", "unknown"), "메일 침해 의심")
        return f"{org} {kind}"

    def facts_view(self) -> list[dict]:
        out = []
        for k, f in self.facts.items():
            if f.value in (None, "", [], "unknown"):
                continue
            val = f.value
            out.append({"key": k, "label": FACT_LABEL.get(k, k), "value": display_value(k, val),
                        "raw": val if not isinstance(val, datetime) else val.isoformat(),
                        "level": f.level, "source": f.source})
        return out

    def missing(self, keys: list[str]) -> list[str]:
        return [k for k in keys if not self.known(k)]
