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
    # v0.5 — 10대 유형 선택 · 랜섬웨어 전용 사실
    "category": None,                 # CAT01_... ~ CAT10_...
    "category_label": None,
    "category_severity": None,        # 유형 기본 심각도(P1~P4)
    "ransomware_confirmed": None,     # 파일 암호화·랜섬노트로 확인
    "ransom_note": None,              # 랜섬노트 파일 경로
    "encrypted_hosts": None,          # 암호화 확인 호스트 수
    "encrypted_files": None,          # 암호화 확인 파일 수
    "encrypted_ext": None,            # 변조 확장자(.locked 등)
    "backup_status": None,            # offline_safe | at_risk | unknown
    "backup_isolated": None,          # 백업 분리 완료
    "shadow_copies_deleted": None,    # 볼륨 섀도 복사본 삭제
    "ransom_amount": None,            # 요구 금액(문자열)
    "ransom_paid": None,              # 몸값 지불 여부
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
    "category": "10대 사고 유형",
    "category_label": "10대 사고 유형명",
    "category_severity": "유형 기본 심각도",
    "ransomware_confirmed": "랜섬웨어 감염 확인",
    "ransom_note": "랜섬노트",
    "encrypted_hosts": "암호화 확인 호스트",
    "encrypted_files": "암호화 확인 파일",
    "encrypted_ext": "변조 확장자",
    "backup_status": "백업 상태",
    "backup_isolated": "백업 분리",
    "shadow_copies_deleted": "섀도 복사본 삭제",
    "ransom_amount": "몸값 요구액",
    "ransom_paid": "몸값 지불",
}


# 내부 코드값 → 화면·문서에 쓰는 한국어 표기
VALUE_LABEL = {
    "incident_type": {"ato": "메일 계정 탈취(ATO)", "spoof": "발신자 위조(스푸핑)",
                      "lookalike": "유사 도메인 사칭", "root": "서버 관리자 권한 탈취",
                      "ransom": "랜섬웨어 감염", "cloud": "클라우드·API 키 유출",
                      "webdb": "웹 애플리케이션·DB 유출", "insider": "내부자 정보 유출",
                      "ddos": "DDoS·서비스 장애", "supply": "공급망·악성코드 감염", "unknown": "판별 전"},
    "transfer_status": {"none": "송금 없음", "pending": "송금 진행·예정", "done": "송금 완료", "unknown": "미확인"},
    "personal_data_leak": {"none": "유출 흔적 없음", "suspected": "유출 의심", "confirmed": "유출 확인",
                           "unknown": "미확인"},
    "backup_status": {"offline_safe": "오프라인 사본 확보", "at_risk": "백업이 같은 망에 노출",
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
    if key == "encrypted_hosts" and isinstance(val, int):
        return f"{val}대"
    if key == "encrypted_files" and isinstance(val, int):
        return f"{val:,}개"
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
    guides: dict[str, dict] = field(default_factory=dict)   # 10대 유형별 Quick Answer 가이드
    viz: dict | None = None                                  # Visualization API 결과
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
            "ransom": "랜섬웨어 감염",
            "cloud": "클라우드·API 키 유출",
            "webdb": "웹 애플리케이션·DB 유출",
            "insider": "내부자 정보 유출",
            "ddos": "DDoS·서비스 장애",
            "supply": "공급망·악성코드 감염",
            "unknown": "메일 침해 의심",
        }.get(self.value("incident_type", "unknown"), "침해 사고 의심")
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
