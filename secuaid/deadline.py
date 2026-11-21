"""신고·통지 기한 계산 — 결정적 규칙(reporting_rules.json)만 사용한다.

- 기한은 "인지 시각(aware_at)"에서 시간 단위로 계산한다(정보통신망법 24시간, 개인정보보호법 72시간).
- 요건이 '미확인'이면 적용/비적용을 단정하지 않고 "판단 보류"로 남긴다.
- 운영상 연락(은행·거래처·경찰·보험)은 법정 신고와 별도로, 사건 사실에 따라 트리거한다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .case import VALUE_LABEL, Case
from .timeutil import UTC, human_delta, kst_label, now_utc

DATA = Path(__file__).resolve().parent.parent / "data"


def load_rules(path: Path | None = None) -> dict:
    p = path or DATA / "reporting_rules.json"
    return json.loads(p.read_text(encoding="utf-8"))


@dataclass
class Deadline:
    rule_id: str
    title: str
    to: str
    status: str                 # 해당 | 비해당 | 판단 보류
    why: str
    due: datetime | None = None
    legal_ref: str = ""
    template: str | None = None
    required_fields: list[str] = field(default_factory=list)
    followup: str = ""
    missing: list[str] = field(default_factory=list)

    def to_dict(self, now: datetime | None = None) -> dict:
        now = now or now_utc()
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "to": self.to,
            "status": self.status,
            "why": self.why,
            "due": kst_label(self.due) if self.due else None,
            "due_iso": self.due.isoformat() if self.due else None,
            "remaining": human_delta(self.due, now) if self.due else None,
            "legal_ref": self.legal_ref,
            "template": self.template,
            "required_fields": self.required_fields,
            "followup": self.followup,
            "missing": self.missing,
        }


@dataclass
class OperationalContact:
    id: str
    title: str
    when: str
    how: str
    triggered: bool
    why: str = ""
    template: str | None = None

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "when": self.when, "how": self.how,
                "triggered": self.triggered, "why": self.why, "template": self.template}


def _intrusion_state(case: Case) -> tuple[str, str]:
    """(confirmed|suspected|none|unknown, 근거)"""
    t = case.value("incident_type", "unknown")
    if case.value("admin_compromise") is True or t == "root":
        return "confirmed", "관리자 권한 탈취(secure 로그로 확인)"
    if t == "ato":
        return "confirmed", "메일 계정 침해(로그인·감사·추적 로그로 확인)"
    if t == "ransom":
        return "confirmed", "랜섬웨어 감염(파일 암호화·랜섬노트로 확인)"
    if t in ("spoof", "lookalike"):
        return "none", "우리 시스템 침해가 아니라 발신자 표시 위조(계정 접근 흔적 없음)"
    if t == "unknown":
        return "unknown", "침해 여부 미확인"
    return "unknown", "침해 여부 미확인"


def _pi_label(pi: str) -> str:
    return VALUE_LABEL["personal_data_leak"].get(pi, pi)


def compute(case: Case, rules: dict | None = None) -> list[Deadline]:
    rules = rules or load_rules()
    aware = case.aware_at
    intrusion, intrusion_why = _intrusion_state(case)
    pi = case.value("personal_data_leak", "unknown")
    count = case.value("affected_count")
    sensitive = case.value("sensitive_or_unique_id")
    external = case.value("external_illegal_access")
    ict = case.value("is_ict_service_provider")

    out: list[Deadline] = []
    for r in rules.get("rules", []):
        rid = r["id"]
        due = aware + timedelta(hours=r["deadline_hours"]) if aware else None
        status, why, missing = "판단 보류", "", []

        if rid == "R_INTRUSION_REPORT":
            if ict is None:
                status, why = "판단 보류", "정보통신서비스 제공자 여부 미확인 — 홈페이지·메일 서비스를 고객에게 제공하는지 확인 필요"
                missing = ["is_ict_service_provider"]
            elif intrusion in ("confirmed", "suspected"):
                status, why = "해당", f"정보통신서비스 제공자 + {intrusion_why}"
            elif intrusion == "none":
                status, why = "비해당", intrusion_why
            else:
                status, why = "판단 보류", intrusion_why
                missing = ["incident_type"]
            if ict is True and intrusion == "none":
                status, why = "검토", "정보통신서비스 제공자이지만 우리 시스템 침해 흔적이 없음 — 사칭 피해는 별도 판단"

        elif rid == "R_PI_LEAK_REPORT":
            conds = []
            if isinstance(count, int) and count >= 1000:
                conds.append(f"정보주체 {count:,}명(1천 명 이상)")
            if sensitive is True:
                conds.append("민감정보·고유식별정보 포함")
            if external is True:
                conds.append("외부 불법접근에 의한 유출")
            if pi == "unknown":
                status, why = "판단 보류", "개인정보 유출 여부가 아직 확인되지 않음(사서함 보관 항목 확인 필요)"
                missing = ["personal_data_leak"]
            elif pi == "none":
                status, why = "비해당", "개인정보 유출 흔적 없음"
            elif conds:
                status, why = "해당", f"{_pi_label(pi)} + " + ", ".join(conds)
            else:
                status, why = "검토", f"{_pi_label(pi)}이지만 신고 요건(1천 명·민감정보·외부 불법접근) 미확인"
                missing = ["affected_count", "sensitive_or_unique_id", "external_illegal_access"]

        elif rid == "R_PI_NOTICE":
            if pi == "unknown":
                status, why = "판단 보류", "개인정보 유출 여부 미확인"
                missing = ["personal_data_leak"]
            elif pi == "none":
                status, why = "비해당", "유출 흔적 없음"
            elif pi == "suspected" and case.level("personal_data_leak") == "추정":
                status, why = "검토", f"{_pi_label(pi)}(추정) — 피해 시스템에 개인정보가 실제로 있었는지 확인 후 통지 여부 판단"
                missing = ["personal_data_leak"]
            else:
                status, why = "해당", f"{_pi_label(pi)} — 확인/가능성 모두 통지 대상 검토"

        if due and status in ("해당", "검토") and due < now_utc():
            why += " (기한 경과 — 즉시 신고 및 경과 사유 기록)"

        out.append(Deadline(
            rule_id=rid, title=r["title"], to=r["to"], status=status, why=why, due=due,
            legal_ref=r.get("legal_ref", ""), template=r.get("template"),
            required_fields=r.get("required_fields", []), followup=r.get("followup", ""),
            missing=missing,
        ))
    return out


def operational(case: Case, rules: dict | None = None) -> list[OperationalContact]:
    rules = rules or load_rules()
    transfer = case.value("transfer_status")
    amount = case.value("transfer_amount")
    intr = case.value("incident_type")
    out = []
    for c in rules.get("operational_contacts", []):
        cid, triggered, why = c["id"], False, ""
        if cid == "O_BANK":
            triggered = transfer in ("done", "pending")
            why = VALUE_LABEL["transfer_status"].get(transfer, transfer) + (f" · {amount}" if amount else "") if triggered else ""
        elif cid == "O_COUNTERPARTY_BANK":
            triggered = transfer in ("done", "pending") and intr in ("ato", "lookalike", "spoof")
            why = "우리 계정/도메인 사칭으로 거래처가 송금한 정황" if triggered else ""
        elif cid == "O_POLICE":
            triggered = transfer in ("done", "pending")
            why = "금전 피해 발생·사기 시도" if triggered else ""
        elif cid == "O_KISA_118":
            triggered = intr in ("ato", "root", "ransom")
            why = "침해 대응 지원 필요" if triggered else ""
        elif cid == "O_RANSOM_KISA":
            triggered = intr == "ransom"
            why = "랜섬웨어 복구 지원·복호화 도구 확인(몸값 지불 금지)" if triggered else ""
        elif cid == "O_BACKUP":
            triggered = intr == "ransom"
            why = "오프라인 백업 사본 무결성 확인·복구 순서 결정" if triggered else ""
        elif cid == "O_INSURER":
            triggered = case.value("insurance") is True
            why = "사이버 보험 가입" if triggered else ""
        out.append(OperationalContact(cid, c["title"], c.get("when", ""), c.get("how", ""),
                                      triggered, why, c.get("template")))
    return out


def board(case: Case, rules: dict | None = None) -> dict:
    rules = rules or load_rules()
    items = compute(case, rules)
    now = now_utc()
    due_items = sorted([d for d in items if d.due and d.status in ("해당", "검토")], key=lambda d: d.due)  # type: ignore[arg-type,return-value]
    next_due = None
    if due_items:
        d = due_items[0]
        next_due = {"title": d.title, "due": kst_label(d.due), "remaining": human_delta(d.due, now),
                    "status": d.status}
    return {
        "items": [d.to_dict(now) for d in items],
        "operational": [c.to_dict() for c in operational(case, rules)],
        "next_due": next_due,
        "disclaimer": rules.get("meta", {}).get("disclaimer", ""),
        "verified_on": rules.get("meta", {}).get("verified_on"),
    }
