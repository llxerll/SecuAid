"""심각도(P1~P4) 결정 — 플레이북 3.2 표를 코드로 옮긴다.

v0.2에는 심각도 엔진이 아예 없어서, 시나리오 정답지의 "P2 → 송금 확인 시 P1" 격상이
사람 손으로만 가능했다. 여기서는 사실(fact)이 추가될 때마다 같은 규칙으로 재평가한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .case import Case
from .classify import Classification
from .detect import DetectionResult

LEVELS = {
    "P1": {"name": "치명", "report": "1~2시간마다 경영진",
           "must": ["은행 즉시 연락(지급정지·회수)", "외부 사고대응 지원 호출 검토", "법무·개인정보 담당 즉시 참여"]},
    "P2": {"name": "높음", "report": "4시간마다",
           "must": ["송금 보류", "거래처 역확인(원장 번호)", "통지·신고 검토 착수"]},
    "P3": {"name": "중간", "report": "당일 2회",
           "must": ["예방적 세션 철회·암호 초기화", "조사 범위 확정", "로그 보존"]},
    "P4": {"name": "낮음", "report": "일 1회",
           "must": ["수신 차단", "직원 경고", "DMARC·인증 정책 점검"]},
}


@dataclass
class Severity:
    level: str = "P3"
    name: str = "중간"
    reasons: list[str] = field(default_factory=list)
    next_report: str = "당일 2회"
    must: list[str] = field(default_factory=list)
    escalate_if: list[str] = field(default_factory=list)
    evidence_level: str = "추정"

    def to_dict(self) -> dict:
        return {"level": self.level, "name": self.name, "reasons": self.reasons,
                "next_report": self.next_report, "must": self.must,
                "escalate_if": self.escalate_if, "evidence_level": self.evidence_level}


def evaluate(case: Case, det: DetectionResult, cls: Classification) -> Severity:
    reasons: list[str] = []
    level = "P4"
    evidence = "추정"

    transfer = case.value("transfer_status", "unknown")
    pi = case.value("personal_data_leak", "unknown")
    count = case.value("affected_count") or 0
    admin = case.value("admin_compromise") is True or cls.type == "root"
    sends = "LR_SUSPICIOUS_SEND" in set(det.rules_hit())
    persistence = bool(set(det.rules_hit()) & {"LR_HIDING_RULE", "LR_PERSISTENCE"})
    multiple = len(det.suspect_accounts) >= 2 or case.value("multiple_accounts") is True

    if transfer in ("done", "pending") and case.level("transfer_status") in ("확인", "추정"):
        level = "P1"
        reasons.append(("송금 완료" if transfer == "done" else "송금 진행·예정") + " — 금전 손실이 진행 중이거나 확정")
        evidence = case.level("transfer_status") if case.level("transfer_status") == "확인" else "추정"
    if admin:
        level = "P1"
        reasons.append("관리자 권한 계정·서버 장악 — 피해 범위가 조직 전체로 번질 수 있음")
        evidence = "확인" if cls.level == "확인" else "추정"
    if multiple:
        level = "P1"
        reasons.append(f"침해 의심 계정이 2개 이상({', '.join(det.suspect_accounts[:3])}) — 다수 계정 침해")
    if pi == "confirmed" and (count >= 1000 or case.value("sensitive_or_unique_id") is True):
        level = "P1"
        reasons.append("개인정보 유출 확인 + 1천 명 이상 또는 민감·고유식별정보 — 대규모 노출 가능성")

    if level not in ("P1",) and cls.type in ("ato", "root"):
        if sends or persistence:
            level = "P2"
            evidence = cls.level
            if sends:
                reasons.append("침해 계정에서 외부로 메일이 실제 발송됨(메시지 추적·감사 로그 확인)")
            if persistence:
                reasons.append("숨김 규칙·앱 비밀번호 등 지속성 수단 발견")
            if cls.type == "ato" and "계좌" in " ".join(f.summary for f in det.findings):
                reasons.append("계좌 변경 요청형 BEC — 거래처 송금이 걸려 있는 상태(송금 전)")
        else:
            level = "P3"
            reasons.append("침해 가능성은 높지만 계정 사용(발송·규칙) 흔적은 아직 확인되지 않음")
            evidence = "추정"
    elif level not in ("P1",) and cls.type in ("spoof", "lookalike"):
        level = "P4"
        evidence = cls.level
        reasons.append("우리 계정 접근 흔적 없음 — 스푸핑/유사 도메인으로 분류")
    elif level not in ("P1",) and cls.type == "unknown":
        level = "P3"
        evidence = "미확인"
        reasons.append("유형 판별 전 — 로그가 확보되면 즉시 재평가")

    if pi == "suspected" and case.value("external_illegal_access") is True and level in ("P3", "P4"):
        level = "P2"
        reasons.append("개인정보 유출 의심 + 외부 불법접근 — 신고·통지 검토 대상")

    escalate = []
    if transfer not in ("done", "pending"):
        escalate.append("송금 완료가 확인되면 즉시 P1 — 은행 지급정지가 첫 행동")
    if not admin:
        escalate.append("관리자 계정 침해가 확인되면 즉시 P1")
    if pi not in ("confirmed",):
        escalate.append("개인정보 유출이 확인되고 1천 명 이상·민감정보이면 P1")
    if len(det.suspect_accounts) < 2:
        escalate.append("같은 공격자 IP로 다른 계정 로그인이 나오면 P1")

    meta = LEVELS[level]
    return Severity(level, meta["name"], reasons or ["판단 근거 없음"], meta["report"], meta["must"], escalate, evidence)
