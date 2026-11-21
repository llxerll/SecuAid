"""사고 유형 판별 — 계정 침해(ATO) / 스푸핑 / 유사 도메인 / 서버 장악(root)을 근거와 함께 가른다.

플레이북 3.3: "도메인 철자·인증 결과·보낸편지함·로그인 로그를 교차 확인한다."
판정은 LLM이 아니라 여기서 결정적으로 만들고, LLM은 문장화만 한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .case import Case
from .detect import DetectionResult


@dataclass
class Classification:
    type: str                       # ato | spoof | lookalike | root | unknown
    label: str
    level: str                      # 확인 | 추정 | 미확인
    basis: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    cards: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"type": self.type, "label": self.label, "level": self.level,
                "basis": self.basis, "missing": self.missing, "cards": self.cards}


LABELS = {
    "ato": "메일 계정 탈취(ATO) — 계정 자체가 공격자에게 사용됨",
    "spoof": "도메인 스푸핑 — 우리 계정이 아니라 발신자 표시가 위조됨",
    "lookalike": "유사 도메인 사칭 — 철자가 비슷한 외부 도메인",
    "root": "관리자 권한 탈취(서버 장악) — 플레이북 범위 밖, 전문 대응 필요",
    "ransom": "랜섬웨어 감염 — 파일 암호화·랜섬노트 확인, 격리·복구 우선",
    "cloud": "클라우드·API 키 유출 — 키 폐기·사용 흔적 확인",
    "webdb": "웹 애플리케이션·DB 유출 — 노출 경로 차단·범위 산정",
    "insider": "내부자 정보 유출 — 권한 회수·증거 보존·법무 판단",
    "ddos": "DDoS·서비스 장애 — 가용성 방어·통신사 연계",
    "supply": "공급망·악성코드 감염 — 감염 경로 차단·배포물 회수",
    "unknown": "판별 근거 부족 — 추가 자료 필요",
}

RANSOM_BASIS = {
    "RW_EXTENSION_MASS": "파일 대량 암호화(변조 확장자) 이벤트가 EDR·파일 서버 로그에 기록됨",
    "RW_RANSOM_NOTE": "랜섬노트 파일 생성 기록",
    "RW_SHADOW_DELETE": "볼륨 섀도 복사본 삭제(복구 수단 제거)",
    "RW_SECURITY_DISABLED": "보안·백업 서비스 중지 기록",
    "RW_LATERAL": "원격 공유 접근으로 측면 이동·백업 공격 시도",
    "RW_BACKUP_TARGETED": "백업 작업 실패·백업 대상 접근 불가",
}


def ato_evidence(det: DetectionResult) -> list[str]:
    """계정이 실제로 사용된 흔적(확인 수준 근거)."""
    out = []
    rules = set(det.rules_hit())
    if "LR_HIDING_RULE" in rules:
        out.append("공격자가 만든 숨김 규칙이 감사 로그에 기록됨(계정 안에서 조작)")
    if "LR_SUSPICIOUS_SEND" in rules:
        out.append("의심 IP에서 발송된 메일이 메시지 추적/감사 로그에 남음(보낸편지함 조작)")
    if "LR_MAIL_ACCESS" in rules:
        out.append("의심 IP에서 사서함 열람·검색(MailItemsAccessed)")
    if "LR_PERSISTENCE" in rules:
        out.append("앱 비밀번호·OAuth 동의 등 지속 접근 수단 추가")
    if "LR_COVER_TRACKS" in rules:
        out.append("보낸 편지함 삭제(흔적 은폐)")
    return out


def classify(case: Case, det: DetectionResult) -> Classification:
    rules = set(det.rules_hit())
    admin = case.value("admin_compromise") is True or bool(rules & {"SR_ROOT_LOGIN", "SR_PERSIST_SERVICE"})
    eml = case.eml_triage[-1] if case.eml_triage else {}
    verdicts = {e.get("verdict") for e in case.eml_triage}

    ransom_rules = {r for r in rules if r.startswith("RW_")}
    if ransom_rules and not admin:
        basis = [RANSOM_BASIS[r] for r in sorted(ransom_rules) if r in RANSOM_BASIS]
        confirmed = bool(ransom_rules & {"RW_EXTENSION_MASS", "RW_RANSOM_NOTE"})
        missing = []
        if "RW_BACKUP_TARGETED" not in ransom_rules:
            missing.append("백업 오프라인 사본 존재·무결성(백업 담당 확인 필요)")
        missing.append("최초 감염 경로(메일·원격접속·공급망) — 조사 중")
        return Classification("ransom", LABELS["ransom"], "확인" if confirmed else "추정", basis, missing,
                              ["C12_9"])

    if admin:
        basis = []
        if "SR_ROOT_LOGIN" in rules:
            basis.append("secure 로그에 root 원격 로그인 성공 기록")
        if "SR_PERSIST_SERVICE" in rules:
            basis.append("원격제어 에이전트 서비스 등록·시작 기록")
        if "SR_LOG_TAMPER" in rules:
            basis.append("로그·히스토리 삭제 기록(은폐)")
        if "FW_OUTBOUND_RDP" in rules:
            basis.append("메일 서버에서 외부 3389 아웃바운드 연결 기록")
        return Classification("root", LABELS["root"], "확인", basis,
                              ["공격자가 심은 악성코드의 전체 범위", "서버에서 유출된 데이터 범위"], ["C12_4"])

    forced = case.value("incident_type")
    a = ato_evidence(det)
    internals = {"ato"} & verdicts

    if a:
        basis = a + [f"메일 원본 판독: {eml.get('basis', [''])[0]}" if eml and eml.get("verdict") == "ato" else ""]
        cards = ["C12_3"]
        summary_blob = " ".join(f.summary for f in det.findings)
        if "LR_HIDING_RULE" in rules:
            cards.append("C12_2")
        if "계좌" in summary_blob or "송금" in summary_blob:
            cards.append("C12_2")
        missing = []
        if "LR_FOREIGN_LOGIN" not in rules:
            missing.append("해외·낯선 IP 로그인 기록(로그인 로그 미확인)")
        return Classification("ato", LABELS["ato"], "확인" if "LR_SUSPICIOUS_SEND" in rules else "추정",
                              [b for b in basis if b], missing, sorted(set(cards)))

    if internals:
        return Classification("ato", LABELS["ato"], "추정",
                              [b for b in (eml.get("basis") or [])], ["감사 로그·메시지 추적(발송 흔적)"], ["C12_3"])

    if "lookalike" in verdicts:
        return Classification("lookalike", LABELS["lookalike"], "확인",
                              [b for b in (eml.get("basis") or [])], ["내부 계정 침해 흔적 유무"], ["C12_7"])
    if "spoof" in verdicts:
        return Classification("spoof", LABELS["spoof"], "확인",
                              [b for b in (eml.get("basis") or [])], ["내부 계정 침해 흔적 유무"], ["C12_7"])
    if forced in LABELS and forced != "unknown":
        return Classification(forced, LABELS[forced], "추정",
                              [f"사용자 진술로 유형을 '{forced}'로 접수(로그 미확인)"], ["로그·메일 원본"], [])
    if "LR_FOREIGN_LOGIN" in rules or "LR_IMPOSSIBLE_TRAVEL" in rules:
        return Classification("unknown", LABELS["unknown"], "추정",
                              ["해외·비정상 로그인은 확인되지만 계정 사용(발송·규칙) 흔적은 아직 미확인"],
                              ["감사 로그", "메시지 추적", "메일 원본"], ["C12_3"])
    return Classification("unknown", LABELS["unknown"], "미확인",
                          ["로그인·감사·추적 로그가 없어 유형을 판별할 수 없음"],
                          ["로그인 로그", "감사 로그", "메시지 추적", "의심 메일 원본"], [])
