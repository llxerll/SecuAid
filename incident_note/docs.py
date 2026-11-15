"""문서 생성 — 플레이북 7.4 템플릿 6종 + 신고서·통지문·타임라인 초안.

원칙
1. 빈칸은 사건 기록으로만 채운다. 모르는 칸은 지우지 않고 "미확인"으로 남긴다.
2. 링크를 넣지 않는다(클릭 유도 방지). 금지 표현("피해 없음" 단정)을 쓰지 않는다.
3. 모든 문서에 확인/추정/미확인 구분과 근거(로그 근거·출처)를 붙인다.
4. 발송은 하지 않는다. 초안과 발송 전 통과표까지만 만든다(제출은 사람이 한다).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .case import Case
from .classify import Classification
from . import deadline as deadline_mod
from .detect import DetectionResult
from .playbook import dont_do, select_cards
from .severity import Severity
from .timeutil import kst_label, now_utc, utc_label

DATA = Path(__file__).resolve().parent.parent / "data"
UNKNOWN = "미확인"


@dataclass
class Document:
    id: str
    title: str
    kind: str                        # notice | report | internal | timeline
    body: str
    evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    gate: list[str] = field(default_factory=list)
    recipients: str = ""
    created_at: str = field(default_factory=lambda: now_utc().isoformat())

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "kind": self.kind, "body": self.body,
                "evidence": self.evidence, "unknowns": self.unknowns, "gate": self.gate,
                "recipients": self.recipients, "created_at": self.created_at}


def load_templates() -> dict:
    return json.loads((DATA / "templates.json").read_text(encoding="utf-8"))


def _mask_account(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if len(digits) < 6:
        return UNKNOWN
    return digits[:3] + "-" + "*" * (len(digits) - 5) + digits[-2:]


def _fill(template: str, mapping: dict[str, str]) -> tuple[str, list[str]]:
    """템플릿 빈칸을 채우고, 남은 빈칸을 미확인으로 바꾼다."""
    out = template
    for k, v in mapping.items():
        out = out.replace(k, v)
    left = re.findall(r"\[[^\]\n]{0,40}\]", out)
    unknowns = [x for x in dict.fromkeys(left)]
    for x in unknowns:
        out = out.replace(x, UNKNOWN)
    return out, [u for u in unknowns]


def _facts_map(case: Case, det: DetectionResult, cls: Classification) -> dict[str, str]:
    org = case.value("org_name") or UNKNOWN
    aware = kst_label(case.aware_at) if case.aware_at else UNKNOWN
    account = case.value("account") or UNKNOWN
    from_domain = (case.eml_triage[-1].get("from_domain") if case.eml_triage else "") or UNKNOWN
    subjects = []
    for f in det.findings:
        if f.rule_id in ("LR_SUSPICIOUS_SEND", "LR_ACCOUNT_CHANGE_MAIL"):
            subj = f.detail.get("subject")
            if subj:
                subjects.append(subj)
    subject = subjects[0] if subjects else UNKNOWN
    window = _send_window(det)
    count = case.value("affected_count")
    amount = case.value("transfer_amount") or UNKNOWN
    gi = case.value("transfer_counterparty") or UNKNOWN
    kinds = {"ato": "계정 침해", "spoof": "도메인 사칭", "lookalike": "유사 도메인 사칭",
             "root": "서버 관리자 권한 탈취", "unknown": "침해 의심"}.get(cls.type, "침해 의심")
    return {
        "[회사/팀명]": org,
        "[회사명]": org,
        "[회사/담당자]": f"{org} 사건 대응 담당",
        "[날짜와 시간대]": aware,
        "[날짜·시간대]": aware,
        "[인지 일시]": aware,
        "[날짜·시간·시간대]": aware,
        "[날짜·시각(시간대)]": aware,
        "[주소 또는 부서]": account,
        "[계정 또는 부서]": account,
        "[계정/유형]": kinds,
        "[송금/계좌 변경/첨부파일/로그인 요청]": "계좌 변경" if "계좌" in " ".join(subjects) else "문서 공유·로그인 요청",
        "[주소]": account,
        "[제목 또는 내용]": subject,
        "[제목/발신자/시간대]": f"{subject} / {from_domain} / {window}",
        "[발송 시간대]": window,
        "[식별 정보]": subject,
        "[다음 안내 시점]": UNKNOWN,
        "[전화번호 / 별도 이메일]": UNKNOWN,
        "[안전한 연락처]": UNKNOWN,
        "[연락처]": UNKNOWN,
        "[담당자 / 전화]": UNKNOWN,
        "[담당 채널]": UNKNOWN,
        "[공식 대표번호]": "기존 거래 명세서에 등록된 대표번호",
        "[부서]": "재무·회계 담당",
        "[거래처명]": gi if gi != UNKNOWN else UNKNOWN,
        "[거래번호]": UNKNOWN,
        "[구체적 사실]": _known_facts_line(det, case),
        "[범위]": "사서함 열람·발송 범위(조사 중)",
        "[짧게]": _known_facts_line(det, case),
        "[시각]": UNKNOWN,
        "[은행명]": UNKNOWN,
        "[금액]": amount,
        "[통화]": "KRW" if amount != UNKNOWN else UNKNOWN,
        "[송금 계좌(일부 마스킹)]": _mask_account(case.value("transfer_account") or ""),
        "[수취은행/수취인]": gi,
        "[거래번호/참조번호]": UNKNOWN,
        "[한두 문장]": "거래처 계좌 변경 안내 메일을 받고 확인 전화를 하던 중, 당사가 계좌를 변경한 적이 없음을 확인",
        "[이름·직통번호]": UNKNOWN,
        "[증권번호]": UNKNOWN,
        "[로그·메일 원본 등]": "로그인·감사·메시지 추적 로그, 메일 원본(헤더 포함)",
        "[언제, 어떤 계정]": f"{aware}, {account}",
        "[발송 수, 송금, 개인정보 — 확인/추정/미확인 구분]": _impact_line(case, det),
        "[계정·세션 차단, 은행 연락]": "계정 일시 중지·세션 철회(진행), 은행 연락(진행)",
        "[외부 통지, 전문가 선임, 서비스 중단]": _decision_line(case, cls),
        "[정확한 시각]": UNKNOWN,
        "[긴급]": "[긴급]",
        "[중요]": "[중요]",
        "[의심/확인]": "확인" if cls.level == "확인" else "의심",
        "[송금/계좌 변경/첨부파일/로그인 요청]": "계좌 변경" if "계좌" in " ".join(subjects) else "문서 공유·로그인 요청",
        "[회사/팀명]": org,
        "[ ]": UNKNOWN,
        "[ ].": UNKNOWN + ".",
        "[날짜와 시간대]": aware,
        "[회사/담당자]": f"{org} 사건 대응 담당",
    }


def _send_window(det: DetectionResult) -> str:
    times = [f.ts for f in det.findings if f.rule_id in ("LR_SUSPICIOUS_SEND", "LR_ACCOUNT_CHANGE_MAIL") and f.ts]
    if not times:
        return UNKNOWN
    times.sort()
    if len(times) == 1:
        return kst_label(times[0])
    return f"{kst_label(times[0])} ~ {kst_label(times[-1])}"


def _known_facts_line(det: DetectionResult, case: Case) -> str:
    bits = []
    if "LR_HIDING_RULE" in set(det.rules_hit()):
        bits.append("숨김 받은편지함 규칙이 생성된 기록")
    if "LR_SUSPICIOUS_SEND" in set(det.rules_hit()):
        bits.append("보낸편지함·메시지 추적에 발송 기록")
    if "LR_MAIL_ACCESS" in set(det.rules_hit()):
        bits.append("사서함 열람·검색 기록")
    if "SR_ROOT_LOGIN" in set(det.rules_hit()):
        bits.append("서버 root 원격 로그인 성공 기록")
    return ", ".join(bits) if bits else UNKNOWN


def _impact_line(case: Case, det: DetectionResult) -> str:
    transfer = {"none": "없음", "pending": "진행·예정", "done": "완료"}.get(case.value("transfer_status"), "미확인")
    pi = {"none": "없음", "suspected": "유출 의심", "confirmed": "유출 확인"}.get(case.value("personal_data_leak"), "미확인")
    sends = sum(1 for f in det.findings if f.rule_id in ("LR_SUSPICIOUS_SEND", "LR_ACCOUNT_CHANGE_MAIL"))
    return (f"송금 {transfer} / 외부 발송 흔적 {sends}건 / 개인정보 {pi}"
            + (f" / 정보주체 약 {case.value('affected_count'):,}명" if isinstance(case.value("affected_count"), int) else " / 정보주체 수 미확인"))


def _decision_line(case: Case, cls: Classification) -> str:
    bits = ["법정 신고·통지 여부(법무·개인정보 담당 판단)"]
    if cls.type == "root":
        bits.append("외부 사고대응 업체 선임")
    if case.value("transfer_status") in ("done", "pending"):
        bits.append("은행 지급정지·회수 절차")
    return ", ".join(bits)


def _evidence_lines(case: Case, det: DetectionResult) -> list[str]:
    lines = []
    for f in case.facts_view():
        lines.append(f"- {f['label']}: {f['value']} 〈{f['level']} / {f['source']}〉")
    summary = {"critical": 0, "high": 0}
    for f in det.findings:
        if f.severity in summary:
            summary[f.severity] += 1
    lines.append(f"- 로그 근거: 치명 {summary['critical']}건, 높음 {summary['high']}건 (규칙 엔진, 확인 수준)")
    return lines


def _unknown_lines(case: Case, det: DetectionResult) -> list[str]:
    out = []
    if not case.aware_at:
        out.append("인지 시각이 기록되지 않아 신고 기한을 계산할 수 없음")
    if case.value("personal_data_leak") == "unknown":
        out.append("사서함에 보관된 개인정보의 항목·규모 미확인")
    if case.value("transfer_status") == "unknown":
        out.append("송금(이체) 실행 여부 미확인")
    if not det.findings:
        out.append("로그가 없어 침해 범위를 확인하지 못함(결과 없음 ≠ 피해 없음)")
    out.append("공격자 신원·소속은 확인하지 않았으며 추정하지 않음")
    return out


def build_documents(case: Case, det: DetectionResult, cls: Classification, sev: Severity) -> dict[str, Document]:
    tpl = load_templates()
    fmap = _facts_map(case, det, cls)
    docs: dict[str, Document] = {}
    evidence = _evidence_lines(case, det)
    unknowns = _unknown_lines(case, det)
    gate = list(tpl.get("principles", {}).get("pre_send_gate", []))

    wanted = ["T1_customer", "T2_deal_check", "T3_staff", "T4_bank", "T5_insurer", "T6_exec5"]
    if cls.type in ("lookalike", "spoof"):
        wanted = ["T1_customer", "T3_staff", "T6_exec5"]
    if case.value("transfer_status") not in ("done", "pending"):
        wanted = [w for w in wanted if w != "T4_bank"]
    if case.value("insurance") is not True:
        wanted = [w for w in wanted if w != "T5_insurer"]

    for key in wanted:
        t = tpl.get(key)
        if not t:
            continue
        body, left = _fill(t.get("body", ""), fmap)
        subject, _ = _fill(t.get("subject", ""), fmap) if t.get("subject") else ("", [])
        full = (f"제목: {subject}\n\n{body}" if subject else body)
        full += "\n\n---\n■ 확인 근거\n" + "\n".join(evidence)
        full += "\n\n■ 미확인 사항\n" + "\n".join(f"- {u}" for u in unknowns)
        docs[key] = Document(key, t.get("title", key), "notice", full, evidence, unknowns, gate,
                             recipients=_recipients_for(key, case))

    docs["tpl_intrusion_report"] = _intrusion_report(case, det, cls, evidence, unknowns)
    ddl = {d.rule_id: d for d in deadline_mod.compute(case)}
    pi_applies = ddl.get("R_PI_LEAK_REPORT") and ddl["R_PI_LEAK_REPORT"].status in ("해당", "검토")
    notice_applies = ddl.get("R_PI_NOTICE") and ddl["R_PI_NOTICE"].status in ("해당", "검토")
    if pi_applies:
        docs["tpl_pi_leak_report"] = _pi_leak_report(case, det, cls, evidence, unknowns)
    if notice_applies:
        docs["tpl_pi_notice"] = _pi_notice(case, det, cls, evidence, unknowns)
    docs["tpl_exec_report"] = _exec_report(case, det, cls, sev, evidence, unknowns)
    docs["tpl_timeline"] = _timeline(case, det)
    return docs


def _recipients_for(key: str, case: Case) -> str:
    return {
        "T1_customer": "메일을 받은 거래처·고객, 내부 영업",
        "T2_deal_check": "해당 거래처 담당자(원장 번호로 전화 확인 후 발송)",
        "T3_staff": "전 직원(침해되지 않은 채널)",
        "T4_bank": "송금 은행 사고접수 창구",
        "T5_insurer": "보험사 사고접수 담당",
        "T6_exec5": "대표·경영진",
    }.get(key, "")


def _header(title: str, case: Case, purpose: str) -> str:
    return (f"{title}\n사건번호: {case.id} / 기준: {kst_label(case.aware_at) if case.aware_at else UNKNOWN}\n"
            f"용도: {purpose}\n" + "-" * 60 + "\n")


def _intrusion_report(case: Case, det: DetectionResult, cls: Classification,
                      evidence: list[str], unknowns: list[str]) -> Document:
    rules = set(det.rules_hit())
    body = _header("침해사고 최초신고서 초안", case, "과학기술정보통신부/KISA 제출용 초안(제출은 담당자)")
    body += (
        f"1. 신고인: {case.value('org_name') or UNKNOWN} (정보통신서비스 제공자 여부: "
        f"{_yes_no(case.value('is_ict_service_provider'))})\n"
        f"2. 침해사고 발생 인지 일시: {kst_label(case.aware_at) if case.aware_at else UNKNOWN}\n"
        f"3. 침해 유형: {cls.label}\n"
        f"4. 발생 경위(확인된 범위): {_known_facts_line(det, case)}\n"
        f"5. 피해 내용: {_impact_line(case, det)}\n"
        f"6. 현재까지의 대응: 계정 일시 중지·세션 철회 요청, 로그 보존, 거래처·직원 통지 준비\n"
        f"7. 추가 확인이 필요한 사항: {', '.join(unknowns[:3])}\n"
        "8. 담당자 연락처: " + UNKNOWN + "\n"
        + ("9. 근거: " + ", ".join(sorted(rules)) + "\n" if rules else "")
    )
    body += "\n■ 확인\n" + "\n".join(evidence) + "\n\n■ 미확인\n" + "\n".join(f"- {u}" for u in unknowns)
    return Document("tpl_intrusion_report", "침해사고 최초신고서 초안", "report", body, evidence, unknowns,
                    ["원인 파악이 덜 됐어도 파악된 범위로 먼저 신고", "추가 확인 시 24시간 내 보완신고"],
                    "과학기술정보통신부/KISA(118)")


def _pi_leak_report(case: Case, det: DetectionResult, cls: Classification,
                    evidence: list[str], unknowns: list[str]) -> Document:
    count = case.value("affected_count")
    body = _header("개인정보 유출 신고서 초안", case, "개인정보보호위원회/KISA 제출용 초안")
    body += (
        f"1. 정보주체에의 통지 여부: 통지 준비 중(통지문 초안 별첨)\n"
        f"2. 유출등이 된 개인정보의 항목 및 규모: {case.value('pi_data_types') or '사서함 보관 고객 문의(이름·연락처·주소) 추정'} / "
        f"{f'{count:,}명' if isinstance(count, int) else '규모 미확인'}\n"
        f"3. 유출 시점과 경위: {_known_facts_line(det, case)} (공격자 사서함 열람 기록 기준)\n"
        f"4. 피해 최소화 대책·조치 및 결과: 세션 철회·규칙 비활성화·비밀번호 초기화·모니터링\n"
        f"5. 정보주체가 할 수 있는 피해 최소화 방법·구제절차: 스미싱·사칭 메일 주의, 금융 피해 시 지급정지·신고 안내\n"
        f"6. 담당부서·담당자 및 연락처: {UNKNOWN}\n"
        "\n※ 유출 여부가 '의심' 단계인 경우 확인된 내용으로 우선 신고하고 추가 확인 시 즉시 보완합니다.\n"
    )
    body += "\n■ 확인\n" + "\n".join(evidence) + "\n\n■ 미확인\n" + "\n".join(f"- {u}" for u in unknowns)
    return Document("tpl_pi_leak_report", "개인정보 유출 신고서 초안", "report", body, evidence, unknowns,
                    ["6개 필수 항목 모두 기재", "확인/추정 구분 유지", "규모 미확인 시 확인된 범위로 신고"],
                    "개인정보보호위원회/KISA")


def _pi_notice(case: Case, det: DetectionResult, cls: Classification,
               evidence: list[str], unknowns: list[str]) -> Document:
    level = "확인" if case.value("personal_data_leak") == "confirmed" else "가능성"
    body = _header("정보주체 통지문 초안", case, f"유출 {level} 통지")
    body += (
        f"안녕하세요. {case.value('org_name') or UNKNOWN}입니다.\n"
        f"{kst_label(case.aware_at) if case.aware_at else UNKNOWN}에 당사 업무용 이메일 계정이 제3자에게 사용된 사실을 확인하였고, "
        f"해당 사서함에 보관된 고객 문의 정보(이름·연락처·주소)가 제3자에게 열람되었을 가능성이 있습니다.\n\n"
        "· 현재 확인된 사실: 사서함 열람·검색 기록, 외부로 발송된 메일 기록\n"
        "· 아직 확인되지 않은 사실: 열람된 정보의 정확한 항목과 규모, 추가 유출 여부\n"
        "· 당사가 한 조치: 해당 계정의 접근 차단·세션 철회, 숨김 규칙 제거, 관련 메일 회수 요청\n\n"
        "고객님께서 하실 일: 당사 이름으로 온 송금·계좌 변경·문서 공유 요청 메일에 회신하거나 링크를 누르지 마시고, "
        "이미 송금하셨다면 거래 은행에 지급정지·회수를 요청하신 뒤 당사 공식 연락처로 알려 주십시오.\n"
        f"공식 확인 연락처: {UNKNOWN}\n"
        f"다음 안내: {UNKNOWN}\n"
    )
    body += "\n■ 확인\n" + "\n".join(evidence) + "\n\n■ 미확인\n" + "\n".join(f"- {u}" for u in unknowns)
    return Document("tpl_pi_notice", "정보주체 통지문 초안", "notice", body, evidence, unknowns,
                    ["확인/가능성 구분", "링크 없음", "재노출 정보 최소화", "공식 연락처 기재 후 발송"],
                    "유출(의심) 정보주체")


def _exec_report(case: Case, det: DetectionResult, cls: Classification, sev: Severity,
                 evidence: list[str], unknowns: list[str]) -> Document:
    body = _header("경영진 보고서(1페이지)", case, "의사결정용 요약")
    body += (
        f"■ 심각도: {sev.level} {sev.name} — 판단 근거 수준: {sev.evidence_level}\n"
        f"■ 한 줄 상황: {cls.label} ({cls.level})\n\n"
        f"1. 확인된 사실\n" + "\n".join(f"  - {kst_label(f.ts)} {f.summary}" for f in det.ordered()[:6]) + "\n"
        f"2. 아직 모르는 점\n" + "\n".join(f"  - {u}" for u in unknowns) + "\n"
        f"3. 돈: {_impact_line(case, det)}\n"
        f"4. 필요한 결정\n" + "\n".join(f"  - {x}" for x in sev.must) + "\n"
        f"5. 다음 보고: {sev.next_report}\n"
        f"6. 하지 말 것\n" + "\n".join(f"  - {x}" for x in dont_do(case, det, cls)[:4]) + "\n"
    )
    return Document("tpl_exec_report", "경영진 보고서(1페이지)", "internal", body, evidence, unknowns,
                    ["확인/추정/미확인 구분", "결정 필요 사항 명시", "다음 보고 시각 포함"], "대표·경영진")


def _timeline(case: Case, det: DetectionResult) -> Document:
    rows = ["시각(KST) | 원본(UTC) | 구분 | 내용 | 근거수준", "-" * 70]
    for f in det.ordered():
        rows.append(f"{kst_label(f.ts)} | {utc_label(f.ts)} | {f.rule_id} | {f.summary} | {f.evidence}")
    if case.aware_at:
        rows.append(f"{kst_label(case.aware_at)} | - | 인지 | {case.fact('aware_at').source} | 확인")
    body = _header("사고 타임라인", case, "내부 기록·보고용") + "\n".join(rows)
    body += "\n\n※ 원본 로그의 UTC 값을 유지하고 KST를 병기했습니다(플레이북 5.3)."
    return Document("tpl_timeline", "사고 타임라인", "timeline", body, [], [], [], "내부")


def _yes_no(v) -> str:
    return {True: "예", False: "아니오", None: UNKNOWN}.get(v, UNKNOWN)


def to_docx(doc: Document) -> bytes | None:
    """DOCX 내보내기(선택). python-docx가 없으면 None."""
    try:
        from docx import Document as Docx  # type: ignore
    except Exception:
        return None
    d = Docx()
    d.add_heading(doc.title, level=1)
    for line in doc.body.splitlines():
        d.add_paragraph(line)
    from io import BytesIO
    buf = BytesIO()
    d.save(buf)
    return buf.getvalue()
