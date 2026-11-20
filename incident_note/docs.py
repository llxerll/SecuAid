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

# ---------------------------------------------------------------- 브랜드
BRAND_KO = "시큐에이드"
BRAND_EN = "SecuAid"
BRAND_SUBTITLE = "중소·소호 기업 보안사고 초동대응 파트너"
DOCX_NOTICE = f"{BRAND_EN} 초동대응 초안 — 발송·제출 전 〔미확인〕 항목 확인"
FONT_LATIN = "Malgun Gothic"       # Windows PC Word/한컴에서 한글·기호가 깨지지 않게
FONT_EA = "맑은 고딕"


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


PRESERVE_LABELS = {"[중요]", "[긴급]"}


def _fill(template: str, mapping: dict[str, str]) -> tuple[str, list[str]]:
    """템플릿 빈칸을 채우고, 템플릿에 남은 빈칸만 미확인으로 바꾼다.

    치환값 안에 들어 있는 대괄호(예: 실제 메일 제목 '[대성포장 귀중] ...')를
    빈칸으로 오인해 지우지 않도록, 빈칸 목록은 치환 전 템플릿에서 먼저 구한다.
    """
    placeholders = list(dict.fromkeys(re.findall(r"\[[^\]\n]{0,40}\]", template)))
    unknown = [p for p in placeholders if p not in mapping and p not in PRESERVE_LABELS]
    out = template
    for k, v in mapping.items():
        # 값이 '미확인'인 칸도 무엇이 비었는지 보이게 남긴다(문장이 '미확인에 안내' 처럼 깨지지 않도록).
        out = out.replace(k, _blank(k) if v == UNKNOWN else v)
    for p in unknown:
        out = out.replace(p, _blank(p))
    return out, unknown + [k for k, v in mapping.items() if v == UNKNOWN and k in placeholders]


def _blank(placeholder: str) -> str:
    """채우지 못한 빈칸 표시 — 담당자가 발송 전에 찾아 채울 수 있게 항목명을 함께 남긴다."""
    return f"〔{UNKNOWN}: {placeholder.strip('[]')}〕"


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
             "root": "서버 관리자 권한 탈취", "ransom": "랜섬웨어 감염",
             "cloud": "클라우드·API 키 유출", "webdb": "웹·DB 유출", "insider": "내부자 유출",
             "ddos": "DDoS·서비스 장애", "supply": "공급망 악성코드",
             "unknown": "침해 의심"}.get(cls.type, "침해 의심")
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
        "[시간대]": window,
        "[보험사]": UNKNOWN,
        "[송금 여부·금액, 미확인 시 미확인]": _transfer_line(case),
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
        "[확장자]": case.value("encrypted_ext") or UNKNOWN,
        "[랜섬노트 파일명]": case.value("ransom_note") or UNKNOWN,
        "[암호화 호스트]": f"{case.value('encrypted_hosts')}대" if isinstance(case.value("encrypted_hosts"), int) else UNKNOWN,
        "[송금/계좌 변경/첨부파일/로그인 요청]": "계좌 변경" if "계좌" in " ".join(subjects) else "문서 공유·로그인 요청",
        "[회사/팀명]": org,
        "[ ]": UNKNOWN,
        "[ ].": UNKNOWN + ".",
        "[날짜와 시간대]": aware,
        "[회사/담당자]": f"{org} 사건 대응 담당",
    }


def _transfer_line(case: Case) -> str:
    status = {"done": "송금 완료", "pending": "송금 진행·예정", "none": "송금 없음"}.get(case.value("transfer_status"), "송금 여부 미확인")
    amount = case.value("transfer_amount")
    return f"{status}" + (f" · {amount}" if amount else "")


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
    if case.value("incident_type") == "ransom":
        hosts = case.value("encrypted_hosts")
        backup = {"offline_safe": "오프라인 사본 확보", "at_risk": "백업이 같은 망에 노출",
                  "unknown": "미확인"}.get(case.value("backup_status"), "미확인")
        paid = {True: "지불함", False: "지불하지 않음", None: "미확인"}.get(case.value("ransom_paid"), "미확인")
        pi = {"none": "없음", "suspected": "유출 의심", "confirmed": "유출 확인"}.get(
            case.value("personal_data_leak"), "미확인")
        return (f"암호화 호스트 {f'{hosts}대' if isinstance(hosts, int) else '미확인'} / "
                f"백업 {backup} / 몸값 {paid} / 개인정보 {pi}")
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
    if cls.type == "ransom":
        # 랜섬웨어는 메일 통지문(T1·T2·T4) 대신 직원 긴급 공지와 경영진 결정 문서가 우선이다.
        wanted = ["T7_staff_ransom", "T6_exec5"]
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
        full += ("\n\n" + "=" * 60 + "\n▼ 여기부터는 내부 검토용입니다. 발송 전에 이 줄 아래를 모두 삭제하세요.\n"
                 + "=" * 60)
        if left:
            full += "\n\n■ 발송 전에 채울 칸\n" + "\n".join(f"- {x.strip('[]')}" for x in left)
        full += "\n\n■ 확인 근거\n" + "\n".join(evidence)
        full += "\n\n■ 미확인 사항\n" + "\n".join(f"- {u}" for u in unknowns)
        full += "\n\n■ 발송 전 통과표\n" + "\n".join(f"☐ {g}" for g in gate)
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
    if cls.type == "ransom":
        docs["tpl_ransom_report"] = _ransom_report(case, det, cls, evidence, unknowns)
    return docs


def _recipients_for(key: str, case: Case) -> str:
    return {
        "T7_staff_ransom": "전 직원(전화·메신저 등 업무 메일 밖 채널)",
        "T1_customer": "메일을 받은 거래처·고객, 내부 영업",
        "T2_deal_check": "해당 거래처 담당자(원장 번호로 전화 확인 후 발송)",
        "T3_staff": "전 직원(침해되지 않은 채널)",
        "T4_bank": "송금 은행 사고접수 창구",
        "T5_insurer": "보험사 사고접수 담당",
        "T6_exec5": "대표·경영진",
    }.get(key, "")


def _blank_label(name: str) -> str:
    return f"〔{UNKNOWN}: {name}〕"


def _done_line(case: Case) -> str:
    """체크리스트에 완료 표시한 조치만 시각과 함께 쓴다 — 하지 않은 조치를 했다고 적지 않는다."""
    done = sorted((case.done or {}).values(), key=lambda d: d.get("at_iso") or "")
    if not done:
        return _blank_label("현재까지의 대응 — 화면의 '지금 할 일'에 완료 표시하면 시각과 함께 채워집니다")
    return "; ".join(f"{d.get('at', '')} {d.get('action', '')}".strip() for d in done[:8])


def _header(title: str, case: Case, purpose: str) -> str:
    return (f"{title}\n{BRAND_KO} · {BRAND_EN} — 초동대응 초안(발송·제출 전 〔미확인〕 확인)\n"
            f"사건번호: {case.id} / 기준: {kst_label(case.aware_at) if case.aware_at else UNKNOWN}\n"
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
        f"6. 현재까지의 대응: {_done_line(case)}\n"
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
        f"해당 사서함에 보관된 {case.value('pi_data_types') or _blank_label('개인정보 항목')}이(가) "
        "제3자에게 열람되었을 가능성이 있습니다.\n\n"
        f"· 현재 확인된 사실: {_known_facts_line(det, case)}\n"
        "· 아직 확인되지 않은 사실: 열람된 정보의 정확한 항목과 규모, 추가 유출 여부\n"
        f"· 당사가 한 조치: {_done_line(case)}\n\n"
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


def _ransom_report(case: Case, det: DetectionResult, cls: Classification,
                   evidence: list[str], unknowns: list[str]) -> Document:
    """랜섬웨어 사고 대응 경과 보고 — 몸값 지불 금지 원칙과 복구 게이트를 문장으로 고정한다."""
    ddl = {d.rule_id: d for d in deadline_mod.compute(case)}
    intrusion = ddl.get("R_INTRUSION_REPORT")
    pi = ddl.get("R_PI_LEAK_REPORT")
    hosts = case.value("encrypted_hosts")
    backup = {"offline_safe": "오프라인 사본 확보(복구 가능)", "at_risk": "백업이 같은 망에 노출됨",
              "unknown": "백업 상태 미확인"}.get(case.value("backup_status"), "백업 상태 미확인")
    body = _header("랜섬웨어 사고 대응 경과 보고", case, "경영진·전문 대응 조직 전달용")
    body += (
        f"1. 상황 요약\n"
        f"  - 판별: {cls.label} ({cls.level})\n"
        f"  - 암호화 확인 호스트: {f'{hosts}대' if isinstance(hosts, int) else UNKNOWN}\n"
        f"  - 변조 확장자: {case.value('encrypted_ext') or UNKNOWN}\n"
        f"  - 랜섬노트: {case.value('ransom_note') or UNKNOWN}\n"
        f"  - 백업 상태: {backup}\n\n"
        f"2. 확인된 사실(로그 근거)\n"
        + "\n".join(f"  - {kst_label(f.ts)} {f.rule_id} {f.summary}" for f in det.ordered()
                    if f.rule_id.startswith("RW_")) + "\n\n"
        "3. 몸값 지불 금지 원칙\n"
        "  - 지불해도 복호화를 보장하지 않습니다(복호화 키 미제공·부분 복호화 사례 다수).\n"
        "  - 지불은 공격자에게 자금을 대고, 같은 조직이 재표적이 됩니다(지불 이력이 유통됨).\n"
        "  - 지불 협상 중에도 암호화·유출 데이터 공개 협박은 계속됩니다.\n"
        "  - 대신: 백업 오프라인 사본 확인, 복구 도구(No More Ransom·KISA 118) 확인, 신고·통지 기한 준수.\n"
        f"  - 몸값 요구액: {case.value('ransom_amount') or UNKNOWN} / 지불 여부: "
        f"{'지불함' if case.value('ransom_paid') is True else '지불하지 않음' if case.value('ransom_paid') is False else UNKNOWN}\n\n"
        "4. 복구 계획(백업 기반)\n"
        "  - 복구 원본: 오프라인 백업 사본(마지막 정상 시점 확인 후 읽기 전용으로 검사)\n"
        "  - 복구 순서: 서비스 복구 → 데이터 복구 → 검증(재감염 여부)\n"
        "  - 복구 전 확인: 백업 무결성 검사, 감염 경로 차단(계정·VPN·원격접속·공급망), 격리 해제 조건\n\n"
        "5. 법정 신고·통지\n"
        f"  - 침해사고 최초신고(정보통신망법 §48조의3, 24시간): [{intrusion.status if intrusion else UNKNOWN}] "
        f"{kst_label(intrusion.due) if intrusion and intrusion.due else UNKNOWN}\n"
        f"  - 개인정보 유출 신고·통지(개인정보보호법 §34, 72시간): [{pi.status if pi else UNKNOWN}] "
        f"{kst_label(pi.due) if pi and pi.due else UNKNOWN}\n"
        "  - 신고 창구: KISA 보호나라·118, 개인정보포털. 제출은 담당자가 한다(이 문서는 초안).\n\n"
        "6. 현재 조치와 다음 단계\n"
        "  - 완료: 감염 호스트 분리, 백업 분리, 로그·랜섬노트 보존\n"
        "  - 진행: 암호화 범위·감염 경로 확인, KISA 118 상담, 복구 검증\n"
        "  - 결정 필요: 복구 우선순위, 외부 사고대응 선임, 서비스 중단 범위와 고객 안내\n"
    )
    body += "\n■ 확인\n" + "\n".join(evidence) + "\n\n■ 미확인\n" + "\n".join(f"- {u}" for u in unknowns)
    return Document("tpl_ransom_report", "랜섬웨어 사고 대응 경과 보고", "report", body, evidence, unknowns,
                    ["몸값 지불 금지 원칙 명시", "복구는 검증된 백업으로만", "신고 기한·담당 표기",
                     "확인/추정/미확인 구분"], "경영진·KISA·외부 대응 조직")


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
    """DOCX 내보내기 — Windows PC Word·한컴오피스에서 한글이 깨지지 않는 보고서형 문서.

    - 맑은 고딕(Malgun Gothic)을 ascii/hAnsi/eastAsia/cs 모든 슬롯에 명시한다
      (테마 폰트 속성은 지운다 — 테마가 명시 폰트를 이기는 경우가 있다).
    - `■`·`1.` 소제목은 Heading, `- `/`  - ` 는 실제 불릿, `|` 표는 Word 표로 만든다.
    - 〔미확인: ...〕 는 볼드+붉은색+배경으로 강조해 발송 전에 눈에 띄게 한다.
    - A4·여백 20mm·상단 브랜드 안내·바닥글(페이지 번호)를 붙인다.

    python-docx가 없으면 None.
    """
    try:
        from io import BytesIO

        from docx import Document as Docx  # type: ignore
        from docx.enum.section import WD_SECTION_START  # noqa: F401
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        from docx.shared import Mm, Pt, RGBColor
    except Exception:
        return None

    d = Docx()
    _docx_page_setup(d, Mm)
    _docx_fonts(d, qn)
    _docx_banner(d, doc, Pt, RGBColor, WD_ALIGN_PARAGRAPH, qn, OxmlElement)
    _docx_render_body(d, doc.body, doc.title, Pt, RGBColor, qn, OxmlElement,
                      WD_TABLE_ALIGNMENT, WD_ALIGN_PARAGRAPH)
    _docx_footer(d, Pt, RGBColor, qn, OxmlElement, WD_ALIGN_PARAGRAPH)

    buf = BytesIO()
    d.save(buf)
    return _patch_font_table(buf.getvalue())


# ------------------------------------------------------------------ DOCX 구성
_PPR_AFTER_SHD = (
    "w:tabs", "w:suppressAutoHyphens", "w:kinsoku", "w:wordWrap", "w:overflowPunct",
    "w:topLinePunct", "w:autoSpaceDE", "w:autoSpaceDN", "w:bidi", "w:adjustRightInd",
    "w:snapToGrid", "w:spacing", "w:ind", "w:contextualSpacing", "w:mirrorIndents",
    "w:suppressOverlap", "w:jc", "w:textDirection", "w:textAlignment", "w:textboxTightWrap",
    "w:outlineLvl", "w:divId", "w:cnfStyle", "w:rPr", "w:sectPr", "w:pPrChange",
)
_PPR_AFTER_BDR = ("w:shd",) + _PPR_AFTER_SHD
_RPR_AFTER_SHD = ("w:fitText", "w:vertAlign", "w:rtl", "w:cs", "w:em", "w:lang",
                  "w:eastAsianLayout", "w:specVanish", "w:oMath")
_TCPR_AFTER_SHD = ("w:noWrap", "w:tcMar", "w:textDirection", "w:tcFitText", "w:vAlign",
                   "w:hideMark", "w:headers", "w:cellIns", "w:cellDel", "w:cellMerge",
                   "w:tcPrChange")

INLINE_RE = re.compile(r"(\*\*.+?\*\*|〔[^〕\n]*〕)")
HEADING_RE = re.compile(r"^(\d{1,2})\.\s+(.+)$")
BULLET_RE = re.compile(r"^(\s*)(?:- |· |• )(.*)$")


def _docx_font_rpr(rPr, qn) -> None:
    """rPr 안의 rFonts 를 네 슬롯 모두 맑은 고딕으로 맞춘다(테마 폰트 제거)."""
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = rPr.makeelement(qn("w:rFonts"), {})
        rPr.insert(0, rFonts)
    for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
        if rFonts.get(qn(attr)) is not None:
            del rFonts.attrib[qn(attr)]
    rFonts.set(qn("w:ascii"), FONT_LATIN)
    rFonts.set(qn("w:hAnsi"), FONT_LATIN)
    rFonts.set(qn("w:eastAsia"), FONT_EA)
    rFonts.set(qn("w:cs"), FONT_LATIN)
    rFonts.set(qn("w:hint"), "eastAsia")


def _docx_fonts(d, qn) -> None:
    """Normal·Heading 1~3·docDefaults 에 폰트·언어를 고정한다."""
    from docx.shared import Pt, RGBColor

    styles = d.styles.element
    defaults = styles.find(qn("w:docDefaults"))
    if defaults is not None:
        rpr_default = defaults.find(qn("w:rPrDefault"))
        rPr = rpr_default.find(qn("w:rPr")) if rpr_default is not None else None
        if rPr is not None:
            _docx_font_rpr(rPr, qn)
            lang = rPr.find(qn("w:lang"))
            if lang is None:
                lang = rPr.makeelement(qn("w:lang"), {})
                rPr.append(lang)
            lang.set(qn("w:val"), "ko-KR")
            lang.set(qn("w:eastAsia"), "ko-KR")

    for name, size, color, bold in (("Normal", 10.5, "0B1B33", False),
                                    ("Heading 1", 19, "14305C", True),
                                    ("Heading 2", 13, "1D4ED8", True),
                                    ("Heading 3", 11.5, "1F3A68", True)):
        try:
            st = d.styles[name]
        except KeyError:
            continue
        rPr = st.element.get_or_add_rPr()
        _docx_font_rpr(rPr, qn)
        st.font.size = Pt(size)
        st.font.color.rgb = RGBColor.from_string(color)
        st.font.bold = bold
        st.font.name = FONT_LATIN
        pf = st.paragraph_format
        if name == "Normal":
            pf.space_before = Pt(0)
            pf.space_after = Pt(4)
            pf.line_spacing = 1.35
        else:
            pf.space_before = Pt(14 if name == "Heading 1" else 11)
            pf.space_after = Pt(5)
            pf.keep_with_next = True


def _docx_page_setup(d, Mm) -> None:
    sec = d.sections[0]
    sec.page_width = Mm(210)
    sec.page_height = Mm(297)
    sec.top_margin = Mm(20)
    sec.bottom_margin = Mm(20)
    sec.left_margin = Mm(20)
    sec.right_margin = Mm(20)
    sec.header_distance = Mm(10)
    sec.footer_distance = Mm(10)


def _docx_run(run, qn, size=None, bold=None, italic=None, color=None) -> None:
    """모든 런에 네 폰트 슬롯을 명시한다(상속·테마에 기대지 않는다)."""
    from docx.shared import Pt, RGBColor

    rPr = run._element.get_or_add_rPr()
    _docx_font_rpr(rPr, qn)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    if color is not None:
        run.font.color.rgb = RGBColor.from_string(color)


def _shade_run(run, fill: str, qn, OxmlElement) -> None:
    rPr = run._element.get_or_add_rPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    rPr.insert_element_before(shd, *_RPR_AFTER_SHD)


def _shade_paragraph(p, fill: str, qn, OxmlElement) -> None:
    pPr = p._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pPr.insert_element_before(shd, *_PPR_AFTER_SHD)


def _left_bar(p, color: str, qn, OxmlElement) -> None:
    """문단 왼쪽 색 띠 — 경고·브랜드 안내를 눈에 띄게."""
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    left = OxmlElement("w:left")
    left.set(qn("w:val"), "single")
    left.set(qn("w:sz"), "18")
    left.set(qn("w:space"), "6")
    left.set(qn("w:color"), color)
    pBdr.append(left)
    pPr.insert_element_before(pBdr, *_PPR_AFTER_BDR)


def _bottom_rule(p, color: str, qn, OxmlElement) -> None:
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "8")
    bottom.set(qn("w:space"), "4")
    bottom.set(qn("w:color"), color)
    pBdr.append(bottom)
    pPr.insert_element_before(pBdr, *_PPR_AFTER_BDR)


def _docx_banner(d, doc: Document, Pt, RGBColor, WD_ALIGN_PARAGRAPH, qn, OxmlElement) -> None:
    """문서 상단 브랜드 안내 — 제품명·부제·초안 경고."""
    p = d.add_paragraph()
    p.paragraph_format.space_after = Pt(2)
    r = p.add_run(f"{BRAND_EN} · {BRAND_KO}")
    _docx_run(r, qn, size=10, bold=True, color="2563EB")
    r2 = p.add_run("   " + BRAND_SUBTITLE)
    _docx_run(r2, qn, size=8.5, color="5B6B84")

    note = d.add_paragraph()
    note.paragraph_format.space_after = Pt(8)
    rn = note.add_run(DOCX_NOTICE)
    _docx_run(rn, qn, size=8.5, bold=True, color="B42318")
    _bottom_rule(note, "CBD9F2", qn, OxmlElement)

    h = d.add_heading(level=1)
    hr = h.add_run(doc.title)
    _docx_run(hr, qn, size=19, bold=True, color="14305C")
    h.paragraph_format.space_before = Pt(10)
    h.paragraph_format.space_after = Pt(8)


def _docx_footer(d, Pt, RGBColor, qn, OxmlElement, WD_ALIGN_PARAGRAPH) -> None:
    footer = d.sections[0].footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(f"{BRAND_KO} · {BRAND_EN} — 초동대응 초안 (발송 전 확인) · ")  # noqa: E501
    _docx_run(r, qn, size=8, color="8494AD")
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), " PAGE ")
    inner = OxmlElement("w:r")
    rPr = OxmlElement("w:rPr")
    rFonts = OxmlElement("w:rFonts")
    rFonts.set(qn("w:ascii"), FONT_LATIN)
    rFonts.set(qn("w:hAnsi"), FONT_LATIN)
    rFonts.set(qn("w:eastAsia"), FONT_EA)
    rFonts.set(qn("w:cs"), FONT_LATIN)
    rPr.append(rFonts)
    sz = OxmlElement("w:sz")
    sz.set(qn("w:val"), "16")
    rPr.append(sz)
    inner.append(rPr)
    t = OxmlElement("w:t")
    t.text = "1"
    inner.append(t)
    fld.append(inner)
    p._p.append(fld)


def _same_title(text: str, title: str) -> bool:
    norm = lambda s: re.sub(r"\s+", "", s or "")
    return norm(text) == norm(title)


def _add_inline(p, text: str, qn, OxmlElement, *,
                size=None, bold=False, italic=None, color=None) -> None:
    """본문 한 줄을 런으로 — 〔미확인: …〕 는 볼드·붉은색·연한 배경으로 강조."""
    for part in INLINE_RE.split(text):
        if not part:
            continue
        if part.startswith("〔") and part.endswith("〕"):
            r = p.add_run(part)
            _docx_run(r, qn, size=size, bold=True, color="B42318", italic=False)
            _shade_run(r, "FFF1F2", qn, OxmlElement)
        elif part.startswith("**") and part.endswith("**") and len(part) > 4:
            r = p.add_run(part[2:-2])
            _docx_run(r, qn, size=size, bold=True, italic=italic, color=color)
        else:
            r = p.add_run(part)
            _docx_run(r, qn, size=size, bold=bold or None, italic=italic, color=color)


def _docx_paragraph(d, text: str, qn, OxmlElement, *,
                    size=None, bold=False, italic=None, color=None,
                    space_after=None, indent=None):
    from docx.shared import Cm, Pt

    p = d.add_paragraph()
    if space_after is not None:
        p.paragraph_format.space_after = Pt(space_after)
    if indent is not None:
        p.paragraph_format.left_indent = Cm(indent)
    _add_inline(p, text, qn, OxmlElement, size=size, bold=bold, italic=italic, color=color)
    return p


def _docx_heading(d, text: str, level: int, qn) -> None:
    from docx.shared import Pt

    h = d.add_heading(level=level)
    r = h.add_run(text)
    _docx_run(r, qn, size={1: 19, 2: 13, 3: 11.5}.get(level, 11), bold=True,
              color={1: "14305C", 2: "1D4ED8", 3: "1F3A68"}.get(level, "1F3A68"))
    h.paragraph_format.space_before = Pt({1: 12, 2: 12, 3: 9}.get(level, 9))
    h.paragraph_format.space_after = Pt(4)


def _is_heading_like(text: str) -> bool:
    """'1. 확인된 사실' 은 소제목, '1. 신고인: …' 은 항목이다."""
    return len(text) <= 40 and ":" not in text[:24]


def _split_field(text: str) -> tuple[str, str] | None:
    idx = text.find(":")
    if idx <= 0 or idx > 40:
        return None
    return text[:idx].strip(), text[idx + 1:].strip()


def _field_paragraph(d, text: str, qn, OxmlElement, *, size=10.5):
    from docx.shared import Pt

    parts = _split_field(text)
    if not parts:
        return _docx_paragraph(d, text, qn, OxmlElement, size=size)
    label, value = parts
    p = d.add_paragraph()
    p.paragraph_format.space_after = Pt(3)
    lr = p.add_run(label + ":")
    _docx_run(lr, qn, size=size, bold=True, color="1F3A68")
    if value:
        vr = p.add_run(" " + value)
        _docx_run(vr, qn, size=size, color="0B1B33")
    return p


def _collect_table(lines: list[str], start: int) -> tuple[list[list[str]] | None, int]:
    """`|` 로 구분된 연속 줄을 표로 모은다(구분선·빈 줄 종료)."""
    rows: list[list[str]] = []
    i = start
    while i < len(lines):
        raw = lines[i].strip()
        if not raw:
            break
        if re.fullmatch(r"[-=_]{5,}", raw):
            i += 1
            continue
        if "|" not in raw:
            break
        cells = [c.strip() for c in raw.strip("|").split("|")]
        if len(cells) < 2:
            break
        rows.append(cells)
        i += 1
    if len(rows) < 2:
        return None, start
    width = max(len(r) for r in rows)
    rows = [r + [""] * (width - len(r)) for r in rows]
    return rows, i


def _docx_table(d, rows: list[list[str]], qn, OxmlElement, *,
                Pt, Mm, WD_TABLE_ALIGNMENT, WD_ALIGN_PARAGRAPH) -> None:
    cols = len(rows[0])
    table = d.add_table(rows=0, cols=cols)
    try:
        table.style = "Table Grid"
    except Exception:  # noqa: BLE001 - 스타일이 없어도 표는 만든다
        pass
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True

    # 열 너비 — 글자 길이에 비례(내용 열이 넓게).
    weights = []
    for c in range(cols):
        longest = max((len(r[c]) for r in rows), default=6)
        weights.append(min(max(longest, 6), 48))
    total = sum(weights) or 1
    usable = Mm(170)
    for c, w in enumerate(weights):
        table.columns[c].width = int(usable * w / total)

    for r_idx, row in enumerate(rows):
        tr = table.add_row()
        if r_idx == 0:
            trPr = tr._tr.get_or_add_trPr()
            th = OxmlElement("w:tblHeader")
            trPr.append(th)
        for c_idx, value in enumerate(row):
            cell = tr.cells[c_idx]
            cell.width = int(usable * weights[c_idx] / total)
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            run = p.add_run(value)
            _docx_run(run, qn, size=9, bold=(r_idx == 0),
                      color=("0B1B33" if r_idx == 0 else "26364F"))
            tcPr = cell._tc.get_or_add_tcPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), "E8F1FF" if r_idx == 0 else ("FBFDFF" if r_idx % 2 else "FFFFFF"))
            tcPr.insert_element_before(shd, *_TCPR_AFTER_SHD)
    d.add_paragraph().paragraph_format.space_after = Pt(2)


def _docx_render_body(d, body: str, title: str, Pt, RGBColor, qn, OxmlElement,
                      WD_TABLE_ALIGNMENT, WD_ALIGN_PARAGRAPH) -> None:
    from docx.shared import Cm, Mm

    lines = (body or "").replace("\r\n", "\n").split("\n")
    i = 0
    first = True
    while i < len(lines):
        line = lines[i].rstrip()
        text = line.strip()
        i += 1
        if not text:
            continue
        if re.fullmatch(r"[-=_]{10,}", text):          # 구분선
            continue
        if first:
            first = False
            if _same_title(text, title):
                continue
        if text.startswith(BRAND_KO) or text.startswith(BRAND_EN):
            continue

        # 내부 검토용 경계
        if text.startswith("▼"):
            p = _docx_paragraph(d, text, qn, OxmlElement, size=9.5, bold=True, color="B45309")
            _shade_paragraph(p, "FFF7E6", qn, OxmlElement)
            _left_bar(p, "F59E0B", qn, OxmlElement)
            continue

        # 표
        if "|" in text:
            rows, nxt = _collect_table(lines, i - 1)
            if rows:
                _docx_table(d, rows, qn, OxmlElement, Pt=Pt, Mm=Mm,
                            WD_TABLE_ALIGNMENT=WD_TABLE_ALIGNMENT, WD_ALIGN_PARAGRAPH=WD_ALIGN_PARAGRAPH)
                i = nxt
                continue

        # 제목
        if text.startswith("제목:"):
            p = d.add_paragraph()
            p.paragraph_format.space_after = Pt(8)
            lab = p.add_run("제목  ")
            _docx_run(lab, qn, size=8.5, bold=True, color="5B6B84")
            val = p.add_run(text[3:].strip())
            _docx_run(val, qn, size=11.5, bold=True, color="0B1B33")
            continue

        # 사건번호·용도 등 머리 정보
        if text.startswith(("사건번호:", "용도:")):
            _docx_paragraph(d, text, qn, OxmlElement, size=9, color="5B6B84", space_after=2)
            continue

        # ■ 소제목 / 항목
        if text.startswith("■"):
            content = text.lstrip("■").strip()
            if _is_heading_like(content):
                _docx_heading(d, content, 2, qn)
            else:
                p = _field_paragraph(d, content, qn, OxmlElement, size=11)
                _shade_paragraph(p, "EEF4FF", qn, OxmlElement)
                _left_bar(p, "2563EB", qn, OxmlElement)
            continue

        # ☐ 발송 전 통과표
        if text.startswith(("☐", "□")):
            p = _docx_paragraph(d, text, qn, OxmlElement, size=10.5, color="16243D")
            p.paragraph_format.left_indent = Cm(0.5)
            continue

        # 불릿
        m = BULLET_RE.match(line)
        if m:
            depth = 2 if len(m.group(1).replace("\t", "  ")) >= 2 else 1
            style = "List Bullet 2" if depth == 2 else "List Bullet"
            p = d.add_paragraph(style=style)
            p.paragraph_format.space_after = Pt(2)
            _add_inline(p, m.group(2), qn, OxmlElement, size=10.5)
            continue

        # 숫자 소제목 / 항목
        m = HEADING_RE.match(text)
        if m:
            content = m.group(2).strip()
            if _is_heading_like(content):
                _docx_heading(d, f"{m.group(1)}. {content}", 2, qn)
            else:
                _field_paragraph(d, text, qn, OxmlElement)
            continue

        # ※ 안내문
        if text.startswith("※"):
            _docx_paragraph(d, text, qn, OxmlElement, size=9, italic=True, color="5B6B84")
            continue

        _docx_paragraph(d, text, qn, OxmlElement, size=10.5, color="16243D")


def _patch_font_table(data: bytes) -> bytes:
    """word/fontTable.xml 에 맑은 고딕(대체 이름 Malgun Gothic)을 등록한다.

    한글 Windows 기본 글꼴이지만, 문서에 이름이 등록돼 있지 않으면 일부 뷰어가
    다른 글꼴로 대체하며 자모가 벌어지거나 깨져 보인다.
    """
    import io
    import zipfile

    try:
        from docx.oxml import parse_xml
        from docx.oxml.ns import nsdecls
        from lxml import etree
    except Exception:  # noqa: BLE001 - 없으면 원본 그대로
        return data

    wanted = [(FONT_EA, FONT_LATIN, "81"), (FONT_LATIN, FONT_EA, "00")]
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            blob = zin.read(info.filename)
            if info.filename == "word/fontTable.xml":
                try:
                    root = parse_xml(blob)
                    have = {f.get("{%s}name" % root.nsmap.get("w", "")) for f in root}
                    for name, alt, charset in wanted:
                        if name in have or root.nsmap.get("w") is None:
                            continue
                        el = parse_xml(
                            f'<w:font {nsdecls("w")} w:name="{name}">'
                            f'<w:altName w:val="{alt}"/><w:charset w:val="{charset}"/>'
                            '<w:family w:val="swiss"/><w:pitch w:val="variable"/></w:font>')
                        root.append(el)
                    blob = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
                except Exception:  # noqa: BLE001 - 손대지 않고 원본 유지
                    pass
            zout.writestr(info, blob)
    return out.getvalue()
