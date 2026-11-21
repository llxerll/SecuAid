"""에이전트 오케스트레이터 — 대화·로그·Liner API·결정적 엔진을 한 사건으로 묶는다.

역할 분담(기획서 3장)
- 계산: 규칙 엔진(detect/classify/severity/deadline) — LLM 없이도 같은 결과
- 판단·문장: Liner Mark(liner-mark-1.3) — 사실을 해석하고 대화·문서 문장을 만든다
- 근거: Liner Search API(검색 결과) + Search Agent API(출처 있는 답변)

Liner 키가 없거나 오류가 나면 자동으로 규칙 기반 모드로 내려간다(데모가 멈추지 않게).
"""
from __future__ import annotations

import base64
import json
import re
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import categories as category_mod
from . import deadline as deadline_mod
from . import docs as docs_mod
from . import eml as eml_mod
from . import evidence as evidence_mod
from . import ingest
from . import nlu
from . import playbook
from .case import DEFAULT_FACTS, FACT_LABEL, Case, Fact, display_value
from .classify import Classification, classify
from .detect import DetectionResult, Finding, detect
from .liner import LinerClient, LinerError, LinerUnavailable
from .mask import Masker
from .severity import Severity, evaluate as evaluate_severity
from .timeutil import kst_label, kst_short, now_utc, parse_kst_local, parse_ts

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "data" / "scenarios"

# 전화 한 통만으로는 '우리 계정이 뚫린 것(ATO)'인지 '비슷한 주소로 사칭한 것'인지 알 수 없다 —
# 메일 원본·로그가 들어오기 전까지 사고 유형(incident_type)을 정하지 않는다.
AMBIGUOUS_TYPE = {"CAT01_BEC_ACCOUNT_CHANGE"}

FACT_SCHEMA_HINT = """{
  "org_name": "회사명 또는 null",
  "org_domains": ["도메인"],
  "account": "침해 의심 계정 또는 null",
  "transfer_status": "none|pending|done|unknown",
  "transfer_amount_krw": 숫자 또는 null,
  "transfer_counterparty": "상대 또는 null",
  "personal_data_leak": "none|suspected|confirmed|unknown",
  "affected_count": 숫자 또는 null,
  "sensitive_or_unique_id": true|false|null,
  "external_illegal_access": true|false|null,
  "admin_compromise": true|false|null,
  "is_ict_service_provider": true|false|null,
  "insurance": true|false|null,
  "pi_data_types": "항목" 또는 null,
  "org_size": 숫자(직원 수) 또는 null,
  "category": "CAT01_BEC_ACCOUNT_CHANGE|CAT02_MAIL_ACCOUNT_ATO|CAT03_LOOKALIKE_SPOOF|CAT04_RANSOMWARE|CAT05_SERVER_ROOT|CAT06_CLOUD_KEY_LEAK|CAT07_WEB_DB_LEAK|CAT08_INSIDER_LEAK|CAT09_DDOS_OUTAGE|CAT10_SUPPLY_CHAIN 중 하나 또는 null",
  "aware_time": "사용자가 사고를 처음 안 시각 'YYYY-MM-DD HH:MM'(KST) 또는 null",
  "events": [{"time": "YYYY-MM-DD HH:MM(KST)", "what": "사고와 관련해 실제로 일어난 일 한 줄"}],
  "question": "사용자가 묻는 질문이 있으면 그 질문 한 문장, 없으면 null"
}"""

LLM_FACT_PROMPT = (
    "너는 한국 소규모 회사의 메일 침해 초동대응을 돕는 분석기다. "
    "사용자 발화에서 사건 사실만 뽑아 JSON으로 출력한다. 발화에 없는 값은 절대 추측하지 말고 null로 둔다. "
    "금액은 원 단위 정수로 바꾼다(예: 1,870만 원 → 18700000). 사람 수는 정수. "
    "명시적으로 '송금했다'고 하면 done, '송금할 예정'이면 pending, '송금 안 했다'면 none, 언급이 없으면 unknown. "
    "직원 수를 정보주체 수(affected_count)로 쓰지 않는다. '오늘 아침 8시 반'처럼 상대 시각은 주어진 현재 시각 기준으로 "
    "절대 시각으로 바꾼다. 유형(category)은 발화가 그 유형을 분명히 가리킬 때만 고른다. "
    "events 에는 시각을 알 수 있는 실제 사건(발송·로그인·발견·연락·조치)만 넣고, 사용자의 상태·의견·질문·사용 환경은 넣지 않는다."
)

NARRATE_PROMPT = (
    "너는 사고 대응 비서다. 아래 JSON 사건 상태만 근거로 한국어 4~6문장 브리핑을 쓴다. 규칙: "
    "1) 확인/추정/미확인을 반드시 구분해 표기한다. 2) JSON에 없는 사실·수치·법령을 만들지 않는다. "
    "3) '피해 없음' 같은 단정을 하지 않는다. 4) 첫 문장은 지금 가장 급한 행동. 5) 링크를 쓰지 않는다. "
    "6) 3인칭 설명조가 아니라 담당자에게 말하듯 쓴다. 7) 사고 유형에 맞지 않는 자료(예: 랜섬웨어에 메일 로그)를 요구하지 않는다. "
    "8) 상대는 보안 비전문가다 — 'ATO·세션 토큰' 같은 용어는 쉬운 말을 함께 쓴다. 9) 로그를 못 구해도 대응은 계속된다는 점과, "
    "화면 사진·발견 경위 메모·업체 요청으로 대신할 수 있음을 필요할 때 알려 준다."
)

LAW_QUESTION = (
    "정보통신망법 제48조의3의 침해사고 신고 기한과, 개인정보 보호법 제34조의 개인정보 유출 통지·신고 기한이 "
    "각각 몇 시간인지 2026년 기준으로 확인해 주세요. 두 기한의 기산점(무엇을 안 때부터인지)과 "
    "2026년 개정으로 달라진 점이 있으면 함께 알려 주세요. 출처 링크를 포함해 주세요."
)


@dataclass
class Agent:
    case: Case = field(default_factory=Case)
    client: LinerClient = field(default_factory=LinerClient.from_env)
    masker: Masker = field(default_factory=Masker)
    det: DetectionResult = field(default_factory=DetectionResult)
    cls: Classification | None = None
    sev: Severity | None = None
    scenario: str | None = None
    narrative: str = ""
    logs: list = field(default_factory=list)
    sev_history: list = field(default_factory=list)

    def __post_init__(self) -> None:
        self.masker.keep_ip = True  # IP는 내부 대응에 필요하고, 예약 대역만 쓰는 데모 데이터다
        if self.cls is None:
            self.cls = classify(self.case, self.det)
        if self.sev is None:
            self.sev = evaluate_severity(self.case, self.det, self.cls)

    # ------------------------------------------------------------------ 시나리오
    @staticmethod
    def scenarios() -> list[dict]:
        out = []
        if not SCENARIO_DIR.exists():
            return out
        for d in sorted(SCENARIO_DIR.iterdir()):
            meta_path = d / "scenario.json"
            if meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                out.append({"id": d.name, **{k: meta.get(k) for k in ("title", "summary")}})
        return out

    def load_scenario(self, scenario_id: str, *, aware_at: str | None = None, preload: bool = True) -> None:
        d = SCENARIO_DIR / scenario_id
        if not d.exists():
            raise FileNotFoundError(f"시나리오를 찾을 수 없습니다: {scenario_id}")
        meta = json.loads((d / "scenario.json").read_text(encoding="utf-8"))
        self.scenario = scenario_id
        self.case = Case()
        self.det = DetectionResult()
        self.logs = []
        self.sev_history = []
        for key, val in (meta.get("facts") or {}).items():
            self.case.set_fact(key, val, "확인", f"시나리오 데이터({meta.get('title', scenario_id)})")
        self.case.set_fact("org_name", meta.get("org_name"), "확인", "시나리오 데이터")
        self.case.set_fact("org_domains", meta.get("org_domains", []), "확인", "시나리오 데이터")
        aware = aware_at or meta.get("aware_at")
        if aware:
            self.case.set_aware_at(aware, source="사용자 진술(데모 입력)")
        self.case.log("scenario", f"시나리오 로드: {meta.get('title', scenario_id)}")

        if preload:
            for name in meta.get("logs", []):
                p = d / name
                if p.exists():
                    log = ingest.parse(p.read_text(encoding="utf-8", errors="replace"))
                    self.logs.append(log)
                    if log.records:
                        self.case.log_kinds.append(log.kind)
            self.det = detect(self.logs, org_country=self.case.value("org_country", "KR") or "KR")
            for name in meta.get("emls", []):
                p = d / name
                if p.exists():
                    tri = eml_mod.triage_eml(p.read_text(encoding="utf-8", errors="replace"),
                                             org_domains=set(self.case.value("org_domains") or []),
                                             suspect_ips=set(self.det.suspect_ips))
                    self.case.eml_triage.append(tri.to_dict())
            if self.case.eml_triage:
                self.det = detect(self.logs, org_country=self.case.value("org_country", "KR") or "KR",
                                  is_eml=self.case.eml_triage[-1])
            self.case.findings = [f.to_dict() for f in self.det.ordered()]
        self._recompute()
        self.narrative = meta.get("narrative", "")

    # ------------------------------------------------------------------ 대화
    def handle(self, text: str, *, defer: bool = False) -> dict:
        """사용자 입력 한 건 처리.

        defer=True(화면 기본값): 결정적 엔진 결과만 즉시 돌려주고, Liner 호출(사실 보조 추출·브리핑·
        법령 재확인·즉답 가이드)은 `pending` 목록으로 넘겨 화면이 /enrich·/law 로 따로 부른다.
        사용자는 판정·할 일·기한을 1초 안에 보고, Liner 문장은 뒤따라 붙는다.
        """
        self._defer = defer
        self._pending = []
        text = (text or "").strip()
        if not text:
            return self.board(reply="무엇을 확인할까요? 사건 설명, 로그 붙여넣기, 메일 원본 중 하나로 시작할 수 있습니다.")
        warnings = playbook.guardrail(text, self.case, self.cls)
        started_now = not self.case.aware_at
        self.case.log("user", text[:500])

        kind = ingest.sniff(text)
        actions_taken: list[str] = []

        if kind == ingest.EML:
            tri = eml_mod.triage_eml(text, org_domains=set(self.case.value("org_domains") or []),
                                     suspect_ips=set(self.det.suspect_ips))
            self.case.eml_triage.append(tri.to_dict())
            actions_taken.append(f"메일 원본 판독: {eml_mod.VERDICT_LABEL.get(tri.verdict, tri.verdict)}")
            self._run_detection(extra_eml=tri.to_dict())
        elif kind != ingest.UNKNOWN and len(text) > 80:
            parsed = ingest.parse_multi(text)
            for log in parsed:
                self.logs.append(log)
                if log.records and log.kind not in self.case.log_kinds:
                    self.case.log_kinds.append(log.kind)
            self._run_detection()
            actions_taken.append("로그 인제스트: " + ", ".join(
                f"{ingest.KIND_LABEL.get(l.kind, l.kind)} {len(l)}건" for l in parsed))
        else:
            facts = self._extract_facts(text)
            if facts:
                actions_taken.append("사실관계 갱신: " + ", ".join(facts[:6]))
            # 10대 유형은 대화 한 줄에서도 추정 연결한다(확정은 로그·유형 선택으로).
            if self.case.value("category") is None:
                cat = category_mod.guess(text)
                if cat:
                    self.case.set_fact("category", cat.id, "추정", "대화 내용에서 유형 추정")
                    self.case.set_fact("category_label", cat.name, "추정", "대화 내용에서 유형 추정")
                    if not self.case.known("incident_type") and cat.id not in AMBIGUOUS_TYPE:
                        self.case.set_fact("incident_type", cat.incident_type, "추정", f"유형 추정({cat.name})")
                    actions_taken.append(f"10대 유형 연결: {cat.no}. {cat.name}")

        if started_now and not self.case.aware_at:
            self.ensure_aware()     # 72시간 시계는 사건이 시작되는 순간부터 돈다(나중에 실제 시각으로 고칠 수 있음)
        intent = self._intent(text, kind)
        need_law = intent == "law" or (self.det.findings and not self.case.law_checks and intent == "logs")
        if need_law:
            if defer and self.client.available:
                self._pending.append("law")
            else:
                self.verify_law()
        if intent == "guide" and self.case.value("category"):
            if defer and self.client.available:
                self._pending.append("guide")
            else:
                self.quick_guide(force=True)
            actions_taken.append("유형별 즉답 가이드 조회")
        if intent == "question" and self.client.available:
            if defer:
                self._pending.append("answer")
            else:
                try:
                    self.answer_question(text)
                except LinerError:
                    pass
        if intent == "evidence":
            plats = evidence_mod.recommended(self.case)
            actions_taken.append("증거 확보 도우미 안내: " + ", ".join(evidence_mod.load_guide()["platforms"][p]["name"].split("(")[0] for p in plats[:2]))
        if intent == "docs":
            self.compose_docs(wait_law=not defer)
            actions_taken.append("문서 초안 생성")

        self._recompute()
        reply = self._reply_text(intent, actions_taken, warnings, narrate=not defer)
        if defer and self.client.available:
            self._pending.append("narrate")
        board = self.board(reply=reply, warnings=warnings)
        board["pending"] = list(dict.fromkeys(self._pending))
        self.case.log("assistant", reply[:800])
        return board

    def _intent(self, text: str, kind: str) -> str:
        t = text.lower()
        # 로그·메일 원문에 들어 있는 단어(예: '문서 공유')로 의도를 잘못 읽지 않는다.
        if kind != ingest.UNKNOWN and len(text) > 300:
            return "logs"
        if any(k in t for k in ("법령", "법 개정", "최신", "기한이 맞", "근거 조항", "법이 바뀐", "재확인",
                                 "신고해야", "신고 대상", "신고 의무", "통지해야", "기한이 언제")):
            return "law"
        if any(k in t for k in ("초안", "문서", "보고서", "통지문", "신고서", "작성해", "만들어줘", "공지문")):
            return "docs"
        if any(k in t for k in ("가이드", "즉답", "어떻게 대응", "뭐부터", "무엇부터")):
            return "guide"
        if any(k in t for k in ("로그가 뭔", "로그는 어디", "로그를 어디", "어디서 뽑", "어디서 확인", "로그 모르", "로그 없", "어떻게 확인", "증거")):
            return "evidence"
        if text.strip().endswith("?") or re.search(r"(나요|까요|가요|ㄹ까|되나|돼요\?|해야 해|하면 돼|어떡|어떻게 해|뭘 해)", text):
            return "question"
        if kind != ingest.UNKNOWN:
            return "logs"
        return "chat"

    # ------------------------------------------------------------------ 사실 추출
    def _extract_facts(self, text: str) -> list[str]:
        updated: list[str] = []
        hedge = any(k in text for k in ("같", "아마", "정도", "듯", "추정", "것 같"))
        level = "추정" if hedge else "확인"
        changes: dict[str, tuple] = {}

        # 인지 시각 · 사용자가 말한 사건(시각이 있는 문장) → 타임라인
        auto_aware = self.case.facts.get("aware_at") and self.case.facts["aware_at"].source.startswith("대화 중 인지")
        m = re.search(r"(20\d{2}-\d{1,2}-\d{1,2}[ T]\d{1,2}:\d{2})", text)
        if m:
            try:
                self.case.set_aware_at(m.group(1).replace("T", " "), source="사용자 입력 시각")
                updated.append("인지 시각")
            except Exception:
                pass
        else:
            for ev in nlu.extract_events(text):
                if self.add_event(ev["when"], ev["what"], level, "사용자 진술"):
                    updated.append(f"타임라인 기록 {ev['when'].strftime('%m/%d %H:%M')}")
                if ev["discovery"] and (not self.case.aware_at or auto_aware):
                    self.case.set_aware_at(ev["when"].astimezone(timezone.utc), source="사용자 진술(발견 시각)", level=level)
                    updated.append(f"인지 시각 {kst_label(self.case.aware_at)}[{level}]")
                    auto_aware = False
            if not self.case.aware_at and any(k in text for k in ("방금", "오늘", "지금", "전화가 왔", "전화 왔", "발견", "알았", "출근")):
                self.case.set_aware_at(now_utc(), source="대화 중 인지(사건 시작 시각 — 실제로 안 시각으로 바꿀 수 있어요)", level="추정")
                updated.append(f"인지 시각 {kst_label(self.case.aware_at)}[추정]")

        # 사용 환경(메일·PC·NAS·쇼핑몰) — 증거 확보 도우미가 이 순서로 안내한다
        plats = evidence_mod.detect_platforms(text)
        if plats:
            cur = list(self.case.value("platform") or [])
            new = [p for p in plats if p not in cur]
            if new:
                self.case.set_fact("platform", cur + new, "확인", "사용자 진술")
                updated.append("사용 환경 " + display_value("platform", new))

        # 송금 — 부정("안 보냈대요", "송금하지 않았") 을 먼저 본다
        money_words = r"(송금|입금|이체|돈|보냈|보내|지급)"
        if re.search(money_words, text) and nlu.negated(text, "보냈|송금|입금|이체|보내"):
            changes["transfer_status"] = ("none", level)
        elif re.search(r"(송금할 예정|송금 예정|보내려|이체 예정|지급 예정|보낸다고|보내기로)", text):
            changes["transfer_status"] = ("pending", level)
        elif re.search(r"(이미\s*송금|송금했|송금 완료|입금했|보냈대|보냈다|이체했|돈을 보냈)", text):
            changes["transfer_status"] = ("done", level)

        # 금액
        m = re.search(r"(\d[\d,\.]*)\s*(억|만)?\s*원", text)
        if m:
            try:
                num = float(m.group(1).replace(",", ""))
                unit = m.group(2)
                amount = int(num * (100_000_000 if unit == "억" else 10_000 if unit == "만" else 1))
                changes["transfer_amount"] = (f"{amount:,}원", level)
            except ValueError:
                pass

        # 인원 — "직원 12명"은 회사 규모, "고객 1,300명분"은 정보주체 수
        m = re.search(r"(직원|임직원|사원|우리 회사|회사)\S{0,3}\s*(\d[\d,]{0,6})\s*명", text)
        if m:
            try:
                changes["org_size"] = (int(m.group(2).replace(",", "")), level)
            except ValueError:
                pass
        m = re.search(r"(고객|회원|정보주체|이용자|개인정보|문의|사서함)[^.?!,]{0,14}?(\d[\d,]{0,8})\s*(명|건)\s*분?", text) \
            or re.search(r"(\d[\d,]{0,8})\s*(명|건)\s*분?\s*(?:의|정도의|가량의)?\s*(고객|회원|정보주체|개인정보|문의)", text)
        if m:
            num = next(g for g in m.groups() if g and re.fullmatch(r"\d[\d,]*", g))
            try:
                changes["affected_count"] = (int(num.replace(",", "")), level)
            except ValueError:
                pass

        # 개인정보
        if re.search(r"(주민번호|주민등록번호).{0,10}(없|미포함)", text):
            changes["sensitive_or_unique_id"] = (False, "확인")
        elif "주민번호" in text or "민감정보" in text:
            changes["sensitive_or_unique_id"] = (True, level)
        pi_words = ("고객 문의", "배송 문의", "사서함에", "고객 정보", "개인정보", "문의 내역", "회원 정보", "고객 명단")
        if any(k in text for k in pi_words):
            few = re.search(r"(거의 없|별로 없|많지 않|조금|일부만|적어요|적습니다)", text)
            none_ = re.search(r"(개인정보|고객 정보|회원 정보)\S{0,4}\s*(?:는|은)?\s*(전혀\s*)?(없어요|없습니다|없음|없다|안 들어|미해당|유출 안)", text)
            if none_ and not few:
                changes["personal_data_leak"] = ("none", level)
            elif any(k in text for k in ("유출 확인", "유출됐", "빼갔", "털렸")):
                changes["personal_data_leak"] = ("confirmed", level)
            else:
                changes["personal_data_leak"] = ("suspected", "추정" if few else level)
            kinds = [w for w in ("이름", "연락처", "전화번호", "주소", "이메일", "주문 내역", "생년월일", "계좌") if w in text]
            if kinds:
                changes["pi_data_types"] = ("·".join(kinds), level)
            elif few:
                changes["pi_data_types"] = ("소량(사용자 진술: 거의 없음 — 항목 미확인)", "추정")

        # 랜섬웨어 관련 사실(v0.5) — 백업 상태·몸값·지불 여부
        if "백업" in text:
            if any(k in text for k in ("꽂혀", "꽂아", "연결돼", "연결되어", "연결된 채", "붙어 있", "같은 랙", "같은 망", "공유 폴더", "같은 서버")) \
                    and not any(k in text for k in ("분리했", "뽑았", "뺐어", "분리 완료")):
                changes["backup_status"] = ("at_risk", level)   # 연결된 외장하드는 함께 암호화될 수 있다
                changes["backup_isolated"] = (False, level)
            elif any(k in text for k in ("오프라인", "테이프", "외장", "분리했", "분리 완료", "격리했", "별도 보관", "뽑았", "뺐어")):
                changes["backup_status"] = ("offline_safe", level)
                changes["backup_isolated"] = (True, level)
            elif any(k in text for k in ("같은 랙", "같은 망", "연결", "온라인", "공유 폴더", "같은 서버")):
                changes["backup_status"] = ("at_risk", level)
        if re.search(r"백업\S{0,2}\s*(은|이)?\s*(전혀\s*)?(없어요|없습니다|없음|안 해|하지 않)", text):
            changes["backup_status"] = ("none", level)
        m = re.search(r"(\d+(?:\.\d+)?)\s*(비트코인|BTC|btc|달러|USD)", text)
        if m:
            changes["ransom_amount"] = (f"{m.group(1)} {m.group(2).upper()}", level)
        if re.search(r"(몸값|랜섬).{0,14}(지불했|지불했습|보냈|결제했)", text):
            changes["ransom_paid"] = (True, "확인")
        elif re.search(r"(몸값|랜섬).{0,14}(지불하지|지불 안|안 보냈|지불 안 했)", text):
            changes["ransom_paid"] = (False, "확인")
        if re.search(r"(암호화|잠겼|.locked).{0,20}(\d[\d,]*)\s*(대|개)", text):
            n = re.search(r"(\d[\d,]*)\s*(대)", text)
            if n:
                try:
                    changes["encrypted_hosts"] = (int(n.group(1).replace(",", "")), level)
                except ValueError:
                    pass

        # 제공자 여부
        svc = re.search(r"(홈페이지|자사 서비스|고객 문의|쇼핑몰|온라인몰|인터넷 쇼핑|웹사이트|앱|회원제|온라인 서비스|예약 사이트).{0,20}(운영|제공|있|해요|합니다)", text)
        if svc and re.search(r"(않아|않습|안 해|안 합|없어|없습)", text[svc.start():svc.end() + 12]):
            changes["is_ict_service_provider"] = (False, level)
        elif svc:
            changes["is_ict_service_provider"] = (True, level)
        dm = re.search(r"@?((?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower()) if "도메인" in text or "@" in text else None
        if dm and not self.case.value("org_domains"):
            changes["org_domains"] = ([dm.group(1)], "확인")
        if "정보통신서비스 제공자" in text:
            changes["is_ict_service_provider"] = ("아니" not in text, level)

        # 서버 장악
        if any(k in text for k in ("root", "루트", "관리자 권한", "서버 장악", "메일 서버")):
            if any(k in text for k in ("탈취", "장악", "침해", "로그인")):
                changes["admin_compromise"] = (True, level)

        # 보험
        if "보험" in text:
            changes["insurance"] = ("없" not in text, level)

        for key, (value, lv) in changes.items():
            self.case.set_fact(key, value, lv, "사용자 진술")
            updated.append(f"{FACT_LABEL.get(key, key)} {display_value(key, value)}[{lv}]")

        # LLM 보조 추출(비어 있는 항목만) — defer 이면 /enrich 의 facts 작업으로 미룬다
        # Liner Mark 보조 해석 — 규칙이 못 읽는 구어체(유형·상대 시각·사건)를 보탠다. 규칙 결과를 덮지 않는다.
        if self.client.available and len(text) >= 6 and getattr(self, "_defer", False):
            self._pending.append("facts")
        elif self.client.available and not updated:
            updated += self._llm_facts(text)
        return updated

    def _llm_facts(self, text: str) -> list[str]:
        updated: list[str] = []
        if self.client.available:
            try:
                masked = self.masker.mask(text)
                now_k = kst_label(now_utc())
                data = self.client.chat_json(LLM_FACT_PROMPT, f"현재 시각(KST): {now_k}\n발화: {masked}\n\nJSON 스키마: {FACT_SCHEMA_HINT}")
                updated += self._apply_llm_extras(data)
                for key, val in data.items():
                    if key.endswith("_krw"):
                        key = "transfer_amount"
                        if val:
                            val = f"{int(val):,}원"
                    if key == "occurred_hint" or key not in DEFAULT_FACTS:
                        continue  # 스키마 밖의 키는 사건 사실로 받지 않는다
                    if val in (None, "", "unknown", []):
                        continue
                    if isinstance(val, str) and (len(val.strip()) <= 2 or val.strip() in ("거래처", "회사", "고객", "알 수 없음")):
                        continue
                    if not self.case.known(key):
                        self.case.set_fact(key, val, "추정", "Liner Mark 사실 추출")
                        updated.append(f"{FACT_LABEL.get(key, key)} {display_value(key, val)}[추정]")
            except (LinerError, ValueError, TypeError):
                pass
        return updated

    def _apply_llm_extras(self, data: dict) -> list[str]:
        """Liner Mark 해석 중 유형·인지 시각·사건·질문을 반영한다 — 전부 '추정', 규칙이 정한 값은 덮지 않는다."""
        out: list[str] = []
        cid = data.pop("category", None)
        if cid and self.case.value("category") is None and category_mod.get(cid):
            cat = category_mod.get(cid)
            self.case.set_fact("category", cat.id, "추정", "Liner Mark 해석")
            self.case.set_fact("category_label", cat.name, "추정", "Liner Mark 해석")
            if not self.case.known("incident_type") and cat.id not in AMBIGUOUS_TYPE:
                self.case.set_fact("incident_type", cat.incident_type, "추정", f"Liner Mark 해석({cat.name})")
            out.append(f"10대 유형 {cat.no}. {cat.name}[추정]")
        aware = data.pop("aware_time", None)
        src = self.case.facts.get("aware_at")
        if aware and (not self.case.aware_at or (src and src.source.startswith("대화 중 인지"))):
            try:
                self.case.set_aware_at(aware, source="Liner Mark 해석(사용자 진술의 시각)", level="추정")
                out.append(f"인지 시각 {kst_label(self.case.aware_at)}[추정]")
            except Exception:  # noqa: BLE001 - 형식이 다르면 무시
                pass
        for ev in (data.pop("events", None) or [])[:6]:
            if not isinstance(ev, dict) or not ev.get("what"):
                continue
            if not ev.get("time"):
                continue  # 시각 없는 진술은 타임라인을 어지럽힌다 — 대화 기록에만 남긴다
            try:
                when = parse_kst_local(str(ev["time"]))
            except Exception:  # noqa: BLE001
                continue
            if self.add_event(when, str(ev["what"])[:160], "추정", "Liner Mark 해석"):
                out.append("타임라인 기록")
        q = data.pop("question", None)
        if isinstance(q, str) and len(q.strip()) > 3:
            self._question = q.strip()[:200]
        for k in ("occurred_hint",):
            data.pop(k, None)
        return out

    def add_event(self, when, what: str, level: str = "추정", source: str = "사용자 진술") -> bool:
        """사용자 진술 사건을 타임라인에 — 같은 시각·비슷한 내용은 한 번만."""
        what = (what or "").strip()
        if not what:
            return False
        ts = None
        if isinstance(when, datetime):
            ts = (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
        for e in self.case.events:
            if ts and e.get("ts") == ts:
                return False  # 같은 시각의 사건은 한 번만(규칙이 먼저 잡은 원문을 남긴다)
            if not ts and e["what"][:20] == what[:20]:
                return False
        self.case.events.append({"id": f"ev{len(self.case.events) + 1}_{abs(hash((ts, what))) % 10000}",
                                 "ts": ts, "what": what, "level": level, "source": source})
        self.case.events.sort(key=lambda e: e.get("ts") or "9999")
        return True

    def remove_event(self, event_id: str) -> bool:
        before = len(self.case.events)
        self.case.events = [e for e in self.case.events if e.get("id") != event_id]
        return len(self.case.events) < before

    def howto_from_liner(self, action: str) -> dict:
        """내장 안내가 없는 할 일 — Liner Quick Answer에 사건 맥락을 붙여 '처음 하는 사람용' 순서를 묻는다."""
        cat = category_mod.get(self.case.value("category"))
        ctx = f"{cat.name} 사고" if cat else "보안사고"
        q = (f"한국 소규모 회사가 {ctx} 대응 중입니다. IT 비전문가가 다음 일을 직접 하려면 무엇을 준비하고 어떤 순서로 하면 되는지 "
             f"3~4단계로 쉽게 알려 주세요. 확실하지 않은 메뉴 이름은 단정하지 마세요. 할 일: {self.masker.mask(action)}")
        res = self.client.quick_answer(q)
        return {"action": action, "answer": self.masker.unmask(res.get("answer") or ""),
                "references": res.get("references", [])[:3]}

    def answer_question(self, question: str) -> dict:
        """사용자의 자유 질문 — 사건 맥락을 붙여 Liner Quick Answer로 짧게 답한다(출처 포함)."""
        cat = category_mod.get(self.case.value("category"))
        ctx = f"{cat.name} 사고" if cat else "보안사고(유형 판별 전)"
        q = (f"한국 소규모 회사가 {ctx}를 겪고 있습니다. 다음 질문에 3문장 이내로, 안전한 초동대응 원칙에 맞게 답해 주세요. "
             f"확실하지 않은 것은 단정하지 마세요. 질문: {self.masker.mask(question)}")
        res = self.client.quick_answer(q)
        ans = self.masker.unmask(res.get("answer") or "")
        if ans:
            self.case.sources.extend(res.get("references", [])[:3])
            self.case.log("assistant", "[Liner Quick Answer] " + ans[:600])
        return {"question": question, "answer": ans, "references": res.get("references", [])[:3]}

    # ------------------------------------------------------------------ 엔진
    def _run_detection(self, *, extra_eml: dict | None = None) -> None:
        eml = extra_eml or (self.case.eml_triage[-1] if self.case.eml_triage else None)
        self.det = detect(self.logs, org_country=self.case.value("org_country", "KR") or "KR", is_eml=eml)
        self.case.findings = [f.to_dict() for f in self.det.ordered()]

    def _derive_ransom_facts(self) -> None:
        """EDR·백업 로그로 랜섬웨어 사실을 채운다(사용자가 덮어쓴 값은 유지)."""
        rules = set(self.det.rules_hit())
        if not any(r.startswith("RW_") for r in rules):
            return
        hosts = {f.detail.get("host") for f in self.det.findings if f.rule_id == "RW_EXTENSION_MASS"}
        files = sum(int(f.detail.get("files") or 0) for f in self.det.findings if f.rule_id == "RW_EXTENSION_MASS")
        ext = next((f.detail.get("ext") for f in self.det.findings if f.rule_id == "RW_EXTENSION_MASS" and f.detail.get("ext")), "")
        note = next((f.detail.get("path") for f in self.det.findings if f.rule_id == "RW_RANSOM_NOTE" and f.detail.get("path")), "")
        if hosts:
            self.case.set_fact("encrypted_hosts", len(hosts), "확인", "EDR·파일 서버 로그")
        if ext:
            self.case.set_fact("encrypted_ext", ext, "확인", "EDR 파일 이벤트")
        if note:
            self.case.set_fact("ransom_note", note, "확인", "EDR 파일 이벤트")
            self.case.set_fact("ransomware_confirmed", True, "확인", "랜섬노트 파일 생성 기록")
        elif "RW_EXTENSION_MASS" in rules:
            self.case.set_fact("ransomware_confirmed", True, "확인", "파일 대량 암호화 이벤트")
        if "RW_SHADOW_DELETE" in rules:
            self.case.set_fact("shadow_copies_deleted", True, "확인", "섀도 복사본 삭제 명령 기록")
        if "RW_BACKUP_TARGETED" in rules and not self.case.known("backup_status"):
            self.case.set_fact("backup_status", "at_risk", "확인", "백업 작업 실패·백업 대상 접근 불가")
        if files:
            self.case.set_fact("encrypted_files", files, "확인", "EDR 파일 이벤트 합계")
        if self.case.value("category") is None:
            cat = category_mod.get("ransom")
            if cat:
                self.case.set_fact("category", cat.id, "확인", "규칙 엔진(랜섬웨어 신호)")
                self.case.set_fact("category_label", cat.name, "확인", "10대 유형 자동 연결")

    def _recompute(self) -> None:
        # 유형·심각도는 사실과 로그가 바뀔 때마다 다시 계산한다(플레이북: 새 사실 → 즉시 재평가)
        self._derive_ransom_facts()
        derived = self.case.value("incident_type")
        pre = None
        if derived and derived != "unknown" and not self.det.findings and not self.case.eml_triage:
            from .classify import LABELS

            cat_name = self.case.value("category_label")
            pre = Classification(derived, LABELS.get(derived, "판별 전 — 추가 자료 필요"), "추정",
                                 [f"사용자 선택·진술로 유형 접수: {cat_name or derived} (로그 미확인)"],
                                 ["로그·메일 원본"], [])
        self.cls = classify(self.case, self.det) if self.det.findings or self.case.eml_triage else (
            pre or classify(self.case, self.det))
        if self.cls.type != "unknown" and self.case.value("incident_type") != self.cls.type:
            self.case.set_fact("incident_type", self.cls.type, self.cls.level, "규칙 엔진")
        if self.case.value("external_illegal_access") is None:
            if self.cls.type in ("ato", "root"):
                self.case.set_fact("external_illegal_access", True, "추정", "외부 IP에서 사서함 접근 정황")
            elif self.cls.type in ("spoof", "lookalike"):
                self.case.set_fact("external_illegal_access", False, "확인", "우리 시스템 접근 흔적 없음")
        if self.cls.type != "unknown" and self.cls.type != self.case.value("category") and self.case.value("category") is None:
            cat = category_mod.for_incident_type(self.cls.type)
            if cat:
                self.case.set_fact("category", cat.id, "추정", "규칙 엔진(탐지 유형)")
                self.case.set_fact("category_label", cat.name, "추정", "10대 유형 자동 연결")
        self.sev = evaluate_severity(self.case, self.det, self.cls)
        self._track_severity()
        self.deadlines = deadline_mod.board(self.case)
        self.actions = playbook.next_actions(self.case, self.det, self.cls, self.sev)
        self.phase = playbook.phase_now(self.case)

    def _track_severity(self) -> None:
        """심각도가 바뀐 순간을 기록한다 — '왜 P1이 됐나'를 화면·보고서에서 되짚을 수 있게."""
        last = self.sev_history[-1] if self.sev_history else None
        if last and last["level"] == self.sev.level:
            return
        self.sev_history.append({
            "level": self.sev.level, "name": self.sev.name,
            "reason": (self.sev.reasons or [""])[0],
            "at": kst_short(now_utc()),
        })

    # ------------------------------------------------------------------ Liner: 법령 재확인
    def verify_law(self, *, force: bool = False) -> dict:
        if self.case.law_checks and not force:
            return self.case.law_checks[-1]
        return self.merge_law_check(self.fetch_law_check())

    def merge_law_check(self, check: dict) -> dict:
        """화면이 /law 로 따로 받아 온 법령 재확인 결과를 사건에 붙인다(상태 토큰 경합 방지)."""
        if not isinstance(check, dict) or "status" not in check:
            return {}
        if any(c.get("checked_at") == check.get("checked_at") for c in self.case.law_checks):
            return check
        self.case.law_checks.append(check)
        self.case.sources.extend(check.get("references") or [])
        self.case.sources.extend(check.get("channels_live") or [])
        return check

    def fetch_law_check(self) -> dict:
        """Search Agent(근거 답변)와 Search(공식 창구)를 동시에 호출한다 — 사건 상태는 바꾸지 않는다."""
        check = {"question": LAW_QUESTION, "answer": "", "references": [], "drift": [],
                 "status": "offline", "checked_at": now_utc().isoformat()}
        if self.client.available:
            pool = ThreadPoolExecutor(max_workers=2)
            web_future = pool.submit(self.client.search_web,
                                     "KISA 침해사고 신고 118 개인정보 유출 신고 개인정보포털", max_results=4)
            try:
                res = self.client.search_agent(LAW_QUESTION)
                check.update({"status": "live", "answer": res["answer"], "references": res["references"][:12]})
                hours = {"intrusion": _hours_from(res["answer"], "정보통신망"), "pi": _hours_from(res["answer"], "개인정보")}
                check["hours"] = hours
                rules = deadline_mod.load_rules()["rules"]
                by_id = {r["id"]: r for r in rules}
                if hours.get("intrusion") and hours["intrusion"] != by_id["R_INTRUSION_REPORT"]["deadline_hours"]:
                    check["drift"].append(f"침해사고 신고: 코드 {by_id['R_INTRUSION_REPORT']['deadline_hours']}시간 vs 검색 {hours['intrusion']}시간")
                if hours.get("pi") and hours["pi"] != by_id["R_PI_LEAK_REPORT"]["deadline_hours"]:
                    check["drift"].append(f"개인정보 통지: 코드 {by_id['R_PI_LEAK_REPORT']['deadline_hours']}시간 vs 검색 {hours['pi']}시간")
            except LinerError as exc:
                check.update({"status": "error", "error": str(exc)[:200]})
            try:
                web = web_future.result()
                check["channels"] = web
                check["channels_live"] = web
            except LinerError:
                pass
            finally:
                pool.shutdown(wait=False)
        if not check["references"]:
            check["channels"] = check.get("channels") or [
                {"title": "KISA 보호나라·KrCERT/CC (118)", "url": "https://www.boho.or.kr/"},
                {"title": "개인정보 유출 신고 (개인정보포털)", "url": "https://pipc.go.kr/"},
            ]
        return check

    # ------------------------------------------------------------------ Liner 보강(비동기 화면용)
    def enrich(self, tasks: list[str], *, text: str = "") -> dict:
        """판정 직후 화면이 부르는 Liner 보강 — 사실 보조 추출 뒤 브리핑·즉답 가이드를 동시에 호출한다.

        결정적 결과(심각도·기한·할 일)는 이미 화면에 있다. 여기서는 문장과 근거만 덧붙인다.
        """
        tasks = [t for t in tasks if t in ("facts", "narrate", "guide", "answer")]
        out: dict = {"brief": "", "updated": [], "timings": {}}
        self._question = None
        if not self.client.available or not tasks:
            return out
        if "facts" in tasks and text:
            started = now_utc()
            out["updated"] = self._llm_facts(text)
            out["timings"]["facts"] = int((now_utc() - started).total_seconds() * 1000)
            if out["updated"]:
                self._recompute()
        question = (self._question or text) if "answer" in tasks else None
        jobs = {}
        with ThreadPoolExecutor(max_workers=3) as pool:
            if "guide" in tasks and self.case.value("category"):
                jobs["guide"] = pool.submit(self.quick_guide, force=True)
            if "narrate" in tasks:
                jobs["narrate"] = pool.submit(self._narrate)
            if question:
                jobs["answer"] = pool.submit(self.answer_question, question)
            for name, fut in jobs.items():
                try:
                    res = fut.result()
                    if name == "narrate":
                        out["brief"] = res or ""
                    elif name == "answer" and res.get("answer"):
                        out["answer"] = res
                except LinerError as exc:
                    out.setdefault("errors", {})[name] = str(exc)[:160]
        if out["brief"]:
            self.case.log("assistant", "[Liner 브리핑] " + out["brief"][:800])
        return out

    # ------------------------------------------------------------------ 체크리스트
    def set_action_done(self, key: str, done: bool) -> dict | None:
        """지금 할 일 체크 — 완료 시각을 사건 기록에 남기고, 신고서 '현재까지의 대응'에 쓴다."""
        action = next((a for a in self.actions if a.get("key") == key), None)
        if done:
            if action is None and key not in self.case.done:
                return None
            label = action["action"] if action else self.case.done[key]["action"]
            self.case.done[key] = {"action": label, "at": kst_short(now_utc()), "at_iso": now_utc().isoformat()}
            self.case.log("checklist", f"완료: {label}")
        else:
            mark = self.case.done.pop(key, None)
            if mark:
                self.case.log("checklist", f"완료 취소: {mark['action']}")
        self._recompute()
        return self.case.done.get(key, {"undone": True})

    # ------------------------------------------------------------------ 10대 유형 (v0.5)
    def _category_view(self) -> dict | None:
        cat = category_mod.get(self.case.value("category"))
        if not cat:
            return None
        return {"id": cat.id, "no": cat.no, "name": cat.name, "short": cat.short,
                "deep": cat.deep, "scenario": cat.scenario, "base_severity": cat.base_severity,
                "level": self.case.level("category"),
                "first_15min": cat.first_15min, "dont_do": cat.dont_do,
                "deadline_focus": cat.deadline_focus, "why_severity": cat.why_severity}

    def ensure_aware(self) -> None:
        """인지 시각이 없으면 '지금'을 추정값으로 기록해 시계를 시작한다."""
        if not self.case.aware_at:
            self.case.set_aware_at(now_utc(), source="대화 중 인지(사건 시작 시각 — 실제로 안 시각으로 바꿀 수 있어요)", level="추정")

    def set_aware_from_text(self, raw: str) -> bool:
        """'2026-11-20 08:30', '오늘 아침 8시 반', '30분 전' 모두 받는다 — 사용자가 직접 고친 값은 '확인'."""
        raw = (raw or "").strip()
        when = None
        try:
            when = parse_kst_local(raw.replace("T", " "))
        except Exception:  # noqa: BLE001 - 구어체
            k = nlu.parse_time(raw)
            when = k.astimezone(timezone.utc) if k else None
        if not when:
            return False
        self.case.set_aware_at(when, source="사용자 지정(인지 시각 수정)", level="확인")
        self.case.log("aware", f"인지 시각 수정: {kst_label(when)}")
        return True

    def apply_category(self, key: str, *, guide: bool = True) -> dict:
        """10대 유형을 고르면 공통 초동조치·기한·즉답 가이드가 바로 작동한다."""
        cat = category_mod.get(key)
        if not cat:
            raise KeyError(f"알 수 없는 사고 유형입니다: {key}")
        self.case.set_fact("category", cat.id, "확인", f"사용자 선택(10대 유형 {cat.no})")
        self.case.set_fact("category_label", cat.name, "확인", "사용자 선택")
        self.case.set_fact("category_severity", cat.base_severity, "추정", f"{cat.name} 유형 기본값")
        if cat.incident_type and not self.case.known("incident_type") and cat.id not in AMBIGUOUS_TYPE:
            self.case.set_fact("incident_type", cat.incident_type, "추정", f"10대 유형 선택({cat.name})")
        self.case.log("category", f"사고 유형 선택: {cat.no}. {cat.name}")
        self.ensure_aware()
        if guide:
            self.quick_guide(cat)
        self._recompute()
        return self.board(reply=f"[{cat.no}. {cat.name}] 유형으로 접수했습니다. "
                                f"{cat.why_severity}. 지금 할 일과 신고 기한을 계산했습니다.")

    def quick_guide(self, cat=None, *, force: bool = False) -> dict:
        """유형별 즉답 가이드 — Liner Quick Answer + 규칙 기반 폴백을 구분해 보관한다."""
        cat = cat if isinstance(cat, category_mod.Category) else category_mod.get(
            cat or self.case.value("category"))
        if not cat:
            return {}
        if not force and cat.id in self.case.guides:
            return self.case.guides[cat.id]
        entry = {"category": cat.id, "category_name": cat.name, "question": cat.guide,
                 "answer": cat.offline_guide, "references": [], "status": "offline",
                 "checked_at": now_utc().isoformat(), "source": "규칙 기반 안내"}
        if self.client.available:
            try:
                res = self.client.quick_answer(cat.guide)
                if res.get("answer"):
                    entry.update({"status": "live", "answer": res["answer"],
                                  "references": res["references"][:3], "source": "Liner Quick Answer"})
                    self.case.sources.extend(res["references"][:3])
            except LinerError as exc:
                entry.update({"status": "error", "error": str(exc)[:200]})
        self.case.guides[cat.id] = entry
        return entry

    def viz_query(self) -> str:
        cat = category_mod.get(self.case.value("category"))
        org = self.case.value("org_name") or "조직"
        subject = cat.name if cat else self.cls.label
        return (f"{org}의 {subject} 사고 대응: 0~10분, 10~60분, 1~4시간, 4~24시간, 24~72시간 조치와 "
                "정보통신망법 24시간·개인정보보호법 72시간 신고 기한을 한 장으로 정리")

    def visualize(self, *, force: bool = False) -> dict:
        """사건 보드 시각화 — 실패·오프라인이면 깨지지 않는 폴백 정보를 돌려준다."""
        if self.case.viz and not force:
            return self.case.viz
        query = self.viz_query()
        entry = {"ok": False, "query": query, "theme": "", "description": "", "html": "",
                 "references": [], "status": "offline", "checked_at": now_utc().isoformat(),
                 "reason": "Liner 키가 없어 차트를 만들 수 없습니다. 아래 요약 카드로 대체합니다."}
        if self.client.available:
            try:
                res = self.client.visualize(query, appearance="light")
                if res.get("ok"):
                    entry.update({"ok": True, "status": "live", "html": res["html"],
                                  "theme": res.get("theme", ""), "description": res.get("description", ""),
                                  "references": res.get("references", [])[:5], "reason": ""})
                    self.case.sources.extend(res.get("references") or [])
                else:
                    entry.update({"status": "empty", "reason": "시각화 결과에 HTML 아티팩트가 없습니다."})
            except LinerError as exc:
                entry.update({"status": "error", "reason": f"시각화 요청 실패: {str(exc)[:160]}"})
        # HTML 본문은 보드에 넣지 않는다(응답 크기) — /viz 엔드포인트가 따로 돌려준다.
        self.case.viz = entry
        return entry

    def viz_public(self) -> dict:
        viz = self.case.viz or {}
        return {"ok": bool(viz.get("ok")), "available": self.client.available,
                "theme": viz.get("theme", ""), "description": viz.get("description", ""),
                "status": viz.get("status", "none"), "reason": viz.get("reason", ""),
                "query": viz.get("query", self.viz_query())}

    # ------------------------------------------------------------------ 문서
    def compose_docs(self, *, wait_law: bool = True) -> dict[str, dict]:
        if not self.case.law_checks and wait_law:
            self.verify_law()
        docs = docs_mod.build_documents(self.case, self.det, self.cls, self.sev)
        self.case.docs = {k: v.to_dict() for k, v in docs.items()}
        return self.case.docs

    # ------------------------------------------------------------------ 문장
    def _reply_text(self, intent: str, actions_taken: list[str], warnings: list[str], *,
                    narrate: bool = True) -> str:
        sev = self.sev
        cls = self.cls
        lines: list[str] = []
        if warnings:
            lines.append("⚠️ " + "\n⚠️ ".join(warnings))
        cat = category_mod.get(self.case.value("category"))
        if cat:
            lines.append(f"[유형] {cat.no}. {cat.name} ({self.case.level('category')})")
        lines.append(f"[심각도] {sev.level} {sev.name} — {', '.join(sev.reasons[:2])}")
        lines.append(f"[판별] {cls.label} ({cls.level})")
        if actions_taken:
            lines.append("[처리] " + " / ".join(actions_taken))

        due = self.deadlines.get("next_due") if hasattr(self, "deadlines") else None
        if due:
            lines.append(f"[신고 기한] {due['title']} → {due['due']} ({due['remaining']}, 판단 {due['status']})")

        if self.actions:
            lines.append("[지금 할 일]")
            for i, a in enumerate(self.actions[:3], 1):
                lines.append(f"  {i}. {a['action']} ({a['who']} / 플레이북 {a['ref']})")

        missing = [m for m in self._missing_questions()][:2]
        if missing:
            lines.append("[확인 필요] " + " / ".join(missing))

        if intent == "evidence":
            lines.append("[증거 확보] 로그를 직접 못 구해도 괜찮습니다. 오른쪽 [증거 확보] 탭에서 사용하는 환경을 고르면 "
                         "무엇을·어디서·언제까지 확보할지, 못 구하면 대신 할 일과 업체에 보낼 요청 메일 초안을 드립니다. "
                         "본 것과 시각을 대화창에 적어도 타임라인에 기록됩니다.")
        if intent == "docs" and self.case.docs:
            lines.append("[생성 문서] " + ", ".join(d["title"] for d in self.case.docs.values()))

        if cat and intent in ("guide", "chat"):
            g = self.case.guides.get(cat.id)
            if g and g.get("answer"):
                label = "Liner Quick Answer" if g.get("status") == "live" else "규칙 기반 안내"
                lines.append(f"\n[유형별 즉답 · {label}] {g['answer']}")
                if g.get("references"):
                    lines.append("출처: " + ", ".join((r.get("hostname") or r.get("url") or "") for r in g["references"][:3]))

        if self.client.available and not narrate:
            pass  # 화면이 /enrich 로 Liner 브리핑을 따로 받아 덧붙인다
        elif self.client.available:
            try:
                brief = self._narrate()
                if brief:
                    lines.append("\n" + brief)
            except LinerError:
                pass
        else:
            lines.append("\n(Liner API 키가 없어 규칙 기반 모드로 응답했습니다. .env에 LINER_API_KEY를 넣으면 해석·문장 생성이 켜집니다.)")
        return "\n".join(lines)

    def _narrate(self) -> str:
        context = {
            "유형": self.cls.label,
            "10대유형": (category_mod.get(self.case.value("category")).name if category_mod.get(self.case.value("category")) else "미정"),
            "증거확보": dict(zip(("확보", "못구함"), evidence_mod.status_lines(self.case))),
            "사용자진술사건수": len(self.case.events),
            "판별근거": self.cls.basis[:3],
            "판별근거_없는것": getattr(self.cls, "missing", []),
            "심각도": self.sev.level,
            "심각도근거": self.sev.reasons,
            "사실": [{"항목": f["label"], "값": str(f["value"]), "근거수준": f["level"]} for f in self.case.facts_view()][:12],
            "지금할일": [a["action"] for a in self.actions[:4]],
            "신고기한": [d for d in self.deadlines["items"] if d["status"] in ("해당", "검토")] if hasattr(self, "deadlines") else [],
            "로그건수": self.det.counts,
            "미확인": self._missing_questions(),
            "법령재확인": {"상태": self.case.law_checks[-1]["status"],
                             "요지": (self.case.law_checks[-1].get("answer") or "")[:600]} if self.case.law_checks else {},
        }
        masked = self.masker.mask(json.dumps(context, ensure_ascii=False, default=str))
        out = self.client.chat([
            {"role": "system", "content": NARRATE_PROMPT},
            {"role": "user", "content": masked},
        ], max_tokens=450, temperature=0.2)
        return self.masker.unmask(out.strip())

    ASK_OPTIONS = {
        "aware": [("방금 알았어요", "방금 알았어요"), ("30분 전", "30분 전에 알았어요"), ("1시간 전", "1시간 전에 알았어요"),
                  ("오늘 아침 9시", "오늘 아침 9시에 알았어요"), ("직접 입력", "@aware")],
        "what": [("거래처·계좌 관련 메일", "거래처에서 계좌 변경 메일 관련 연락이 왔어요"),
                 ("파일이 안 열려요", "파일이 이상한 확장자로 바뀌고 열리지 않아요"),
                 ("메일 계정이 이상해요", "메일 계정이 해킹당한 것 같아요"),
                 ("홈페이지·쇼핑몰 이상", "홈페이지 회원 정보가 털린 것 같아요"), ("직접 적기", "@type")],
        "transfer": [("이미 보냈대요", "거래처가 이미 송금했대요"), ("보낼 예정", "송금할 예정이래요"),
                     ("안 보냈대요", "아직 송금 안 했대요"), ("모르겠어요", "@skip")],
        "backup": [("연결돼 있었어요", "백업은 외장하드에 있는데 꽂혀 있었어요"),
                   ("분리 보관 중", "백업은 외장하드에 따로 분리해 보관하고 있어요"),
                   ("백업 없어요", "백업은 없어요"), ("모르겠어요", "@skip")],
        "hosts": [("1대", "암호화된 PC가 1대예요"), ("2~5대", "암호화된 PC가 3대 정도예요"),
                  ("6대 이상", "암호화된 PC가 6대 이상이에요"), ("모르겠어요", "@skip")],
        "pi": [("많이 있어요(1천 명 이상)", "고객 개인정보가 1,000명분 이상 있어요"), ("조금 있어요", "고객 정보가 조금 있어요"),
               ("없어요", "고객 개인정보는 없어요"), ("모르겠어요", "@skip")],
        "ict": [("네, 운영해요", "쇼핑몰이나 홈페이지를 운영하고 있어요"), ("아니요", "온라인 서비스는 제공하지 않아요"),
                ("모르겠어요", "@skip")],
        "domain": [("직접 입력", "@domain"), ("모르겠어요", "@skip")],
    }

    def asks(self) -> list[dict]:
        """화면의 '확인이 필요해요' 카드 — 질문마다 누르기만 하면 되는 답 버튼. '모르겠어요'는 다시 묻지 않는다."""
        out = []
        for qid, q in self._missing_items():
            if qid in self.case.skipped:
                continue
            out.append({"id": qid, "q": q,
                        "options": [{"label": lb, "say": say} for lb, say in self.ASK_OPTIONS.get(qid, [])]})
        return out

    def skip_ask(self, qid: str) -> None:
        if qid and qid not in self.case.skipped:
            self.case.skipped.append(qid)
            self.case.log("ask", f"질문 건너뜀(모름): {qid}")

    def _missing_questions(self) -> list[str]:
        return [q for _, q in self._missing_items()]

    def _missing_items(self) -> list[tuple[str, str]]:
        """다음에 물어볼 것 — 사고 유형에 맞는 질문만(랜섬웨어에 '메일 도메인'을 묻지 않는다)."""
        q = []
        itype = self.case.value("incident_type")
        cat = self.case.value("category") or ""
        mail_like = itype in ("ato", "spoof", "lookalike", "unknown", None) and not cat.startswith(("CAT04", "CAT05", "CAT06", "CAT07", "CAT09", "CAT10"))
        src = self.case.facts.get("aware_at")
        if not self.case.aware_at:
            q.append(("aware", "이 일을 처음 안 시각이 언제인가요? (예: 오늘 아침 8시 반) — 신고 기한 계산의 기준입니다"))
        elif src and src.source.startswith("대화 중 인지"):
            q.append(("aware", "처음 안 시각을 지금으로 적어 두었습니다. 실제로 언제 알았나요? (예: 오늘 오전 10시쯤 전화 받음)"))
        if itype is None or itype == "unknown":
            if not cat:
                q.append(("what", "어떤 일이 있었나요? 화면·메일·전화로 본 것을 그대로 적어 주세요(위 10개 유형 중 골라도 됩니다)"))
        money_talk = any(k in " ".join(h.get("text", "") for h in self.case.history if h.get("kind") == "user")
                         for k in ("계좌", "송금", "입금", "이체", "대금", "거래처", "돈"))
        if mail_like and self.case.value("transfer_status") == "unknown" and (
                cat in ("CAT01_BEC_ACCOUNT_CHANGE", "CAT03_LOOKALIKE_SPOOF") or (not cat and money_talk)):
            q.append(("transfer", "거래처나 우리 쪽에서 실제로 돈이 나갔나요(송금 완료/예정/없음)?"))
        if itype == "ransom" or cat == "CAT04_RANSOMWARE":
            if self.case.value("backup_status") in (None, "unknown"):
                q.append(("backup", "백업(외장하드·NAS·클라우드)이 있나요? 지금 PC나 서버에 연결돼 있나요?"))
            if not isinstance(self.case.value("encrypted_hosts"), int):
                q.append(("hosts", "파일이 바뀐 컴퓨터·서버가 몇 대인가요? 바뀐 확장자는 무엇인가요?"))
        if self.case.value("personal_data_leak") == "unknown":
            where = "메일함" if mail_like else "피해를 입은 PC·서버·DB"
            q.append(("pi", f"{where}에 고객 개인정보(이름·연락처·주소 등)가 들어 있나요? 대략 몇 명분인가요?"))
        if self.case.value("is_ict_service_provider") is None:
            q.append(("ict", "회사가 쇼핑몰·홈페이지·앱처럼 고객에게 온라인 서비스를 제공하나요? (24시간 침해사고 신고 대상 판단에 필요)"))
        if mail_like and not self.case.value("org_domains") and (not cat or self.case.value("platform") or cat in ("CAT01_BEC_ACCOUNT_CHANGE", "CAT02_MAIL_ACCOUNT_ATO", "CAT03_LOOKALIKE_SPOOF")):
            q.append(("domain", "회사 메일 도메인(메일 주소의 @ 뒤, 예: @ourcompany.co.kr)을 알려 주세요 — 사칭 여부를 가립니다"))
        return q

    # ------------------------------------------------------------------ 보드
    def board(self, *, reply: str = "", warnings: list[str] | None = None) -> dict:
        if not hasattr(self, "deadlines"):
            self._recompute()
        ddl = self.deadlines
        return {
            "reply": reply,
            "case": {**self.case.summary(), "aware_at": self.case.aware_label(),
                     "aware_iso": self.case.aware_at.isoformat() if self.case.aware_at else None,
                     "mode": "liner" if self.client.available else "offline"},
            "severity": self.sev.to_dict(),
            "severity_history": self.sev_history[-6:],
            "events": self.case.events,
            "howto": {h["id"]: {k: v for k, v in h.items() if k != "match"}
                      for h in playbook.howto_items() if any(a.get("howto") == h["id"] for a in self.actions)},
            "evidence": evidence_mod.view(self.case),
            "classification": self.cls.to_dict(),
            "phase": self.phase,
            "findings": [f.to_dict() for f in self.det.ordered()],
            "counts": self.det.counts,
            "suspect_ips": self.det.suspect_ips,
            "suspect_accounts": self.det.suspect_accounts,
            "log_kinds": self.case.log_kinds,
            "deadlines": ddl,
            "actions": self.actions,
            "first_five": playbook.first_five(self.case, self.det),
            "urgent_branches": playbook.urgent_branches(self.case, self.det),
            "dont_do": playbook.dont_do(self.case, self.det, self.cls),
            "persistence": playbook.persistence_items(self.case, self.det),
            "recovery": playbook.recovery(self.case, self.det),
            "facts": self.case.facts_view(),
            "missing": self._missing_questions(),
            "asks": self.asks(),
            "docs": [{"id": k, "title": v["title"], "kind": v["kind"]} for k, v in self.case.docs.items()],
            "sources": self.case.sources[:20],
            "law_checks": self.case.law_checks,
            "category": self._category_view(),
            "guide": self.case.guides.get(self.case.value("category") or ""),
            "guides": list(self.case.guides.values())[:10],
            "suggested_categories": category_mod.suggest(self.det, self.case),
            "ransom": self._ransom_view(),
            "viz": self.viz_public(),
            "warnings": warnings or [],
            "api": {"mode": "liner" if self.client.available else "offline",
                    "model": self.client.model, "calls": self.client.calls[-8:]},
        }

    def _ransom_view(self) -> dict | None:
        if not any(r.startswith("RW_") for r in self.det.rules_hit()) and self.case.value("incident_type") != "ransom":
            return None
        return {
            "confirmed": self.case.value("ransomware_confirmed"),
            "hosts": self.case.value("encrypted_hosts"),
            "files": self.case.value("encrypted_files"),
            "ext": self.case.value("encrypted_ext"),
            "note": self.case.value("ransom_note"),
            "backup_status": self.case.value("backup_status"),
            "shadow_deleted": self.case.value("shadow_copies_deleted"),
            "paid": self.case.value("ransom_paid"),
            "rules": [r for r in self.det.rules_hit() if r.startswith("RW_")],
        }

    # ------------------------------------------------------------------ 상태 직렬화(서버리스)
    def snapshot(self) -> dict:
        """사건 전체 상태를 JSON으로 — Vercel 서버리스에서 세션이 사라져도 복원할 수 있게."""
        return {
            "v": 1,
            "scenario": self.scenario,
            "narrative": self.narrative,
            "sev_history": self.sev_history,
            "case": {
                "id": self.case.id,
                "created_at": self.case.created_at.isoformat(),
                "facts": {k: {"value": _enc(v.value), "level": v.level, "source": v.source, "note": v.note}
                          for k, v in self.case.facts.items()},
                "findings": self.case.findings,
                "eml_triage": self.case.eml_triage,
                "log_kinds": self.case.log_kinds,
                "sources": self.case.sources,
                "law_checks": self.case.law_checks,
                "guides": self.case.guides,
                "viz": self.case.viz,
                "docs": self.case.docs,
                "history": self.case.history,
                "notes": self.case.notes,
                "done": self.case.done,
                "events": self.case.events,
                "evidence": self.case.evidence,
                "skipped": self.case.skipped,
            },
            "det": {**self.det.to_dict(),
                    "findings": [{**f.to_dict(), "ts": f.ts.isoformat() if f.ts else None}
                                 for f in self.det.findings]},
            "logs": [{"kind": log.kind, "warnings": log.warnings,
                      "records": [{"ts": r.ts.isoformat() if r.ts else None, "data": r.data, "raw": r.raw}
                                  for r in log.records]} for log in self.logs],
        }

    def snapshot_token(self) -> str:
        raw = json.dumps(self.snapshot(), ensure_ascii=False, default=str).encode("utf-8")
        return base64.urlsafe_b64encode(zlib.compress(raw, 6)).decode("ascii")

    @classmethod
    def from_snapshot(cls, data: dict, *, client: LinerClient | None = None) -> "Agent":
        cdata = data.get("case") or {}
        case = Case(id=cdata.get("id")) if cdata.get("id") else Case()
        created = cdata.get("created_at")
        if created:
            ts = parse_ts(created)
            if ts:
                case.created_at = ts
        case.facts = {}
        for k, v in (cdata.get("facts") or {}).items():
            case.facts[k] = Fact(_dec(v.get("value")), v.get("level", "미확인"), v.get("source", "미상"), v.get("note", ""))
        for k, default in DEFAULT_FACTS.items():
            case.facts.setdefault(k, Fact(default, "미확인", "미상"))
        case.findings = cdata.get("findings") or []
        case.eml_triage = cdata.get("eml_triage") or []
        case.log_kinds = cdata.get("log_kinds") or []
        case.sources = cdata.get("sources") or []
        case.law_checks = cdata.get("law_checks") or []
        case.guides = cdata.get("guides") or {}
        case.viz = cdata.get("viz")
        case.docs = cdata.get("docs") or {}
        case.history = cdata.get("history") or []
        case.notes = cdata.get("notes") or []
        case.done = cdata.get("done") or {}
        case.events = cdata.get("events") or []
        case.evidence = cdata.get("evidence") or {}
        case.skipped = cdata.get("skipped") or []

        det = DetectionResult()
        ddata = data.get("det") or {}
        for fd in ddata.get("findings") or []:
            det.findings.append(Finding(
                fd.get("rule_id", ""), parse_ts(fd.get("ts")) if fd.get("ts") else None,
                fd.get("summary", ""), fd.get("severity", "info"), fd.get("source", ""),
                fd.get("signal", ""), fd.get("evidence", "확인"), fd.get("actor", ""), fd.get("detail") or {}))
        det.suspect_ips = ddata.get("suspect_ips") or []
        det.suspect_accounts = ddata.get("suspect_accounts") or []
        det.hosts = ddata.get("hosts") or []
        det.counts = ddata.get("counts") or {}
        det.sources_seen = ddata.get("sources_seen") or {}
        det.notes = ddata.get("notes") or []

        logs = []
        for ldata in data.get("logs") or []:
            records = [ingest.Record(ldata.get("kind", ingest.UNKNOWN),
                                     parse_ts(r.get("ts")) if r.get("ts") else None,
                                     r.get("data") or {}, r.get("raw", ""))
                       for r in ldata.get("records") or []]
            logs.append(ingest.ParsedLog(ldata.get("kind", ingest.UNKNOWN), records, ldata.get("warnings") or []))

        agent = cls(case=case, client=client or LinerClient.from_env(), det=det,
                    scenario=data.get("scenario"), narrative=data.get("narrative", ""),
                    logs=logs, sev_history=data.get("sev_history") or [])
        agent._recompute()
        return agent

    @classmethod
    def from_token(cls, token: str, *, client: LinerClient | None = None, max_bytes: int = 8_000_000) -> "Agent":
        """상태 토큰 복원 — 압축 폭탄을 막기 위해 전개 크기에 상한을 둔다."""
        if not token or not isinstance(token, str):
            raise ValueError("상태 토큰이 비어 있습니다")
        packed = base64.urlsafe_b64decode(token.encode("ascii"))
        dec = zlib.decompressobj()
        raw = dec.decompress(packed, max_bytes)
        if dec.unconsumed_tail:
            raise ValueError("상태 토큰이 너무 큽니다")
        return cls.from_snapshot(json.loads(raw.decode("utf-8")), client=client)

    # ------------------------------------------------------------------ 데모
    def run_scenario(self, scenario_id: str, *, aware_at: str | None = None, steps: list[str] | None = None,
                     defer: bool = False) -> dict:
        """데모 입력을 실제 사용자 입력처럼 순서대로 흘려보낸다(사전 주입 없음)."""
        d = SCENARIO_DIR / scenario_id
        meta = json.loads((d / "scenario.json").read_text(encoding="utf-8"))
        self.load_scenario(scenario_id, aware_at=aware_at, preload=False)
        for step in (steps if steps is not None else meta.get("demo_inputs", [])):
            self.handle(self._resolve_files(step, d), defer=defer)
        if not self.case.docs:
            self.compose_docs(wait_law=not defer)
        self._recompute()
        # 한 번에 실행에서도 대화창에 쓸 수 있는 브리핑을 남긴다(심각도·지금 할 일·기한·해석).
        reply = self._reply_text("scenario", [f"시나리오 실행 완료 — {meta.get('title', scenario_id)}"], [],
                                 narrate=not defer)
        board = self.board(reply=reply)
        if defer and self.client.available:
            board["pending"] = (["law"] if not self.case.law_checks else []) + ["narrate"]
        return board

    def start_replay(self, scenario_id: str, *, aware_at: str | None = None) -> list[dict]:
        """화면에서 한 단계씩 재생할 데모 입력 목록을 돌려준다(사건은 빈 상태로 시작)."""
        d = SCENARIO_DIR / scenario_id
        if not (d / "scenario.json").exists():
            raise FileNotFoundError(f"시나리오를 찾을 수 없습니다: {scenario_id}")
        meta = json.loads((d / "scenario.json").read_text(encoding="utf-8"))
        self.load_scenario(scenario_id, aware_at=aware_at, preload=False)
        steps = []
        for step in meta.get("demo_inputs", []):
            files = re.findall(r"@file:([\w.\-]+)", step)
            text = self._resolve_files(step, d)
            if files:
                label = "📎 " + ", ".join(files) + f" 붙여넣기 ({text.count(chr(10)) + 1}줄)"
            else:
                label = step
            steps.append({"label": label, "text": text, "files": files})
        return steps

    @staticmethod
    def _resolve_files(step: str, scenario_dir: Path) -> str:
        def repl(m: re.Match[str]) -> str:
            p = scenario_dir / m.group(1)
            return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
        return re.sub(r"@file:([\w.\-]+)", repl, step)


def _enc(value):
    """스냅샷용 값 인코딩 — datetime만 태그해 보존한다."""
    if isinstance(value, datetime):
        return {"__dt__": value.isoformat()}
    if isinstance(value, (list, tuple)):
        return [_enc(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _enc(v) for k, v in value.items()}
    return value


def _dec(value):
    if isinstance(value, dict):
        if set(value) == {"__dt__"}:
            return parse_ts(value["__dt__"])
        return {k: _dec(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_dec(v) for v in value]
    return value


def _hours_from(answer: str, keyword: str) -> int | None:
    """답변에서 '24시간' 같은 기한을 뽑는다(키워드 문단 우선)."""
    if not answer:
        return None
    best = None
    for line in answer.splitlines():
        if keyword not in line and "시간" not in line:
            continue
        m = re.search(r"(\d{1,3})\s*시간", line)
        if m and (keyword in line or best is None):
            val = int(m.group(1))
            if val in (24, 72):
                if keyword in line:
                    return val
                best = best or val
    return best
