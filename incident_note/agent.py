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
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import categories as category_mod
from . import deadline as deadline_mod
from . import docs as docs_mod
from . import eml as eml_mod
from . import ingest
from . import playbook
from .case import DEFAULT_FACTS, FACT_LABEL, Case, Fact, display_value
from .classify import Classification, classify
from .detect import DetectionResult, Finding, detect
from .liner import LinerClient, LinerError, LinerUnavailable
from .mask import Masker
from .severity import Severity, evaluate as evaluate_severity
from .timeutil import kst_label, kst_short, now_utc, parse_kst_local, parse_ts

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "data" / "scenarios"

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
  "occurred_hint": "사건이 시작된 시점 표현 또는 null"
}"""

LLM_FACT_PROMPT = (
    "너는 한국 소규모 회사의 메일 침해 초동대응을 돕는 분석기다. "
    "사용자 발화에서 사건 사실만 뽑아 JSON으로 출력한다. 발화에 없는 값은 절대 추측하지 말고 null로 둔다. "
    "금액은 원 단위 정수로 바꾼다(예: 1,870만 원 → 18700000). 사람 수는 정수. "
    "명시적으로 '송금했다'고 하면 done, '송금할 예정'이면 pending, '송금 안 했다'면 none, 언급이 없으면 unknown."
)

NARRATE_PROMPT = (
    "너는 사고 대응 비서다. 아래 JSON 사건 상태만 근거로 한국어 4~6문장 브리핑을 쓴다. 규칙: "
    "1) 확인/추정/미확인을 반드시 구분해 표기한다. 2) JSON에 없는 사실·수치·법령을 만들지 않는다. "
    "3) '피해 없음' 같은 단정을 하지 않는다. 4) 첫 문장은 지금 가장 급한 행동. 5) 링크를 쓰지 않는다. "
    "6) 3인칭 설명조가 아니라 담당자에게 말하듯 쓴다."
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
    def handle(self, text: str) -> dict:
        text = (text or "").strip()
        if not text:
            return self.board(reply="무엇을 확인할까요? 사건 설명, 로그 붙여넣기, 메일 원본 중 하나로 시작할 수 있습니다.")
        warnings = playbook.guardrail(text, self.case, self.cls)
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
                    if not self.case.known("incident_type"):
                        self.case.set_fact("incident_type", cat.incident_type, "추정", f"유형 추정({cat.name})")
                    actions_taken.append(f"10대 유형 연결: {cat.no}. {cat.name}")

        intent = self._intent(text, kind)
        if intent == "law" or (self.det.findings and not self.case.law_checks and intent == "logs"):
            self.verify_law()
        if intent == "guide" and self.case.value("category"):
            self.quick_guide(force=True)
            actions_taken.append("유형별 즉답 가이드 조회")
        if intent == "docs":
            self.compose_docs()
            actions_taken.append("문서 초안 생성")

        self._recompute()
        reply = self._reply_text(intent, actions_taken, warnings)
        board = self.board(reply=reply, warnings=warnings)
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
        if kind != ingest.UNKNOWN:
            return "logs"
        return "chat"

    # ------------------------------------------------------------------ 사실 추출
    def _extract_facts(self, text: str) -> list[str]:
        updated: list[str] = []
        hedge = any(k in text for k in ("같", "아마", "정도", "듯", "추정", "것 같"))
        level = "추정" if hedge else "확인"
        changes: dict[str, tuple] = {}

        # 인지 시각
        m = re.search(r"(20\d{2}-\d{1,2}-\d{1,2}[ T]\d{1,2}:\d{2})", text)
        if m:
            try:
                self.case.set_aware_at(m.group(1).replace("T", " "), source="사용자 입력 시각")
                updated.append("인지 시각")
            except Exception:
                pass
        elif not self.case.aware_at and any(k in text for k in ("방금", "오늘", "지금", "전화가 왔")):
            self.case.set_aware_at(now_utc(), source="대화 중 인지(현재 시각 사용)")
            updated.append(f"인지 시각={kst_label(self.case.aware_at)}")

        # 송금
        if re.search(r"(이미\s*송금|송금했|송금 완료|입금했|보냈대|이체했)", text):
            changes["transfer_status"] = ("done", level)
        elif re.search(r"(송금할 예정|송금 예정|보내려|이체 예정|지급 예정)", text):
            changes["transfer_status"] = ("pending", level)
        elif re.search(r"(송금\s*(안|하지 않|없)|보내지 않|아직 안 보냈)", text):
            changes["transfer_status"] = ("none", "확인")

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

        # 인원
        m = re.search(r"(\d[\d,]{0,8})\s*(명|건|개)\s*분?", text)
        if m and any(k in text for k in ("명", "고객", "정보주체", "사서함", "문의")):
            try:
                changes["affected_count"] = (int(m.group(1).replace(",", "")), level)
            except ValueError:
                pass

        # 개인정보
        if re.search(r"(주민번호|주민등록번호).{0,10}(없|미포함)", text):
            changes["sensitive_or_unique_id"] = (False, "확인")
        elif "주민번호" in text or "민감정보" in text:
            changes["sensitive_or_unique_id"] = (True, level)
        if any(k in text for k in ("고객 문의", "배송 문의", "사서함에", "고객 정보", "개인정보", "문의 내역")):
            if any(k in text for k in ("유출 확인", "유출됐", "빼갔")):
                changes["personal_data_leak"] = ("confirmed", level)
            else:
                changes["personal_data_leak"] = ("suspected", level)
            if "pi_data_types" not in changes:
                changes["pi_data_types"] = ("고객 문의 정보(이름·연락처·주소)", level)
        if re.search(r"(개인정보).{0,10}(없|유출 안|미해당)", text):
            changes["personal_data_leak"] = ("none", "확인")

        # 랜섬웨어 관련 사실(v0.5) — 백업 상태·몸값·지불 여부
        if "백업" in text:
            if any(k in text for k in ("오프라인", "테이프", "외장", "분리했", "분리 완료", "격리했", "별도 보관")):
                changes["backup_status"] = ("offline_safe", level)
                changes["backup_isolated"] = (True, level)
            elif any(k in text for k in ("같은 랙", "같은 망", "연결", "온라인", "공유 폴더", "같은 서버")):
                changes["backup_status"] = ("at_risk", level)
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
        if re.search(r"(홈페이지|자사 서비스|고객 문의).{0,20}(운영|제공)", text):
            changes["is_ict_service_provider"] = (True, level)
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

        # LLM 보조 추출(비어 있는 항목만)
        if self.client.available and not updated:
            try:
                masked = self.masker.mask(text)
                data = self.client.chat_json(LLM_FACT_PROMPT, f"발화: {masked}\n\nJSON 스키마: {FACT_SCHEMA_HINT}")
                for key, val in data.items():
                    if key.endswith("_krw"):
                        key = "transfer_amount"
                        if val:
                            val = f"{int(val):,}원"
                    if key == "occurred_hint":
                        continue
                    if val in (None, "", "unknown", []):
                        continue
                    if isinstance(val, str) and (len(val.strip()) <= 2 or val.strip() in ("거래처", "회사", "고객", "알 수 없음")):
                        continue
                    if not self.case.known(key):
                        self.case.set_fact(key, val, "추정", "Liner Mark 사실 추출")
                        updated.append(f"{FACT_LABEL.get(key, key)} {display_value(key, val)}[추정]")
            except (LinerError, ValueError):
                pass
        return updated

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
        check = {"question": LAW_QUESTION, "answer": "", "references": [], "drift": [],
                 "status": "offline", "checked_at": now_utc().isoformat()}
        if self.client.available:
            try:
                res = self.client.search_agent(LAW_QUESTION)
                check.update({"status": "live", "answer": res["answer"], "references": res["references"][:12]})
                self.case.sources.extend(res["references"][:12])
                hours = {"intrusion": _hours_from(res["answer"], "정보통신망"), "pi": _hours_from(res["answer"], "개인정보")}
                check["hours"] = hours
                rules = deadline_mod.load_rules()["rules"]
                by_id = {r["id"]: r for r in rules}
                if hours.get("intrusion") and hours["intrusion"] != by_id["R_INTRUSION_REPORT"]["deadline_hours"]:
                    check["drift"].append(f"침해사고 신고: 코드 {by_id['R_INTRUSION_REPORT']['deadline_hours']}시간 vs 검색 {hours['intrusion']}시간")
                if hours.get("pi") and hours["pi"] != by_id["R_PI_LEAK_REPORT"]["deadline_hours"]:
                    check["drift"].append(f"개인정보 통지: 코드 {by_id['R_PI_LEAK_REPORT']['deadline_hours']}시간 vs 검색 {hours['pi']}시간")
                try:
                    web = self.client.search_web("KISA 침해사고 신고 118 개인정보 유출 신고 개인정보포털", max_results=4)
                    check["channels"] = web
                    self.case.sources.extend(web)
                except LinerError:
                    pass
            except LinerError as exc:
                check.update({"status": "error", "error": str(exc)[:200]})
        if not check["references"]:
            check["channels"] = check.get("channels") or [
                {"title": "KISA 보호나라·KrCERT/CC (118)", "url": "https://www.boho.or.kr/"},
                {"title": "개인정보 유출 신고 (개인정보포털)", "url": "https://pipc.go.kr/"},
            ]
        self.case.law_checks.append(check)
        return check

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

    def apply_category(self, key: str, *, guide: bool = True) -> dict:
        """10대 유형을 고르면 공통 초동조치·기한·즉답 가이드가 바로 작동한다."""
        cat = category_mod.get(key)
        if not cat:
            raise KeyError(f"알 수 없는 사고 유형입니다: {key}")
        self.case.set_fact("category", cat.id, "확인", f"사용자 선택(10대 유형 {cat.no})")
        self.case.set_fact("category_label", cat.name, "확인", "사용자 선택")
        self.case.set_fact("category_severity", cat.base_severity, "추정", f"{cat.name} 유형 기본값")
        if cat.incident_type and not self.case.known("incident_type"):
            self.case.set_fact("incident_type", cat.incident_type, "추정", f"10대 유형 선택({cat.name})")
        self.case.log("category", f"사고 유형 선택: {cat.no}. {cat.name}")
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
                res = self.client.visualize(query, appearance="dark")
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
    def compose_docs(self) -> dict[str, dict]:
        if not self.case.law_checks:
            self.verify_law()
        docs = docs_mod.build_documents(self.case, self.det, self.cls, self.sev)
        self.case.docs = {k: v.to_dict() for k, v in docs.items()}
        return self.case.docs

    # ------------------------------------------------------------------ 문장
    def _reply_text(self, intent: str, actions_taken: list[str], warnings: list[str]) -> str:
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

        if intent == "docs" and self.case.docs:
            lines.append("[생성 문서] " + ", ".join(d["title"] for d in self.case.docs.values()))

        if cat and intent in ("guide", "chat"):
            g = self.case.guides.get(cat.id)
            if g and g.get("answer"):
                label = "Liner Quick Answer" if g.get("status") == "live" else "규칙 기반 안내"
                lines.append(f"\n[유형별 즉답 · {label}] {g['answer']}")
                if g.get("references"):
                    lines.append("출처: " + ", ".join((r.get("hostname") or r.get("url") or "") for r in g["references"][:3]))

        if self.client.available:
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
        ], max_tokens=700, temperature=0.2)
        return self.masker.unmask(out.strip())

    def _missing_questions(self) -> list[str]:
        q = []
        if not self.case.aware_at:
            q.append("사건을 처음 안 시각(인지 시각)이 언제인가요? 신고 기한 계산의 기준입니다")
        if self.case.value("transfer_status") == "unknown" and self.case.value("incident_type") not in ("ransom", "ddos"):
            q.append("실제로 돈이 움직였나요(송금 완료/예정/없음)?")
        if self.case.value("incident_type") == "ransom":
            if self.case.value("backup_status") in (None, "unknown"):
                q.append("백업 오프라인 사본(테이프·외장·다른 계정)이 있나요? 같은 망에 연결돼 있나요?")
            if not isinstance(self.case.value("encrypted_hosts"), int):
                q.append("암호화된 서버·PC가 몇 대인가요? 확장자는 무엇인가요(.locked 등)?")
        if self.case.value("personal_data_leak") == "unknown":
            q.append("사서함에 고객 개인정보(이름·연락처·주소 등)가 들어 있나요? 규모는 어느 정도인가요?")
        if self.case.value("is_ict_service_provider") is None:
            q.append("회사가 홈페이지·고객 문의 메일 같은 서비스를 외부에 제공하나요? (정보통신서비스 제공자 여부)")
        if not self.case.value("org_domains"):
            q.append("회사 메일 도메인을 알려 주세요(사칭 여부 판별에 필요)")
        return q

    # ------------------------------------------------------------------ 보드
    def board(self, *, reply: str = "", warnings: list[str] | None = None) -> dict:
        if not hasattr(self, "deadlines"):
            self._recompute()
        ddl = self.deadlines
        return {
            "reply": reply,
            "case": {**self.case.summary(), "aware_at": self.case.aware_label(),
                     "mode": "liner" if self.client.available else "offline"},
            "severity": self.sev.to_dict(),
            "severity_history": self.sev_history[-6:],
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
    def run_scenario(self, scenario_id: str, *, aware_at: str | None = None, steps: list[str] | None = None) -> dict:
        """데모 입력을 실제 사용자 입력처럼 순서대로 흘려보낸다(사전 주입 없음)."""
        d = SCENARIO_DIR / scenario_id
        meta = json.loads((d / "scenario.json").read_text(encoding="utf-8"))
        self.load_scenario(scenario_id, aware_at=aware_at, preload=False)
        for step in (steps if steps is not None else meta.get("demo_inputs", [])):
            self.handle(self._resolve_files(step, d))
        if not self.case.docs:
            self.compose_docs()
        self._recompute()
        # 한 번에 실행에서도 대화창에 쓸 수 있는 브리핑을 남긴다(심각도·지금 할 일·기한·해석).
        reply = self._reply_text("scenario", [f"시나리오 실행 완료 — {meta.get('title', scenario_id)}"], [])
        return self.board(reply=reply)

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
