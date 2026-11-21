"""EML 헤더 판독 — 계정 침해(ATO) / 스푸핑 / 유사 도메인을 가르는 근거를 만든다.

플레이북 3.3·3.4:
- 인증 결과(SPF/DKIM/DMARC)는 "우리 도메인을 사칭했는가"를 보는 신호다.
- 우리 도메인에서 정상 인증으로 나갔고 보낸편지함에 기록이 있으면 계정 침해다.
- 도메인 철자가 비슷하면 유사 도메인(lookalike)이다.
v0.2는 log_rules.json에 LR_HEADER_TRIAGE만 선언하고 파서가 없었다.
"""
from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parsedate_to_datetime

from .timeutil import parse_ts

# 철자 혼동(homoglyph) 정규화 — 유사 도메인 판별용
_HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "rn": "m", "vv": "w", "ii": "u", "$": "s"}


@dataclass
class Flag:
    code: str
    level: str          # 확인 | 추정 | 미확인 | 주의
    text: str


@dataclass
class EmlTriage:
    subject: str = ""
    from_addr: str = ""
    from_display: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    sent_at: str = ""          # ISO(UTC) 문자열
    message_id: str = ""
    originating_ip: str = ""
    auth: dict[str, str] = field(default_factory=dict)
    flags: list[Flag] = field(default_factory=list)
    verdict: str = "unknown"   # ato | spoof | lookalike | external | unknown
    basis: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "from_addr": self.from_addr,
            "from_display": self.from_display,
            "from_domain": self.from_domain,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "sent_at": self.sent_at,
            "message_id": self.message_id,
            "originating_ip": self.originating_ip,
            "auth": self.auth,
            "flags": [{"code": f.code, "level": f.level, "text": f.text} for f in self.flags],
            "verdict": self.verdict,
            "basis": self.basis,
        }


def _addr(value: str) -> tuple[str, str]:
    pairs = getaddresses([value or ""])
    if not pairs:
        return "", ""
    name, addr = pairs[0]
    return (name or "").strip(), (addr or "").strip().lower()


def domain_of(addr: str) -> str:
    return addr.split("@", 1)[1].lower() if "@" in addr else ""


def normalize_domain(dom: str) -> str:
    d = dom.lower()
    for k, v in _HOMOGLYPHS.items():
        d = d.replace(k, v)
    return d


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_lookalike(domain: str, org_domains: set[str]) -> tuple[bool, str]:
    """조직 도메인과 철자만 다른 도메인인지."""
    norm = normalize_domain(domain)
    label, _, tld = domain.partition(".")
    for org in org_domains:
        if not org or "." not in org:
            continue
        if norm == normalize_domain(org):
            return True, f"정규화하면 {org}와 같음(숫자·글자 치환)"
        org_label = org.split(".")[0]
        if tld == org.split(".")[-1] and levenshtein(label, org_label) <= 2:
            return True, f"{org}와 철자 거리 {levenshtein(label, org_label)}"
        # 회사명을 그대로 포함한 변형(예: hanbit-logis → hanbit-logistcs, hanbit-logis-kr)
        if tld == org.split(".")[-1] and org_label in label and label != org_label:
            return True, f"{org_label}를 포함한 변형 도메인"
    return False, ""


def _auth_values(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    low = raw.lower()
    for k in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{k}\s*=\s*([a-z]+)", low)
        if m:
            out[k] = m.group(1)
    return out


def triage_eml(text: str, *, org_domains: set[str] | None = None,
               suspect_ips: set[str] | None = None) -> EmlTriage:
    """EML 원문을 판독한다. 원문은 저장하지 않고 발신·인증 요약만 남긴다."""
    org_domains = {d.lower() for d in (org_domains or set()) if d}
    suspect_ips = suspect_ips or set()
    msg = email.message_from_string(text, policy=policy.default)
    tri = EmlTriage()
    tri.subject = str(msg.get("Subject", "") or "").strip()
    tri.from_display, tri.from_addr = _addr(str(msg.get("From", "")))
    tri.from_domain = domain_of(tri.from_addr)
    _, tri.reply_to = _addr(str(msg.get("Reply-To", "")))
    _, tri.return_path = _addr(str(msg.get("Return-Path", "")))
    tri.message_id = str(msg.get("Message-ID", "") or "").strip()
    ip_header = str(msg.get("X-Originating-IP", "") or "")
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", ip_header)
    tri.originating_ip = m.group(1) if m else ""

    date_header = str(msg.get("Date", "") or "")
    if date_header:
        try:
            dt = parsedate_to_datetime(date_header)
            tri.sent_at = parse_ts(dt).isoformat() if dt else ""
        except (TypeError, ValueError):
            dt = parse_ts(date_header)
            tri.sent_at = dt.isoformat() if dt else ""

    auth_raw = str(msg.get("Authentication-Results", "") or "")
    tri.auth = _auth_values(auth_raw)

    for hop in (msg.get_all("Received") or [])[:3]:
        hop_ip = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", str(hop))
        if hop_ip and not tri.originating_ip:
            tri.originating_ip = hop_ip.group(1)

    # --- 판독 ---
    internal = tri.from_domain in org_domains
    auth_pass = tri.auth.get("spf") == "pass" or tri.auth.get("dkim") == "pass"
    auth_fail = any(tri.auth.get(k) == "fail" for k in ("spf", "dkim", "dmarc"))
    lookalike, why = is_lookalike(tri.from_domain, org_domains)

    if tri.originating_ip and tri.originating_ip in suspect_ips:
        tri.flags.append(Flag("HDR_ORIGIN_IP_SUSPECT", "확인",
                              f"X-Originating-IP {tri.originating_ip}가 의심 IP 목록과 일치"))
    if internal:
        tri.flags.append(Flag("HDR_FROM_INTERNAL", "확인", f"발신 도메인이 조직 도메인({tri.from_domain})과 일치 — 외부 사칭이 아님"))
    elif lookalike:
        tri.flags.append(Flag("HDR_LOOKALIKE", "확인", f"유사 도메인 의심: {tri.from_domain} ({why})"))
    else:
        tri.flags.append(Flag("HDR_FROM_EXTERNAL", "확인", f"발신 도메인 {tri.from_domain or '미상'}이 조직 도메인과 다름"))
    if tri.auth:
        tri.flags.append(Flag("HDR_AUTH", "확인",
                              " / ".join(f"{k.upper()}={v}" for k, v in tri.auth.items())))
        if auth_fail:
            tri.flags.append(Flag("HDR_AUTH_FAIL", "확인", "인증 실패 — 발신 도메인 사칭 가능성"))
    else:
        tri.flags.append(Flag("HDR_AUTH_UNKNOWN", "미확인", "Authentication-Results 헤더가 없어 인증 여부를 확인하지 못함"))
    if tri.reply_to and tri.from_addr and tri.reply_to != tri.from_addr:
        tri.flags.append(Flag("HDR_REPLYTO_MISMATCH", "확인", f"Reply-To({tri.reply_to})가 From({tri.from_addr})과 다름"))
    if tri.return_path and tri.from_addr and tri.return_path != tri.from_addr:
        tri.flags.append(Flag("HDR_RETURNPATH_MISMATCH", "확인", f"Return-Path({tri.return_path})가 From과 다름 — 대량 발송·사칭 신호"))

    if internal and (auth_pass or not tri.auth) and (not auth_fail):
        tri.verdict = "ato"
        tri.basis.append("조직 도메인에서 정상 인증으로 발송 — 외부 사칭이 아니라 계정 자체가 사용된 것으로 판단(추정)")
        if tri.originating_ip in suspect_ips:
            tri.basis.append("발송 IP가 해외 로그인 IP와 동일 — 계정 침해 소지 확인")
    elif internal and auth_fail:
        tri.verdict = "spoof"
        tri.basis.append("조직 도메인을 표방했지만 인증 실패 — 도메인 스푸핑")
    elif lookalike:
        tri.verdict = "lookalike"
        tri.basis.append(f"철자만 다른 유사 도메인({tri.from_domain}) — 우리 계정 침해가 아닌 외부 도메인 사칭")
    elif not internal and auth_fail:
        tri.verdict = "spoof"
        tri.basis.append("외부 도메인 + 인증 실패 — 스푸핑 발송")
    elif not internal:
        tri.verdict = "external"
        tri.basis.append("외부 도메인에서 정상 인증으로 발송 — 우리 계정 침해와 무관, 거래처 침해 여부를 별도 확인")
    else:
        tri.verdict = "unknown"
        tri.basis.append("판별 근거가 부족 — 원본 헤더 전체와 메일 서버 로그 추가 확인 필요")

    return tri


VERDICT_LABEL = {
    "ato": "계정 침해(ATO) 소지",
    "spoof": "도메인 스푸핑",
    "lookalike": "유사 도메인 사칭",
    "external": "외부 발신(우리 계정 침해 아님)",
    "unknown": "판별 보류",
}
